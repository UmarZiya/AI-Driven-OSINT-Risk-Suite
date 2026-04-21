/**
 * OSINT Module: Social Media Footprint Mapping
 * Checks presence of a username across major social/professional platforms.
 *
 * Routes:
 *   POST /api/osint/social/username   — username presence check
 */

const express = require("express");
const axios   = require("axios");
const router  = express.Router();

// ─── Platform definitions ─────────────────────────────────────────────────────
//
// Each entry defines how to check if a username exists on that platform.
// Method: "status" — profile exists if HTTP status matches existStatus.
//         "body"   — profile exists if body matches bodyPattern regex.

const PLATFORMS = [
  {
    name:        "GitHub",
    url:         (u) => `https://github.com/${u}`,
    method:      "status",
    existStatus: 200,
    category:    "developer",
  },
  {
    name:        "Twitter / X",
    url:         (u) => `https://twitter.com/${u}`,
    method:      "status",
    existStatus: 200,
    category:    "social",
  },
  {
    name:        "Instagram",
    url:         (u) => `https://www.instagram.com/${u}/`,
    method:      "status",
    existStatus: 200,
    category:    "social",
  },
  {
    name:        "Reddit",
    url:         (u) => `https://www.reddit.com/user/${u}/about.json`,
    method:      "status",
    existStatus: 200,
    category:    "social",
  },
  {
    name:        "LinkedIn",
    url:         (u) => `https://www.linkedin.com/in/${u}/`,
    method:      "body",
    bodyPattern: /\/in\//,
    category:    "professional",
  },
  {
    name:        "HackerNews",
    url:         (u) => `https://hacker-news.firebaseio.com/v0/user/${u}.json`,
    method:      "body",
    bodyPattern: /"id"/,
    category:    "developer",
  },
  {
    name:        "Dev.to",
    url:         (u) => `https://dev.to/${u}`,
    method:      "status",
    existStatus: 200,
    category:    "developer",
  },
  {
    name:        "Medium",
    url:         (u) => `https://medium.com/@${u}`,
    method:      "status",
    existStatus: 200,
    category:    "blogging",
  },
  {
    name:        "Pinterest",
    url:         (u) => `https://www.pinterest.com/${u}/`,
    method:      "status",
    existStatus: 200,
    category:    "social",
  },
  {
    name:        "Keybase",
    url:         (u) => `https://keybase.io/${u}`,
    method:      "status",
    existStatus: 200,
    category:    "crypto/identity",
  },
  {
    name:        "GitLab",
    url:         (u) => `https://gitlab.com/${u}`,
    method:      "status",
    existStatus: 200,
    category:    "developer",
  },
  {
    name:        "Pastebin",
    url:         (u) => `https://pastebin.com/u/${u}`,
    method:      "status",
    existStatus: 200,
    category:    "misc",
  },
  {
    name:        "Twitch",
    url:         (u) => `https://www.twitch.tv/${u}`,
    method:      "status",
    existStatus: 200,
    category:    "gaming/streaming",
  },
  {
    name:        "YouTube",
    url:         (u) => `https://www.youtube.com/@${u}`,
    method:      "status",
    existStatus: 200,
    category:    "social",
  },
  {
    name:        "TikTok",
    url:         (u) => `https://www.tiktok.com/@${u}`,
    method:      "status",
    existStatus: 200,
    category:    "social",
  },
  {
    name:        "Telegram",
    url:         (u) => `https://t.me/${u}`,
    method:      "status",
    existStatus: 200,
    category:    "messaging",
  },
  {
    name:        "DockerHub",
    url:         (u) => `https://hub.docker.com/u/${u}`,
    method:      "status",
    existStatus: 200,
    category:    "developer",
  },
  {
    name:        "npm",
    url:         (u) => `https://www.npmjs.com/~${u}`,
    method:      "status",
    existStatus: 200,
    category:    "developer",
  },
  {
    name:        "Gravatar",
    url:         (u) => `https://en.gravatar.com/${u}`,
    method:      "status",
    existStatus: 200,
    category:    "identity",
  },
  {
    name:        "About.me",
    url:         (u) => `https://about.me/${u}`,
    method:      "status",
    existStatus: 200,
    category:    "identity",
  },
];

// ─── helpers ──────────────────────────────────────────────────────────────────

const BROWSER_HEADERS = {
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  Accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
};

/**
 * Check a single platform for a username.
 * Returns { found: boolean, url: string }
 */
async function checkPlatform(platform, username) {
  const url = platform.url(username);
  try {
    if (platform.method === "status") {
      const resp = await axios.get(url, {
        headers:        BROWSER_HEADERS,
        timeout:        8000,
        maxRedirects:   5,
        validateStatus: () => true,  // don't throw on non-2xx
      });
      return { found: resp.status === platform.existStatus, url };
    }

    if (platform.method === "body") {
      const resp = await axios.get(url, {
        headers:        BROWSER_HEADERS,
        timeout:        8000,
        maxRedirects:   5,
        validateStatus: () => true,
      });
      const bodyText = typeof resp.data === "string"
        ? resp.data
        : JSON.stringify(resp.data);
      return { found: resp.status === 200 && platform.bodyPattern.test(bodyText), url };
    }
  } catch {
    // Network error / timeout — treat as not found
  }
  return { found: false, url };
}

/**
 * Social footprint risk score (0–100).
 * A larger footprint = more attack surface.
 * High-risk categories (misc, pastebin) add extra weight.
 */
function calcSocialRiskScore(found) {
  if (!found.length) return 0;

  const baseScore  = Math.min(found.length * 5, 50);  // max 50 from count alone

  const highRisk = found.filter((p) =>
    ["misc", "gaming/streaming"].includes(p.category)
  ).length;

  const professionalPresence = found.filter((p) => p.category === "professional").length;

  let score = baseScore + highRisk * 10;

  // Professional presence is expected — don't penalise it much
  if (professionalPresence > 0 && found.length === professionalPresence) {
    score = Math.max(score - 20, 0);
  }

  return Math.min(score, 100);
}

// ─── routes ───────────────────────────────────────────────────────────────────

/**
 * POST /api/osint/social/username
 * Body: { username: "johndoe" }
 */
router.post("/username", async (req, res) => {
  const { username } = req.body;
  if (!username || username.trim().length < 2) {
    return res.status(400).json({ success: false, error: "username must be at least 2 characters." });
  }

  const clean = username.trim().toLowerCase();

  // Run all platform checks concurrently
  const checks = await Promise.allSettled(
    PLATFORMS.map(async (platform) => {
      const result = await checkPlatform(platform, clean);
      return { platform: platform.name, category: platform.category, ...result };
    })
  );

  const allResults = checks.map((r, i) =>
    r.status === "fulfilled"
      ? r.value
      : { platform: PLATFORMS[i].name, category: PLATFORMS[i].category, found: false, url: PLATFORMS[i].url(clean), error: r.reason?.message }
  );

  const found    = allResults.filter((r) => r.found);
  const notFound = allResults.filter((r) => !r.found);

  const riskScore = calcSocialRiskScore(found);
  const riskLevel = riskScore >= 60 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW";

  // Group found results by category
  const byCategory = found.reduce((acc, r) => {
    acc[r.category] = acc[r.category] || [];
    acc[r.category].push({ platform: r.platform, url: r.url });
    return acc;
  }, {});

  return res.json({
    success: true,
    username: clean,
    totalChecked:   PLATFORMS.length,
    foundCount:     found.length,
    riskScore,
    riskLevel,
    foundPlatforms: found.map((r) => ({ platform: r.platform, category: r.category, url: r.url })),
    byCategory,
    notFoundPlatforms: notFound.map((r) => r.platform),
    recommendations: buildSocialRecommendations(riskLevel, found),
  });
});

// ─── recommendations ──────────────────────────────────────────────────────────

function buildSocialRecommendations(riskLevel, found) {
  const recs = [];

  if (found.length === 0) {
    recs.push("Username not found on any monitored platform. Good — minimal public footprint.");
    return recs;
  }

  if (riskLevel === "HIGH" || found.length > 10) {
    recs.push("Large digital footprint detected. Review and deactivate unused accounts.");
  }

  const hasPastebin = found.find((p) => p.platform === "Pastebin");
  if (hasPastebin) {
    recs.push("Pastebin account found. Check for inadvertently posted sensitive data (credentials, API keys).");
  }

  const hasGitHub = found.find((p) => p.platform === "GitHub");
  if (hasGitHub) {
    recs.push("GitHub account found. Scan repositories for accidentally committed secrets or API keys.");
  }

  recs.push("Set all social media accounts to private and review connected third-party apps.");
  recs.push("Enable login notifications on all active platforms.");

  return recs;
}

module.exports = router;
