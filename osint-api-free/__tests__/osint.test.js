/**
 * Test Suite: OSINT Risk Suite API
 * Run with: npm test
 *
 * Uses Jest + Supertest. MongoDB is mocked via jest.mock so no live DB is needed.
 * HIBP and Shodan calls are mocked to avoid network dependency in CI.
 */

const request = require("supertest");

// ─── Mock mongoose so no real DB connection is needed ─────────────────────────
jest.mock("mongoose", () => {
  const actual = jest.requireActual("mongoose");
  return {
    ...actual,
    connect: jest.fn().mockResolvedValue(true),
    connection: { readyState: 1 },
    model: jest.fn().mockReturnValue({
      create: jest.fn().mockResolvedValue({ _id: "mockid123" }),
      find:   jest.fn().mockReturnValue({ sort: () => ({ limit: () => ({ select: () => ({ lean: () => Promise.resolve([]) }) }) }) }),
      findById: jest.fn().mockReturnValue({ lean: () => Promise.resolve(null) }),
    }),
    Schema: actual.Schema,
  };
});

// ─── Mock HIBP ────────────────────────────────────────────────────────────────
jest.mock("../services/breachService", () => ({
  queryHIBP: jest.fn().mockResolvedValue([
    { name: "TestBreach", title: "Test Breach", domain: "test.com", breachDate: "2023-01-01",
      pwnCount: 100000, dataClasses: ["Email addresses", "Passwords"], isVerified: true, isSensitive: false },
  ]),
  calcBreachRiskScore: jest.fn().mockReturnValue(65),
}));

// ─── Mock Shodan ──────────────────────────────────────────────────────────────
jest.mock("../services/networkService", () => ({
  shodanHostLookup:    jest.fn().mockResolvedValue({ ports: [22, 80, 3306], vulns: {}, country_name: "United States", org: "TestOrg" }),
  calcNetworkRiskScore: jest.fn().mockReturnValue(45),
}));

// ─── Import app AFTER mocks are set up ───────────────────────────────────────
const app = require("../app");

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("Health Check", () => {
  it("GET /api/health → 200", async () => {
    const res = await request(app).get("/api/health");
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe("ok");
  });
});

describe("Breach Module — POST /api/osint/breach/email", () => {
  it("returns breach data for a valid email", async () => {
    const res = await request(app)
      .post("/api/osint/breach/email")
      .send({ email: "test@example.com" });

    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body).toHaveProperty("breachCount");
    expect(res.body).toHaveProperty("riskScore");
    expect(res.body).toHaveProperty("riskLevel");
    expect(res.body).toHaveProperty("recommendations");
  });

  it("rejects invalid email", async () => {
    const res = await request(app)
      .post("/api/osint/breach/email")
      .send({ email: "notanemail" });
    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
  });

  it("rejects missing email", async () => {
    const res = await request(app).post("/api/osint/breach/email").send({});
    expect(res.statusCode).toBe(400);
  });
});

describe("Domain Module — POST /api/osint/domain/dns", () => {
  it("returns DNS records for a valid domain", async () => {
    const res = await request(app)
      .post("/api/osint/domain/dns")
      .send({ domain: "example.com" });

    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body).toHaveProperty("dns");
  });

  it("rejects missing domain", async () => {
    const res = await request(app).post("/api/osint/domain/dns").send({});
    expect(res.statusCode).toBe(400);
  });
});

describe("Network Module — POST /api/osint/network/ip", () => {
  it("returns network info for a valid IP", async () => {
    const res = await request(app)
      .post("/api/osint/network/ip")
      .send({ ip: "8.8.8.8" });

    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body).toHaveProperty("riskScore");
    expect(res.body).toHaveProperty("openPorts");
  });

  it("rejects invalid IP format", async () => {
    const res = await request(app)
      .post("/api/osint/network/ip")
      .send({ ip: "not-an-ip" });
    expect(res.statusCode).toBe(400);
  });
});

describe("Social Module — POST /api/osint/social/username", () => {
  it("returns platform results for a valid username", async () => {
    const res = await request(app)
      .post("/api/osint/social/username")
      .send({ username: "testuser" });

    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body).toHaveProperty("foundCount");
    expect(res.body).toHaveProperty("foundPlatforms");
    expect(res.body).toHaveProperty("riskScore");
    expect(Array.isArray(res.body.foundPlatforms)).toBe(true);
  });

  it("rejects too-short username", async () => {
    const res = await request(app)
      .post("/api/osint/social/username")
      .send({ username: "a" });
    expect(res.statusCode).toBe(400);
  });
});

describe("Threat Module — POST /api/osint/threat/analyze-text", () => {
  it("detects credential exposure in text", async () => {
    const res = await request(app)
      .post("/api/osint/threat/analyze-text")
      .send({ text: "password=mysecretpass123 api_key=ABCDEFGHIJKLMNOP" });

    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.findingsCount).toBeGreaterThan(0);
  });

  it("returns CLEAN for benign text", async () => {
    const res = await request(app)
      .post("/api/osint/threat/analyze-text")
      .send({ text: "Hello world, this is a normal sentence about cats and dogs." });

    expect(res.statusCode).toBe(200);
    expect(res.body.contentClass).toBe("CLEAN");
  });

  it("blocks SSRF via analyze-url with internal IP", async () => {
    const res = await request(app)
      .post("/api/osint/threat/analyze-url")
      .send({ url: "http://localhost/admin" });
    expect(res.statusCode).toBe(403);
  });

  it("rejects missing text field", async () => {
    const res = await request(app).post("/api/osint/threat/analyze-text").send({});
    expect(res.statusCode).toBe(400);
  });
});

describe("Risk Score — POST /api/osint/risk-score/calculate", () => {
  it("calculates a weighted final score", async () => {
    const res = await request(app)
      .post("/api/osint/risk-score/calculate")
      .send({
        target:    { email: "test@example.com", domain: "example.com" },
        subScores: { breach: 80, network: 50, domain: 20, social: 30, threat: 10 },
      });

    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.finalScore).toBeGreaterThanOrEqual(0);
    expect(res.body.finalScore).toBeLessThanOrEqual(100);
    expect(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).toContain(res.body.riskLevel);
    expect(res.body).toHaveProperty("breakdown");
    expect(res.body).toHaveProperty("badge");
  });

  it("rejects empty subScores", async () => {
    const res = await request(app)
      .post("/api/osint/risk-score/calculate")
      .send({ subScores: {} });
    expect(res.statusCode).toBe(400);
  });
});

describe("Full Scan — POST /api/osint/scan/full", () => {
  it("runs a full scan with all target fields", async () => {
    const res = await request(app)
      .post("/api/osint/scan/full")
      .send({
        email:    "test@example.com",
        domain:   "example.com",
        username: "testuser",
        ip:       "8.8.8.8",
      });

    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body).toHaveProperty("finalScore");
    expect(res.body).toHaveProperty("riskLevel");
    expect(res.body).toHaveProperty("results");
    expect(res.body).toHaveProperty("recommendations");
  });

  it("rejects scan with no target fields", async () => {
    const res = await request(app).post("/api/osint/scan/full").send({});
    expect(res.statusCode).toBe(400);
  });
});

describe("404 handler", () => {
  it("returns 404 for unknown routes", async () => {
    const res = await request(app).get("/api/nonexistent");
    expect(res.statusCode).toBe(404);
    expect(res.body.success).toBe(false);
  });
});
