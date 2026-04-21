/**
 * OSINT Module: EXIF Metadata Extraction
 * Extracts sensitive metadata from uploaded images.
 * Uses exifr (pure JS, no native deps).
 *
 * Routes:
 *   POST /api/osint/exif/extract   — upload image, returns EXIF metadata + risk
 */

const express  = require("express");
const multer   = require("multer");
const exifr    = require("exifr");               // npm i exifr
const router   = express.Router();

// ─── Multer setup (memory storage — no disk writes) ───────────────────────────

const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 20 * 1024 * 1024 },       // 20 MB max
  fileFilter: (_req, file, cb) => {
    const allowed = ["image/jpeg", "image/jpg", "image/png", "image/tiff", "image/heic"];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only JPEG, PNG, TIFF, and HEIC images are supported."));
    }
  },
});

// ─── Sensitive EXIF fields reference ──────────────────────────────────────────

const SENSITIVE_FIELDS = {
  // GPS / location
  GPSLatitude:          { risk: "HIGH",   reason: "Precise GPS latitude embedded in image." },
  GPSLongitude:         { risk: "HIGH",   reason: "Precise GPS longitude embedded in image." },
  GPSAltitude:          { risk: "MEDIUM", reason: "Altitude data present." },
  GPSSpeed:             { risk: "MEDIUM", reason: "Movement speed captured." },
  GPSImgDirection:      { risk: "LOW",    reason: "Camera direction captured." },

  // Device / identity
  Make:                 { risk: "LOW",    reason: "Device manufacturer revealed." },
  Model:                { risk: "LOW",    reason: "Device model revealed." },
  Software:             { risk: "LOW",    reason: "Software/OS version revealed." },
  HostComputer:         { risk: "MEDIUM", reason: "Hostname of the originating computer." },
  Artist:               { risk: "MEDIUM", reason: "Author/owner name embedded." },
  Copyright:            { risk: "LOW",    reason: "Copyright/identity information." },
  CameraSerialNumber:   { risk: "MEDIUM", reason: "Camera serial number can link images together." },
  LensSerialNumber:     { risk: "LOW",    reason: "Lens serial number present." },
  OwnerName:            { risk: "HIGH",   reason: "Owner name directly embedded in image." },

  // Timestamps
  DateTimeOriginal:     { risk: "LOW",    reason: "Exact capture time recorded." },
  DateTimeDigitized:    { risk: "LOW",    reason: "Digitization timestamp present." },

  // Network / app
  ImageUniqueID:        { risk: "LOW",    reason: "Unique ID can be used for tracking." },
};

// ─── helpers ──────────────────────────────────────────────────────────────────

/**
 * Parse GPS coordinates from raw EXIF values into decimal degrees.
 */
function formatGPS(lat, lon, latRef, lonRef) {
  if (!lat || !lon) return null;
  const latitude  = (latRef  === "S" ? -1 : 1) * lat;
  const longitude = (lonRef  === "W" ? -1 : 1) * lon;
  return {
    latitude,
    longitude,
    googleMapsUrl: `https://www.google.com/maps?q=${latitude},${longitude}`,
  };
}

/**
 * Build EXIF risk sub-score (0–100).
 */
function calcExifRiskScore(findings) {
  if (!findings.length) return 0;

  let score = 0;
  for (const f of findings) {
    if (f.risk === "HIGH")   score += 30;
    if (f.risk === "MEDIUM") score += 15;
    if (f.risk === "LOW")    score +=  5;
  }
  return Math.min(score, 100);
}

// ─── route ────────────────────────────────────────────────────────────────────

/**
 * POST /api/osint/exif/extract
 * Form-data: file (image file)
 */
router.post("/extract", upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: "No image file provided." });
  }

  try {
    // Extract ALL available EXIF data
    const exifData = await exifr.parse(req.file.buffer, {
      tiff:  true,
      gps:   true,
      xmp:   true,
      iptc:  true,
      icc:   true,
      exif:  true,
      makerNote: false,   // Skip camera-specific maker notes (noisy)
    });

    if (!exifData) {
      return res.json({
        success:    true,
        filename:   req.file.originalname,
        hasExif:    false,
        riskScore:  0,
        riskLevel:  "LOW",
        message:    "No EXIF metadata found in this image.",
        recommendations: ["Image appears clean of embedded metadata."],
      });
    }

    // Identify sensitive findings
    const findings = [];
    for (const [field, meta] of Object.entries(SENSITIVE_FIELDS)) {
      if (exifData[field] !== undefined && exifData[field] !== null) {
        findings.push({
          field,
          value:  exifData[field],
          risk:   meta.risk,
          reason: meta.reason,
        });
      }
    }

    // GPS location (if present)
    const gps = formatGPS(
      exifData.GPSLatitude,
      exifData.GPSLongitude,
      exifData.GPSLatitudeRef,
      exifData.GPSLongitudeRef
    );

    const riskScore = calcExifRiskScore(findings);
    const riskLevel = riskScore >= 60 ? "HIGH" : riskScore >= 25 ? "MEDIUM" : "LOW";

    // Build a clean summary of all extracted metadata
    const metaSummary = {
      camera:     { make: exifData.Make, model: exifData.Model, software: exifData.Software },
      capture:    { dateTime: exifData.DateTimeOriginal || exifData.DateTime, flash: exifData.Flash },
      image:      { width: exifData.ImageWidth || exifData.ExifImageWidth, height: exifData.ImageHeight || exifData.ExifImageHeight, orientation: exifData.Orientation },
      gps:        gps,
      copyright:  exifData.Copyright  || exifData.Artist || null,
      ownerName:  exifData.OwnerName  || null,
    };

    return res.json({
      success:         true,
      filename:        req.file.originalname,
      hasExif:         true,
      sensitiveCount:  findings.length,
      riskScore,
      riskLevel,
      findings,
      metadata:        metaSummary,
      recommendations: buildExifRecommendations(riskLevel, findings, gps),
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: `EXIF extraction failed: ${err.message}` });
  }
});

// ─── recommendations ──────────────────────────────────────────────────────────

function buildExifRecommendations(riskLevel, findings, gps) {
  const recs = [];

  if (gps) {
    recs.push("GPS coordinates found in image. Remove before sharing publicly — location reveals where the photo was taken.");
    recs.push("Disable GPS tagging in your camera/phone settings: Settings → Camera → Location → Off.");
  }

  const hasOwner = findings.find((f) => f.field === "OwnerName" || f.field === "Artist");
  if (hasOwner) {
    recs.push("Personal identity information found in metadata. Strip it before sharing.");
  }

  const hasSerial = findings.find((f) => f.field === "CameraSerialNumber");
  if (hasSerial) {
    recs.push("Camera serial number present. This can link multiple images to the same device — consider stripping it.");
  }

  if (riskLevel !== "LOW") {
    recs.push("Use a metadata stripper (e.g., ExifTool, ImageOptim, or mat2) to sanitise images before sharing.");
  }

  if (!recs.length) {
    recs.push("No significant privacy-sensitive metadata detected.");
  }

  return recs;
}

module.exports = router;
