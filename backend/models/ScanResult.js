const mongoose = require('mongoose');

const BreachDataSchema = new mongoose.Schema({
  name: String,
  date: String,
  dataClasses: [String],
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'] },
  affectedRecords: Number,
});

const WhoisDataSchema = new mongoose.Schema({
  domain: String,
  registrar: String,
  createdDate: String,
  expiryDate: String,
  nameServers: [String],
  exposedEmail: Boolean,
});

const ShodanDataSchema = new mongoose.Schema({
  ip: String,
  openPorts: [Number],
  services: [
    {
      port: Number,
      service: String,
      version: String,
    },
  ],
  vulnerabilities: [String],
  country: String,
  organization: String,
});

const SocialMediaSchema = new mongoose.Schema({
  platform: String,
  username: String,
  url: String,
  isPublic: Boolean,
  lastActive: String,
});

const ExifDataSchema = new mongoose.Schema({
  fileName: String,
  gpsLocation: {
    lat: Number,
    lng: Number,
  },
  deviceModel: String,
  timestamp: String,
  risk: { type: String, enum: ['low', 'medium', 'high'] },
});

const NLPAnalysisSchema = new mongoose.Schema({
  sentiment: { type: String, enum: ['positive', 'neutral', 'negative', 'threatening'] },
  threatLevel: Number,
  keywords: [String],
  isDoxxed: Boolean,
  mentions: Number,
});

const RiskScoreSchema = new mongoose.Schema({
  overall: Number,
  categories: {
    dataBreaches: Number,
    domainSecurity: Number,
    networkExposure: Number,
    socialFootprint: Number,
    privacyLeaks: Number,
  },
  mlConfidence: Number,
});

const ScanResultSchema = new mongoose.Schema(
  {
    target: {
      email: String,
      domain: String,
      username: String,
      ipAddress: String,
    },
    status: { type: String, enum: ['pending', 'scanning', 'completed', 'failed'], default: 'pending' },
    breaches: [BreachDataSchema],
    whois: WhoisDataSchema,
    shodan: ShodanDataSchema,
    socialMedia: [SocialMediaSchema],
    exifData: [ExifDataSchema],
    nlpAnalysis: NLPAnalysisSchema,
    riskScore: RiskScoreSchema,
    recommendations: [String],
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true }
);

module.exports = mongoose.model('ScanResult', ScanResultSchema);
