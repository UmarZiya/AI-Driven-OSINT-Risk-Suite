/**
 * Service: NLP Threat Detection
 * Re-exported here for clean import paths.
 */
const { analyzeText, calcThreatRiskScore } = require("./socialService");
module.exports = { analyzeText, calcThreatRiskScore };
