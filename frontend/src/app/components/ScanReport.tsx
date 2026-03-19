import { ArrowLeft, Shield, AlertTriangle, Database, Globe, Users, Image, Brain, Download, Share2 } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Progress } from './ui/progress';
import { Separator } from './ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell } from 'recharts';
import type { ScanResult } from '../types';

interface ScanReportProps {
  scan: ScanResult;
  onBack: () => void;
}

export function ScanReport({ scan, onBack }: ScanReportProps) {
  const getRiskColor = (score: number) => {
    if (score >= 75) return 'text-red-500';
    if (score >= 50) return 'text-orange-500';
    if (score >= 25) return 'text-yellow-500';
    return 'text-green-500';
  };

  const getRiskBadge = (score: number) => {
    if (score >= 75) return <Badge variant="destructive">Critical</Badge>;
    if (score >= 50) return <Badge className="bg-orange-600">High</Badge>;
    if (score >= 25) return <Badge className="bg-yellow-600">Medium</Badge>;
    return <Badge className="bg-green-600">Low</Badge>;
  };

  const severityColors = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
  };

  // Spider chart data
  const radarData = [
    { category: 'Data Breaches', value: scan.riskScore.categories.dataBreaches },
    { category: 'Domain Security', value: scan.riskScore.categories.domainSecurity },
    { category: 'Network Exposure', value: scan.riskScore.categories.networkExposure },
    { category: 'Social Footprint', value: scan.riskScore.categories.socialFootprint },
    { category: 'Privacy Leaks', value: scan.riskScore.categories.privacyLeaks },
  ];

  // Bar chart data for breaches
  const breachData = scan.breaches.map(b => ({
    name: b.name.length > 20 ? b.name.substring(0, 20) + '...' : b.name,
    severity: b.severity === 'critical' ? 100 : b.severity === 'high' ? 75 : b.severity === 'medium' ? 50 : 25,
    color: severityColors[b.severity],
  }));

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Button
              variant="ghost"
              onClick={onBack}
              className="text-slate-300 hover:text-white"
            >
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Dashboard
            </Button>
            <div className="flex gap-2">
              <Button variant="outline" className="border-slate-700 text-slate-300 hover:bg-slate-800">
                <Share2 className="mr-2 h-4 w-4" />
                Share
              </Button>
              <Button variant="outline" className="border-slate-700 text-slate-300 hover:bg-slate-800">
                <Download className="mr-2 h-4 w-4" />
                Export PDF
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        {/* Risk Score Overview */}
        <Card className="mb-6 border-slate-800 bg-slate-900/50 backdrop-blur-sm">
          <CardHeader>
            <div className="flex items-start justify-between">
              <div>
                <CardTitle className="text-2xl text-white">Security Assessment Report</CardTitle>
                <CardDescription className="text-slate-400">
                  Scan ID: {scan.id} • {new Date(scan.timestamp).toLocaleString()}
                </CardDescription>
              </div>
              {getRiskBadge(scan.riskScore.overall)}
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-6 md:grid-cols-2">
              <div className="space-y-4">
                <div>
                  <div className="mb-2 flex items-center justify-between">
                    <span className="text-slate-300">Overall Risk Score</span>
                    <span className={`text-3xl font-bold ${getRiskColor(scan.riskScore.overall)}`}>
                      {scan.riskScore.overall}/100
                    </span>
                  </div>
                  <Progress value={scan.riskScore.overall} className="h-3" />
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                  <div className="mb-2 flex items-center gap-2">
                    <Brain className="h-4 w-4 text-purple-400" />
                    <span className="text-sm font-medium text-slate-300">ML Model Confidence</span>
                  </div>
                  <div className="text-2xl font-bold text-white">
                    {(scan.riskScore.mlConfidence * 100).toFixed(1)}%
                  </div>
                </div>

                <div className="space-y-2">
                  <h4 className="font-semibold text-white">Scan Target:</h4>
                  <div className="space-y-1 text-sm">
                    {scan.target.email && (
                      <div className="flex items-center gap-2 text-slate-300">
                        <Shield className="h-3 w-3" />
                        <span>Email: {scan.target.email}</span>
                      </div>
                    )}
                    {scan.target.domain && (
                      <div className="flex items-center gap-2 text-slate-300">
                        <Globe className="h-3 w-3" />
                        <span>Domain: {scan.target.domain}</span>
                      </div>
                    )}
                    {scan.target.username && (
                      <div className="flex items-center gap-2 text-slate-300">
                        <Users className="h-3 w-3" />
                        <span>Username: {scan.target.username}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div>
                <h4 className="mb-4 font-semibold text-white">Risk Category Breakdown</h4>
                <ResponsiveContainer width="100%" height={250}>
                  <RadarChart data={radarData}>
                    <PolarGrid stroke="#334155" />
                    <PolarAngleAxis dataKey="category" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fill: '#64748b' }} />
                    <Radar name="Risk" dataKey="value" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.6} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Detailed Findings */}
        <Tabs defaultValue="breaches" className="space-y-4">
          <TabsList className="grid w-full grid-cols-5 bg-slate-900/50 lg:w-auto lg:inline-grid">
            <TabsTrigger value="breaches" className="data-[state=active]:bg-slate-800">
              <Database className="mr-2 h-4 w-4" />
              Breaches
            </TabsTrigger>
            <TabsTrigger value="network" className="data-[state=active]:bg-slate-800">
              <Globe className="mr-2 h-4 w-4" />
              Network
            </TabsTrigger>
            <TabsTrigger value="social" className="data-[state=active]:bg-slate-800">
              <Users className="mr-2 h-4 w-4" />
              Social
            </TabsTrigger>
            <TabsTrigger value="privacy" className="data-[state=active]:bg-slate-800">
              <Image className="mr-2 h-4 w-4" />
              Privacy
            </TabsTrigger>
            <TabsTrigger value="recommendations" className="data-[state=active]:bg-slate-800">
              <AlertTriangle className="mr-2 h-4 w-4" />
              Actions
            </TabsTrigger>
          </TabsList>

          {/* Data Breaches Tab */}
          <TabsContent value="breaches">
            <Card className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-white">Data Breach Analysis</CardTitle>
                <CardDescription className="text-slate-400">
                  {scan.breaches.length} breach{scan.breaches.length !== 1 ? 'es' : ''} found affecting this target
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {scan.breaches.length > 0 && (
                  <div>
                    <h4 className="mb-3 font-semibold text-white">Breach Severity Distribution</h4>
                    <ResponsiveContainer width="100%" height={200}>
                      <BarChart data={breachData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                        <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                        <YAxis tick={{ fill: '#94a3b8' }} />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                          labelStyle={{ color: '#e2e8f0' }}
                        />
                        <Bar dataKey="severity" radius={[4, 4, 0, 0]}>
                          {breachData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}

                <Separator className="bg-slate-800" />

                <div className="space-y-4">
                  {scan.breaches.map((breach, index) => (
                    <div key={index} className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                      <div className="mb-3 flex items-start justify-between">
                        <div>
                          <h4 className="font-semibold text-white">{breach.name}</h4>
                          <p className="text-sm text-slate-400">
                            Breach Date: {new Date(breach.date).toLocaleDateString()}
                          </p>
                        </div>
                        <Badge
                          variant={breach.severity === 'critical' ? 'destructive' : 'secondary'}
                          className={
                            breach.severity === 'high' ? 'bg-orange-600' :
                            breach.severity === 'medium' ? 'bg-yellow-600' :
                            breach.severity === 'low' ? 'bg-green-600' : ''
                          }
                        >
                          {breach.severity.toUpperCase()}
                        </Badge>
                      </div>
                      <div className="mb-2 text-sm text-slate-300">
                        Affected Records: {breach.affectedRecords.toLocaleString()}
                      </div>
                      <div>
                        <div className="mb-1 text-sm font-medium text-slate-400">Compromised Data:</div>
                        <div className="flex flex-wrap gap-2">
                          {breach.dataClasses.map((dataClass, idx) => (
                            <Badge key={idx} variant="outline" className="border-slate-700 text-slate-300">
                              {dataClass}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Network Exposure Tab */}
          <TabsContent value="network">
            <Card className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-white">Network Exposure Analysis</CardTitle>
                <CardDescription className="text-slate-400">
                  Infrastructure vulnerabilities and exposed services
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {scan.shodan ? (
                  <>
                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                        <div className="text-sm text-slate-400">IP Address</div>
                        <div className="text-lg font-semibold text-white">{scan.shodan.ip}</div>
                      </div>
                      <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                        <div className="text-sm text-slate-400">Organization</div>
                        <div className="text-lg font-semibold text-white">{scan.shodan.organization}</div>
                      </div>
                      <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                        <div className="text-sm text-slate-400">Country</div>
                        <div className="text-lg font-semibold text-white">{scan.shodan.country}</div>
                      </div>
                      <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                        <div className="text-sm text-slate-400">Open Ports</div>
                        <div className="text-lg font-semibold text-white">{scan.shodan.openPorts.length}</div>
                      </div>
                    </div>

                    {scan.shodan.services.length > 0 && (
                      <div>
                        <h4 className="mb-3 font-semibold text-white">Exposed Services</h4>
                        <div className="space-y-2">
                          {scan.shodan.services.map((service, idx) => (
                            <div key={idx} className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                              <div className="flex items-center gap-3">
                                <Badge variant="outline" className="border-blue-700 text-blue-400">
                                  Port {service.port}
                                </Badge>
                                <span className="text-white">{service.service}</span>
                              </div>
                              <span className="text-sm text-slate-400">v{service.version}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {scan.shodan.vulnerabilities.length > 0 && (
                      <div>
                        <h4 className="mb-3 font-semibold text-white">Known Vulnerabilities</h4>
                        <div className="space-y-2">
                          {scan.shodan.vulnerabilities.map((vuln, idx) => (
                            <div key={idx} className="flex items-center gap-3 rounded-lg border border-red-900/50 bg-red-950/20 p-3">
                              <AlertTriangle className="h-4 w-4 text-red-400" />
                              <span className="text-white">{vuln}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="py-8 text-center text-slate-400">
                    No network exposure data available for this scan
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Social Media Tab */}
          <TabsContent value="social">
            <Card className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-white">Social Media Footprint</CardTitle>
                <CardDescription className="text-slate-400">
                  {scan.socialMedia.length} social media profile{scan.socialMedia.length !== 1 ? 's' : ''} discovered
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-2">
                  {scan.socialMedia.map((profile, idx) => (
                    <div key={idx} className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                      <div className="mb-2 flex items-center justify-between">
                        <h4 className="font-semibold text-white">{profile.platform}</h4>
                        {profile.isPublic ? (
                          <Badge variant="destructive" className="text-xs">Public</Badge>
                        ) : (
                          <Badge variant="secondary" className="bg-green-900 text-xs">Private</Badge>
                        )}
                      </div>
                      <p className="mb-1 text-sm text-slate-300">@{profile.username}</p>
                      <p className="mb-2 text-xs text-slate-400">
                        Last Active: {new Date(profile.lastActive).toLocaleDateString()}
                      </p>
                      <a
                        href={profile.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-blue-400 hover:underline"
                      >
                        View Profile →
                      </a>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Privacy Leaks Tab */}
          <TabsContent value="privacy">
            <Card className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-white">Privacy & Metadata Leaks</CardTitle>
                <CardDescription className="text-slate-400">
                  EXIF data and metadata extraction results
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {scan.exifData.map((exif, idx) => (
                    <div key={idx} className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                      <div className="mb-3 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Image className="h-4 w-4 text-blue-400" />
                          <h4 className="font-semibold text-white">{exif.fileName}</h4>
                        </div>
                        <Badge
                          variant={exif.risk === 'high' ? 'destructive' : 'secondary'}
                          className={exif.risk === 'medium' ? 'bg-yellow-600' : exif.risk === 'low' ? 'bg-green-600' : ''}
                        >
                          {exif.risk.toUpperCase()} Risk
                        </Badge>
                      </div>
                      <div className="space-y-1 text-sm">
                        {exif.gpsLocation && (
                          <div className="text-red-400">
                            ⚠️ GPS Location: {exif.gpsLocation.lat.toFixed(4)}, {exif.gpsLocation.lng.toFixed(4)}
                          </div>
                        )}
                        {exif.deviceModel && (
                          <div className="text-slate-300">Device: {exif.deviceModel}</div>
                        )}
                        {exif.timestamp && (
                          <div className="text-slate-400">
                            Captured: {new Date(exif.timestamp).toLocaleString()}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {scan.nlpAnalysis && (
                  <>
                    <Separator className="my-6 bg-slate-800" />
                    <div>
                      <h4 className="mb-3 font-semibold text-white">NLP Threat Analysis</h4>
                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                          <div className="text-sm text-slate-400">Sentiment</div>
                          <div className="text-lg font-semibold text-white capitalize">
                            {scan.nlpAnalysis.sentiment}
                          </div>
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                          <div className="text-sm text-slate-400">Threat Level</div>
                          <div className={`text-lg font-semibold ${getRiskColor(scan.nlpAnalysis.threatLevel)}`}>
                            {scan.nlpAnalysis.threatLevel.toFixed(0)}/100
                          </div>
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                          <div className="text-sm text-slate-400">Public Mentions</div>
                          <div className="text-lg font-semibold text-white">
                            {scan.nlpAnalysis.mentions}
                          </div>
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                          <div className="text-sm text-slate-400">Doxxing Detected</div>
                          <div className={`text-lg font-semibold ${scan.nlpAnalysis.isDoxxed ? 'text-red-500' : 'text-green-500'}`}>
                            {scan.nlpAnalysis.isDoxxed ? 'Yes' : 'No'}
                          </div>
                        </div>
                      </div>
                      {scan.nlpAnalysis.keywords.length > 0 && (
                        <div className="mt-4">
                          <div className="mb-2 text-sm text-slate-400">Threat Keywords:</div>
                          <div className="flex flex-wrap gap-2">
                            {scan.nlpAnalysis.keywords.map((keyword, idx) => (
                              <Badge key={idx} variant="outline" className="border-red-700 text-red-400">
                                {keyword}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Recommendations Tab */}
          <TabsContent value="recommendations">
            <Card className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-white">Security Recommendations</CardTitle>
                <CardDescription className="text-slate-400">
                  Actionable steps to reduce your digital risk exposure
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {scan.recommendations.map((rec, idx) => (
                    <div key={idx} className="flex gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                      <div className="mt-0.5">
                        <div className="flex h-6 w-6 items-center justify-center rounded-full bg-blue-600 text-xs font-bold text-white">
                          {idx + 1}
                        </div>
                      </div>
                      <p className="flex-1 text-slate-300">{rec}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
