import { useState, useEffect } from 'react';
import { Shield, Activity, Database, Globe, AlertTriangle, TrendingUp } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { fetchScanHistory } from '../utils/osintEngine';

interface DashboardProps {
  onStartScan: () => void;
  onViewHistory: () => void;
  onLogout: () => void;
  user: { name: string; email: string };
}

interface Alert {
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  time: string;
}

function getRelativeTime(timestamp: string) {
  const diffMs = Date.now() - new Date(timestamp).getTime();
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffHours / 24);
  if (diffHours < 1) return 'Less than an hour ago';
  if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
  return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
}

function scoreToSeverity(score: number): Alert['severity'] {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  return 'low';
}

export function Dashboard({ onStartScan, onViewHistory, onLogout, user }: DashboardProps) {
  const [totalScans, setTotalScans] = useState<number | null>(null);
  const [criticalCount, setCriticalCount] = useState<number | null>(null);
  const [breachCount, setBreachCount] = useState<number | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);

  useEffect(() => {
    fetchScanHistory().then((history) => {
      setTotalScans(history.length);
      setCriticalCount(history.filter((s) => s.riskScore >= 80).length);
      setBreachCount(history.filter((s) => s.riskScore >= 35).length);

      // Build alerts from the 5 most recent scans
      const recent = history.slice(0, 5);
      const built: Alert[] = recent.map((s) => ({
        severity: scoreToSeverity(s.riskScore),
        title:    `Scan: ${s.target}`,
        description: `Risk score ${s.riskScore}/100 — ${
          s.riskScore >= 75 ? 'Critical exposure detected' :
          s.riskScore >= 50 ? 'Significant vulnerabilities found' :
          s.riskScore >= 25 ? 'Moderate risks detected' :
          'Low risk detected'
        }`,
        time: getRelativeTime(s.timestamp),
      }));
      setAlerts(built);
    });
  }, []);

  const stats = [
    { title: 'Total Scans',    value: totalScans    === null ? '—' : String(totalScans),    icon: Activity      },
    { title: 'Critical Risks', value: criticalCount === null ? '—' : String(criticalCount), icon: AlertTriangle },
    { title: 'Data Breaches',  value: breachCount   === null ? '—' : String(breachCount),   icon: Database      },
    { title: 'Active Monitors', value: '—', icon: Globe },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-blue-600 p-2">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">OSINT Risk Suite</h1>
                <p className="text-sm text-slate-400">Digital Footprint Analysis Platform</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                onClick={onViewHistory}
                className="border-slate-700 text-slate-300 hover:bg-slate-800 hover:text-white"
              >
                View History
              </Button>
              <Button onClick={onStartScan} className="bg-blue-600 hover:bg-blue-700">
                New Scan
              </Button>
              <div className="flex items-center gap-3 border-l border-slate-700 pl-3">
                <div className="text-right">
                  <p className="text-sm font-medium text-white">{user.name}</p>
                  <p className="text-xs text-slate-400">{user.email}</p>
                </div>
                <Button
                  variant="ghost"
                  onClick={onLogout}
                  className="text-slate-400 hover:text-white"
                >
                  Logout
                </Button>
              </div>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        <div className="mb-8 grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {stats.map((stat, index) => {
            const Icon = stat.icon;
            return (
              <Card key={index} className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-slate-300">{stat.title}</CardTitle>
                  <Icon className="h-4 w-4 text-slate-400" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-white">{stat.value}</div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <Card className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-white">Welcome to OSINT Risk Suite</CardTitle>
                <CardDescription className="text-slate-400">
                  Advanced AI-Driven Digital Footprint Analysis
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-slate-300">
                  This platform integrates passive reconnaissance, machine learning risk classification,
                  and real-time monitoring to provide comprehensive security insights.
                </p>

                <div className="space-y-3">
                  <h3 className="font-semibold text-white">Key Features:</h3>
                  <div className="grid gap-3 md:grid-cols-2">
                    <div className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                      <Database className="mt-0.5 h-5 w-5 text-blue-400" />
                      <div>
                        <h4 className="font-medium text-white">Breach Detection</h4>
                        <p className="text-sm text-slate-400">LeakCheck, EmailRep, PwnedPasswords</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                      <Globe className="mt-0.5 h-5 w-5 text-green-400" />
                      <div>
                        <h4 className="font-medium text-white">Domain Analysis</h4>
                        <p className="text-sm text-slate-400">WHOIS and DNS reconnaissance</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                      <Activity className="mt-0.5 h-5 w-5 text-purple-400" />
                      <div>
                        <h4 className="font-medium text-white">Network Scanning</h4>
                        <p className="text-sm text-slate-400">Shodan integration for exposure detection</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                      <TrendingUp className="mt-0.5 h-5 w-5 text-orange-400" />
                      <div>
                        <h4 className="font-medium text-white">ML Risk Scoring</h4>
                        <p className="text-sm text-slate-400">AI-powered threat classification</p>
                      </div>
                    </div>
                  </div>
                </div>

                <Button onClick={onStartScan} className="w-full bg-blue-600 hover:bg-blue-700">
                  Start New Security Scan
                </Button>
              </CardContent>
            </Card>
          </div>

          <div>
            <Card className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-white">Recent Alerts</CardTitle>
                <CardDescription className="text-slate-400">Latest security findings</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {alerts.length === 0 ? (
                  <div className="py-8 text-center text-sm text-slate-500">
                    No alerts yet. Start a scan to detect risks.
                  </div>
                ) : (
                  alerts.map((alert, index) => (
                    <div
                      key={index}
                      className="flex gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3"
                    >
                      <div className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
                        alert.severity === 'critical' ? 'bg-red-500' :
                        alert.severity === 'high'     ? 'bg-orange-500' :
                        alert.severity === 'medium'   ? 'bg-yellow-500' :
                                                        'bg-green-500'
                      }`} />
                      <div className="flex-1 min-w-0">
                        <h4 className="text-sm font-medium text-white truncate">{alert.title}</h4>
                        <p className="text-xs text-slate-400">{alert.description}</p>
                        <p className="mt-1 text-xs text-slate-500">{alert.time}</p>
                      </div>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
