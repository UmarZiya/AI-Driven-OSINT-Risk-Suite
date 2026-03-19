import { Shield, Activity, Database, Globe, AlertTriangle, TrendingUp } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';

interface DashboardProps {
  onStartScan: () => void;
  onViewHistory: () => void;
}

export function Dashboard({ onStartScan, onViewHistory }: DashboardProps) {
  const stats = [
    {
      title: 'Total Scans',
      value: '47',
      change: '+12.5%',
      icon: Activity,
      trend: 'up',
    },
    {
      title: 'Critical Risks',
      value: '3',
      change: '-25%',
      icon: AlertTriangle,
      trend: 'down',
    },
    {
      title: 'Data Breaches',
      value: '128',
      change: '+8.2%',
      icon: Database,
      trend: 'up',
    },
    {
      title: 'Active Monitors',
      value: '12',
      change: '+2',
      icon: Globe,
      trend: 'up',
    },
  ];

  const recentAlerts = [
    {
      severity: 'critical',
      title: 'New Data Breach Detected',
      description: 'LinkedIn credentials found in recent breach',
      time: '2 hours ago',
    },
    {
      severity: 'high',
      title: 'Open Port Vulnerability',
      description: 'Port 3306 exposed on production server',
      time: '5 hours ago',
    },
    {
      severity: 'medium',
      title: 'Social Media Exposure',
      description: 'Personal information publicly accessible',
      time: '1 day ago',
    },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Header */}
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
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        {/* Stats Grid */}
        <div className="mb-8 grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {stats.map((stat, index) => {
            const Icon = stat.icon;
            return (
              <Card key={index} className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-slate-300">
                    {stat.title}
                  </CardTitle>
                  <Icon className="h-4 w-4 text-slate-400" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-white">{stat.value}</div>
                  <p className={`text-xs ${stat.trend === 'up' ? 'text-red-400' : 'text-green-400'}`}>
                    {stat.change} from last month
                  </p>
                </CardContent>
              </Card>
            );
          })}
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          {/* Main Content - Welcome Section */}
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
                        <p className="text-sm text-slate-400">
                          Query HaveIBeenPwned and correlate breaches
                        </p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                      <Globe className="mt-0.5 h-5 w-5 text-green-400" />
                      <div>
                        <h4 className="font-medium text-white">Domain Analysis</h4>
                        <p className="text-sm text-slate-400">
                          WHOIS and DNS reconnaissance
                        </p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                      <Activity className="mt-0.5 h-5 w-5 text-purple-400" />
                      <div>
                        <h4 className="font-medium text-white">Network Scanning</h4>
                        <p className="text-sm text-slate-400">
                          Shodan integration for exposure detection
                        </p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                      <TrendingUp className="mt-0.5 h-5 w-5 text-orange-400" />
                      <div>
                        <h4 className="font-medium text-white">ML Risk Scoring</h4>
                        <p className="text-sm text-slate-400">
                          AI-powered threat classification
                        </p>
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

          {/* Sidebar - Recent Alerts */}
          <div>
            <Card className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-white">Recent Alerts</CardTitle>
                <CardDescription className="text-slate-400">
                  Latest security findings
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {recentAlerts.map((alert, index) => (
                  <div
                    key={index}
                    className="flex gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3"
                  >
                    <div className={`mt-0.5 h-2 w-2 rounded-full ${
                      alert.severity === 'critical' ? 'bg-red-500' :
                      alert.severity === 'high' ? 'bg-orange-500' :
                      'bg-yellow-500'
                    }`} />
                    <div className="flex-1">
                      <h4 className="text-sm font-medium text-white">{alert.title}</h4>
                      <p className="text-xs text-slate-400">{alert.description}</p>
                      <p className="mt-1 text-xs text-slate-500">{alert.time}</p>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}