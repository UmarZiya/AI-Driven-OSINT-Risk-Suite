import { ArrowLeft, Clock, Shield, AlertCircle, CheckCircle } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import type { ScanHistoryItem } from '../types';

interface ScanHistoryProps {
  onBack: () => void;
  onViewReport: (scanId: string) => void;
}

export function ScanHistory({ onBack, onViewReport }: ScanHistoryProps) {
  // Mock scan history data
  const scanHistory: ScanHistoryItem[] = [
    {
      id: 'scan_1709040234567_abc123',
      target: 'john.doe@example.com',
      timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
      riskScore: 78,
      status: 'completed',
    },
    {
      id: 'scan_1709033856789_def456',
      target: 'example.com',
      timestamp: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(),
      riskScore: 45,
      status: 'completed',
    },
    {
      id: 'scan_1709020123456_ghi789',
      target: '@johndoe',
      timestamp: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
      riskScore: 62,
      status: 'completed',
    },
    {
      id: 'scan_1709006789012_jkl012',
      target: '192.168.1.100',
      timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      riskScore: 89,
      status: 'completed',
    },
    {
      id: 'scan_1708993456789_mno345',
      target: 'jane.smith@company.com',
      timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
      riskScore: 34,
      status: 'completed',
    },
    {
      id: 'scan_1708980123456_pqr678',
      target: 'testdomain.org',
      timestamp: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
      riskScore: 56,
      status: 'completed',
    },
  ];

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

  const getRelativeTime = (timestamp: string) => {
    const now = new Date();
    const then = new Date(timestamp);
    const diffMs = now.getTime() - then.getTime();
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHours / 24);

    if (diffHours < 1) return 'Less than an hour ago';
    if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
  };

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
                <h1 className="text-xl font-bold text-white">Scan History</h1>
                <p className="text-sm text-slate-400">View all previous security assessments</p>
              </div>
            </div>
            <Button
              variant="ghost"
              onClick={onBack}
              className="text-slate-300 hover:text-white"
            >
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Dashboard
            </Button>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        <Card className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="text-white">Recent Scans</CardTitle>
            <CardDescription className="text-slate-400">
              {scanHistory.length} scan{scanHistory.length !== 1 ? 's' : ''} performed
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {scanHistory.map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/50 p-4 transition-colors hover:border-slate-700 hover:bg-slate-900/50"
                >
                  <div className="flex items-center gap-4">
                    <div className={`rounded-full p-2 ${
                      scan.status === 'completed' ? 'bg-green-950/50' : 'bg-red-950/50'
                    }`}>
                      {scan.status === 'completed' ? (
                        <CheckCircle className="h-5 w-5 text-green-500" />
                      ) : (
                        <AlertCircle className="h-5 w-5 text-red-500" />
                      )}
                    </div>

                    <div>
                      <div className="flex items-center gap-3">
                        <h4 className="font-semibold text-white">{scan.target}</h4>
                        {getRiskBadge(scan.riskScore)}
                      </div>
                      <div className="mt-1 flex items-center gap-2 text-sm text-slate-400">
                        <Clock className="h-3 w-3" />
                        <span>{getRelativeTime(scan.timestamp)}</span>
                        <span>•</span>
                        <span>ID: {scan.id.substring(0, 20)}...</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-6">
                    <div className="text-right">
                      <div className="text-sm text-slate-400">Risk Score</div>
                      <div className={`text-2xl font-bold ${getRiskColor(scan.riskScore)}`}>
                        {scan.riskScore}
                      </div>
                    </div>

                    <Button
                      onClick={() => onViewReport(scan.id)}
                      variant="outline"
                      className="border-slate-700 text-slate-300 hover:bg-slate-800 hover:text-white"
                    >
                      View Report
                    </Button>
                  </div>
                </div>
              ))}
            </div>

            {scanHistory.length === 0 && (
              <div className="py-12 text-center">
                <Clock className="mx-auto mb-4 h-12 w-12 text-slate-600" />
                <h3 className="mb-2 font-semibold text-white">No scans yet</h3>
                <p className="text-slate-400">Start your first security assessment to see results here</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
