import { useState } from 'react';
import { Mail, Globe, User, Server, ArrowLeft, Loader2 } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Progress } from './ui/progress';
import type { ScanTarget } from '../types';

interface ScanInterfaceProps {
  onScanComplete: (scanId: string) => void;
  onBack: () => void;
  onScanStart: (target: ScanTarget) => Promise<string>;
}

const PHASES = [
  { name: 'Initializing OSINT modules...', progress: 10 },
  { name: 'Querying breach databases...', progress: 25 },
  { name: 'Performing WHOIS lookup...', progress: 40 },
  { name: 'Scanning network exposure...', progress: 55 },
  { name: 'Analyzing social media presence...', progress: 70 },
  { name: 'Running NLP threat analysis...', progress: 85 },
  { name: 'Computing risk score...', progress: 95 },
];

export function ScanInterface({ onScanComplete, onBack, onScanStart }: ScanInterfaceProps) {
  const [target, setTarget] = useState<ScanTarget>({});
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState('');
  const [error, setError] = useState<string | null>(null);

  const hasTarget = !!(target.email || target.domain || target.username || target.ipAddress);

  const handleStartScan = async () => {
    if (!hasTarget) return;

    setIsScanning(true);
    setScanProgress(0);
    setError(null);

    // Run progress animation concurrently with the real API call
    const animateProgress = async () => {
      const stepMs = 2500; // spread animation over ~17s (7 phases × ~2.5s)
      for (const phase of PHASES) {
        setCurrentPhase(phase.name);
        setScanProgress(phase.progress);
        await new Promise(r => setTimeout(r, stepMs));
      }
    };

    try {
      const [scanId] = await Promise.all([
        onScanStart(target),   // real API call
        animateProgress(),     // visual progress
      ]);

      setScanProgress(100);
      setCurrentPhase('Scan complete!');
      await new Promise(r => setTimeout(r, 400));
      onScanComplete(scanId);
    } catch (err: any) {
      setError(err.message || 'Scan failed. Is the backend running?');
      setIsScanning(false);
      setScanProgress(0);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <div className="container mx-auto px-6 py-8">
        <Button
          variant="ghost"
          onClick={onBack}
          disabled={isScanning}
          className="mb-6 text-slate-300 hover:text-white"
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Dashboard
        </Button>

        <div className="mx-auto max-w-3xl">
          <Card className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-2xl text-white">New OSINT Scan</CardTitle>
              <CardDescription className="text-slate-400">
                Enter target information to begin reconnaissance and risk analysis
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!isScanning ? (
                <div className="space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="email" className="text-slate-300">Email Address</Label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-3 h-4 w-4 text-slate-400" />
                      <Input
                        id="email"
                        type="email"
                        placeholder="target@example.com"
                        value={target.email || ''}
                        onChange={(e) => setTarget({ ...target, email: e.target.value })}
                        className="border-slate-700 bg-slate-950/50 pl-10 text-white placeholder:text-slate-500"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="domain" className="text-slate-300">Domain Name</Label>
                    <div className="relative">
                      <Globe className="absolute left-3 top-3 h-4 w-4 text-slate-400" />
                      <Input
                        id="domain"
                        type="text"
                        placeholder="example.com"
                        value={target.domain || ''}
                        onChange={(e) => setTarget({ ...target, domain: e.target.value })}
                        className="border-slate-700 bg-slate-950/50 pl-10 text-white placeholder:text-slate-500"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="username" className="text-slate-300">Username</Label>
                    <div className="relative">
                      <User className="absolute left-3 top-3 h-4 w-4 text-slate-400" />
                      <Input
                        id="username"
                        type="text"
                        placeholder="johndoe"
                        value={target.username || ''}
                        onChange={(e) => setTarget({ ...target, username: e.target.value })}
                        className="border-slate-700 bg-slate-950/50 pl-10 text-white placeholder:text-slate-500"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="ip" className="text-slate-300">IP Address (Optional)</Label>
                    <div className="relative">
                      <Server className="absolute left-3 top-3 h-4 w-4 text-slate-400" />
                      <Input
                        id="ip"
                        type="text"
                        placeholder="192.168.1.1"
                        value={target.ipAddress || ''}
                        onChange={(e) => setTarget({ ...target, ipAddress: e.target.value })}
                        className="border-slate-700 bg-slate-950/50 pl-10 text-white placeholder:text-slate-500"
                      />
                    </div>
                  </div>

                  {error && (
                    <div className="rounded-lg border border-red-800 bg-red-950/30 p-3 text-sm text-red-400">
                      {error}
                    </div>
                  )}

                  <div className="rounded-lg border border-blue-900/50 bg-blue-950/20 p-4">
                    <h4 className="mb-2 font-semibold text-blue-400">Scan Coverage</h4>
                    <ul className="space-y-1 text-sm text-slate-300">
                      <li>• Data breach correlation (LeakCheck, EmailRep, PwnedPasswords)</li>
                      <li>• WHOIS and DNS enumeration</li>
                      <li>• Network exposure analysis (Shodan)</li>
                      <li>• Social media footprint mapping (20 platforms)</li>
                      <li>• NLP-based threat detection</li>
                      <li>• ML-powered risk scoring</li>
                    </ul>
                  </div>

                  <Button
                    onClick={handleStartScan}
                    disabled={!hasTarget}
                    className="w-full bg-blue-600 hover:bg-blue-700"
                  >
                    Start Deep Scan
                  </Button>
                </div>
              ) : (
                <div className="space-y-6 py-8">
                  <div className="flex items-center justify-center">
                    <Loader2 className="h-16 w-16 animate-spin text-blue-500" />
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-slate-300">{currentPhase}</span>
                      <span className="text-slate-400">{scanProgress}%</span>
                    </div>
                    <Progress value={scanProgress} className="h-2" />
                  </div>

                  <p className="text-center text-sm text-slate-400">
                    This may take up to 30 seconds. Please do not close this window.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
