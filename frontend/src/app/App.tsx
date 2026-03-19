import { useState, useEffect } from 'react';
import { Dashboard } from './components/Dashboard';
import { ScanInterface } from './components/ScanInterface';
import { ScanReport } from './components/ScanReport';
import { ScanHistory } from './components/ScanHistory';
import { performOSINTScan } from './utils/osintEngine';
import type { ScanTarget, ScanResult } from './types';

type View = 'dashboard' | 'scan' | 'report' | 'history';

export default function App() {
  const [currentView, setCurrentView] = useState<View>('dashboard');
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [scanResults, setScanResults] = useState<Map<string, ScanResult>>(new Map());

  const handleStartScan = () => {
    setCurrentView('scan');
  };

  const handleScanStart = async (target: ScanTarget) => {
    // This will be called when the scan actually starts
    // The actual OSINT scan will be performed
    const result = await performOSINTScan(target);
    setScanResults(prev => new Map(prev).set(result.id, result));
    setCurrentScan(result);
  };

  const handleScanComplete = (scanId: string) => {
    // When scan completes, show the report
    const result = scanResults.get(scanId);
    if (result) {
      setCurrentScan(result);
      setCurrentView('report');
    }
  };

  const handleBackToDashboard = () => {
    setCurrentView('dashboard');
    setCurrentScan(null);
  };

  const handleViewHistory = () => {
    setCurrentView('history');
  };

  const handleViewReport = (scanId: string) => {
    // In a real app, this would fetch the scan from a database
    // For now, we'll create a mock scan
    const mockScan = scanResults.get(scanId);
    if (mockScan) {
      setCurrentScan(mockScan);
      setCurrentView('report');
    } else {
      // Generate a new mock scan for history items
      handleStartScan();
    }
  };

  return (
    <>
      {currentView === 'dashboard' && (
        <Dashboard onStartScan={handleStartScan} onViewHistory={handleViewHistory} />
      )}
      {currentView === 'scan' && (
        <ScanInterface
          onScanComplete={handleScanComplete}
          onBack={handleBackToDashboard}
          onScanStart={handleScanStart}
        />
      )}
      {currentView === 'report' && currentScan && (
        <ScanReport
          scan={currentScan}
          onBack={handleBackToDashboard}
        />
      )}
      {currentView === 'history' && (
        <ScanHistory
          onBack={handleBackToDashboard}
          onViewReport={handleViewReport}
        />
      )}
    </>
  );
}