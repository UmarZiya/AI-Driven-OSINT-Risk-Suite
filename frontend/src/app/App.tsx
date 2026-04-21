import { useState, useEffect } from 'react';
import { AuthPage } from './components/AuthPage';
import { Dashboard } from './components/Dashboard';
import { ScanInterface } from './components/ScanInterface';
import { ScanReport } from './components/ScanReport';
import { ScanHistory } from './components/ScanHistory';
import { performOSINTScan, fetchScanById } from './utils/osintEngine';
import type { ScanTarget, ScanResult } from './types';

type View = 'dashboard' | 'scan' | 'report' | 'history';

interface User {
  id: string;
  name: string;
  email: string;
}

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [currentView, setCurrentView] = useState<View>('dashboard');
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);

  useEffect(() => {
    const token = localStorage.getItem('osint_token');
    const userData = localStorage.getItem('osint_user');
    if (token && userData) {
      setUser(JSON.parse(userData));
    }
  }, []);

  const handleAuth = (token: string, userData: User) => {
    localStorage.setItem('osint_token', token);
    localStorage.setItem('osint_user', JSON.stringify(userData));
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem('osint_token');
    localStorage.removeItem('osint_user');
    setUser(null);
    setCurrentView('dashboard');
  };

  const handleStartScan = () => setCurrentView('scan');

  const handleScanStart = async (target: ScanTarget): Promise<string> => {
    const result = await performOSINTScan(target);
    setCurrentScan(result);
    return result.id;
  };

  const handleScanComplete = (scanId: string) => {
    if (scanId) setCurrentView('report');
  };

  const handleBackToDashboard = () => {
    setCurrentView('dashboard');
    setCurrentScan(null);
  };

  const handleViewHistory = () => setCurrentView('history');

  const handleViewReport = async (scanId: string) => {
    const result = await fetchScanById(scanId);
    if (result) {
      setCurrentScan(result);
      setCurrentView('report');
    }
  };

  if (!user) {
    return <AuthPage onAuth={handleAuth} />;
  }

  return (
    <>
      {currentView === 'dashboard' && (
        <Dashboard
          onStartScan={handleStartScan}
          onViewHistory={handleViewHistory}
          onLogout={handleLogout}
          user={user}
        />
      )}
      {currentView === 'scan' && (
        <ScanInterface
          onScanComplete={handleScanComplete}
          onBack={handleBackToDashboard}
          onScanStart={handleScanStart}
        />
      )}
      {currentView === 'report' && currentScan && (
        <ScanReport scan={currentScan} onBack={handleBackToDashboard} />
      )}
      {currentView === 'history' && (
        <ScanHistory onBack={handleBackToDashboard} onViewReport={handleViewReport} />
      )}
    </>
  );
}
