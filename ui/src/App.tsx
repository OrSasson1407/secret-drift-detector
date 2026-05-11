import { useEffect, useState } from 'react';
import axios from 'axios';
import { ShieldAlert, ShieldCheck, Activity, KeyRound } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

interface DriftItem {
  key: string;
  kind: string;
  severity: string;
  detail: string;
}

interface RunRecord {
  id: number;
  timestamp: string;
  expected_count: number;
  actual_count: number;
  drift_count: number;
  has_drift: boolean;
  report_json: {
    items: DriftItem[];
  };
}

function App() {
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchHistory = async () => {
    try {
      const res = await axios.get('http://127.0.0.1:8000/api/v1/history');
      if (!res.data.error) {
        setRuns(res.data);
      }
    } catch (error) {
      console.error("Failed to fetch history", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
    const interval = setInterval(fetchHistory, 10000); // Auto-refresh every 10s
    return () => clearInterval(interval);
  }, []);

  if (loading) return <div className="p-8 text-center text-gray-500">Loading detector history...</div>;

  const latestRun = runs[0];

  return (
    <div className="min-h-screen p-8 max-w-6xl mx-auto space-y-6">
      <header className="flex items-center justify-between pb-6 border-b border-gray-200">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-2">
            <KeyRound className="text-blue-600" />
            Secret Drift Dashboard
          </h1>
          <p className="text-gray-500 mt-1">Real-time configuration monitoring</p>
        </div>
        <div className="flex items-center gap-2 text-sm font-medium px-4 py-2 bg-white rounded-lg shadow-sm border border-gray-200">
          <Activity className="w-4 h-4 text-green-500 animate-pulse" />
          System Active
        </div>
      </header>

      {/* Top Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-gray-500 text-sm font-medium">Status</h3>
          <div className="mt-2 flex items-center gap-2">
            {latestRun?.has_drift ? (
              <><ShieldAlert className="text-red-500 w-8 h-8" /><span className="text-2xl font-bold text-gray-900">Drift Detected</span></>
            ) : (
              <><ShieldCheck className="text-green-500 w-8 h-8" /><span className="text-2xl font-bold text-gray-900">Secure</span></>
            )}
          </div>
        </div>
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-gray-500 text-sm font-medium">Expected Secrets</h3>
          <p className="mt-2 text-3xl font-bold text-gray-900">{latestRun?.expected_count || 0}</p>
        </div>
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h3 className="text-gray-500 text-sm font-medium">Active Drifts</h3>
          <p className="mt-2 text-3xl font-bold text-gray-900">{latestRun?.drift_count || 0}</p>
        </div>
      </div>

      {/* History Feed */}
      <h2 className="text-xl font-bold text-gray-900 pt-4">Recent Scans</h2>
      <div className="space-y-4">
        {runs.map((run) => (
          <div key={run.id} className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            <div className={`px-6 py-4 border-l-4 ${run.has_drift ? 'border-red-500 bg-red-50' : 'border-green-500 bg-green-50'} flex justify-between items-center`}>
              <div className="flex items-center gap-3">
                {run.has_drift ? <ShieldAlert className="text-red-500" /> : <ShieldCheck className="text-green-500" />}
                <span className="font-semibold text-gray-900">
                  Run #{run.id}
                </span>
                <span className="text-gray-500 text-sm">
                  {formatDistanceToNow(new Date(run.timestamp), { addSuffix: true })}
                </span>
              </div>
              <div className="text-sm font-medium text-gray-600">
                Found {run.actual_count} secrets in runtime
              </div>
            </div>
            
            {run.has_drift && run.report_json.items.length > 0 && (
              <div className="p-6">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="text-xs uppercase text-gray-500 border-b border-gray-200">
                      <th className="pb-3 font-medium">Key</th>
                      <th className="pb-3 font-medium">Kind</th>
                      <th className="pb-3 font-medium">Severity</th>
                      <th className="pb-3 font-medium">Detail</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {run.report_json.items.map((item, idx) => (
                      <tr key={idx}>
                        <td className="py-3 font-mono text-sm text-gray-900">{item.key}</td>
                        <td className="py-3 text-sm text-gray-600">{item.kind}</td>
                        <td className="py-3">
                          <span className={`px-2 py-1 text-xs font-semibold rounded-full 
                            ${item.severity === 'critical' ? 'bg-red-100 text-red-700' : 
                              item.severity === 'high' ? 'bg-orange-100 text-orange-700' : 
                              'bg-yellow-100 text-yellow-700'}`}>
                            {item.severity.toUpperCase()}
                          </span>
                        </td>
                        <td className="py-3 text-sm text-gray-500">{item.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export default App;
