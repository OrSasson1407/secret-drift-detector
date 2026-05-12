import React from 'react';
import { Run } from '../types';

interface Props {
  run: Run;
  onAcknowledge: (id: number) => void;
}

export const RunRow: React.FC<Props> = ({ run, onAcknowledge }) => {
  return (
    <div className="flex items-center justify-between p-4 mb-3 bg-slate-800 border border-slate-700/50 rounded-xl shadow-lg hover:bg-slate-750 hover:border-slate-600 transition-all">
      <div className="flex items-center space-x-4">
        <span className="font-mono text-emerald-400 font-bold bg-emerald-900/30 px-2 py-1 rounded-md">#{run.id}</span>
        <span className="text-slate-300 text-sm">{new Date(run.timestamp).toLocaleString()}</span>
        
        {run.has_drift ? (
          <span className="px-2.5 py-1 text-xs font-semibold bg-red-900/50 text-red-300 rounded-full border border-red-800/50">
            Drift Detected: {run.max_severity.toUpperCase()}
          </span>
        ) : (
          <span className="px-2.5 py-1 text-xs font-semibold bg-emerald-900/50 text-emerald-300 rounded-full border border-emerald-800/50">
            Healthy
          </span>
        )}
        
                {run.jira_task && (
          <span className="px-2.5 py-1 text-xs font-semibold bg-blue-900/50 text-blue-300 rounded-full border border-blue-800/50">
            🎫 {run.jira_task}
          </span>
        )}

        {run.acknowledged && (
          <span className="px-2.5 py-1 text-xs font-semibold bg-indigo-900/50 text-indigo-300 rounded-full border border-indigo-800/50">
            ✓ Acknowledged
          </span>
        )}
      </div>
      
      {run.has_drift && !run.acknowledged && (
        <button
          onClick={() => onAcknowledge(run.id)}
          className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium rounded-lg shadow-md transition-colors focus:ring-2 focus:ring-indigo-400 focus:outline-none"
        >
          Acknowledge
        </button>
      )}
    </div>
  );
};

