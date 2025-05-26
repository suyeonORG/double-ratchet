/**
 * /examples/nextjs/src/app/components/Console.tsx
 * -------------------------------------------------
 * Double Ratchet Protocol Implementation
 *
 * Authors (Université Libre de Bruxelles ULB):
 * @suyeonORG, @ChaosArnhug, @KTBASECURITY, @Draimy
 *
 * - Signal Protocol Specifications by Trevor Perrin & Moxie Marlinspike
 *   https://signal.org/docs/specifications/doubleratchet/
 *   https://signal.org/docs/specifications/x3dh/
 *
 * - Original 2key-ratchet implementation by Peculiar Ventures, Inc. Under MIT license
 *   https://github.com/PeculiarVentures/2key-ratchet
 *
 * @license MIT
 */
import { useState } from "react";
import Spinner from "./Spinner";

interface ConsoleProps {
  logs: string[];
  isRunning: boolean;
  onClear: () => void;
  title?: string;
}

export default function Console({
  logs,
  isRunning,
  onClear,
  title = "Console Output",
}: ConsoleProps) {
  const [copySuccess, setCopySuccess] = useState(false);

  const handleCopy = async () => {
    try {
      const text = logs.join('\n');
      await navigator.clipboard.writeText(text);
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  return (
    <div className="console-container">
      <div className="console-header">
        <div className="console-title">
          {isRunning && <Spinner size={16} className="title-spinner" />}
          <span>{title}</span>
        </div>
        <div className="console-actions">
          <button 
            onClick={handleCopy} 
            className="copy-btn" 
            disabled={logs.length === 0}
            title="Copy to clipboard"
          >
            {copySuccess ? 'Copied!' : 'Copy'}
          </button>
          <button onClick={onClear} className="clear-btn" disabled={isRunning}>
            Clear
          </button>
        </div>
      </div>
      <div className="console-output">
        {logs.length > 0 ? (
          logs.map((log, index) => (
            <div key={index} className="log-line">
              {log}
            </div>
          ))
        ) : (
          <div className="empty-state">No output yet...</div>
        )}
      </div>
    </div>
  );
}
