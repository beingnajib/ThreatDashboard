import { createContext, useCallback, useContext, useMemo, useState } from "react";

export function Loading({ label = "Loading" }) {
  return <div className="loading" role="status" aria-label={label}><span className="spinner" /></div>;
}

export function ErrorState({ error, onRetry }) {
  if (!error) return null;
  return (
    <div className="alert-banner danger" role="alert">
      <div style={{ flex: 1 }}>{error.message || String(error)}</div>
      {onRetry && <button className="btn small" onClick={() => onRetry()}>Retry</button>}
    </div>
  );
}

export function Empty({ children = "Nothing to show yet." }) {
  return <div className="empty">{children}</div>;
}

const ToastContext = createContext(() => {});

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const push = useCallback((message, tone = "info") => {
    const id = Math.random().toString(36).slice(2);
    setToasts((items) => [...items, { id, message, tone }]);
    setTimeout(() => setToasts((items) => items.filter((t) => t.id !== id)), tone === "error" ? 7000 : 4000);
  }, []);
  const value = useMemo(() => push, [push]);
  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-stack" aria-live="polite">
        {toasts.map((t) => <div key={t.id} className={`toast ${t.tone}`}>{t.message}</div>)}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}
