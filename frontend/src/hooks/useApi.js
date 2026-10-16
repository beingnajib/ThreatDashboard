import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "../lib/api";

/**
 * Fetch `path` with `params`; refetches when either changes, and every
 * `pollMs` milliseconds while the tab is visible. Stale responses are dropped.
 */
export function useApi(path, params, { pollMs = 0, enabled = true } = {}) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(Boolean(path) && enabled);
  const key = JSON.stringify(params || {});
  const requestId = useRef(0);

  const load = useCallback(
    async (quiet = false) => {
      if (!path || !enabled) return;
      const id = ++requestId.current;
      if (!quiet) setLoading(true);
      try {
        const result = await api.get(path, JSON.parse(key));
        if (id === requestId.current) {
          setData(result);
          setError(null);
        }
      } catch (err) {
        if (id === requestId.current) setError(err);
      } finally {
        if (id === requestId.current) setLoading(false);
      }
    },
    [path, key, enabled],
  );

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!pollMs) return undefined;
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") load(true);
    }, pollMs);
    return () => clearInterval(timer);
  }, [load, pollMs]);

  return { data, error, loading, reload: load, setData };
}

export function useDebounced(value, delay = 300) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}
