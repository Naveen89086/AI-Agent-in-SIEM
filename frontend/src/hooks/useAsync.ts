import { useCallback, useEffect, useRef, useState } from "react";

export type AsyncStatus = "loading" | "success" | "error";

export interface AsyncState<T> {
  status: AsyncStatus;
  data: T | null;
  error: string | null;
  reload: () => void;
}

/**
 * Data-fetching hook with loading / error / success states plus optional
 * auto-refresh. Keeps components declarative and reusable for any endpoint.
 */
export function useAsync<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  refreshMs?: number
): AsyncState<T> {
  const [status, setStatus] = useState<AsyncStatus>("loading");
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  useEffect(() => {
    let active = true;
    setStatus((prev) => (prev === "success" ? "loading" : prev));
    setError(null);
    fetcherRef
      .current()
      .then((res) => {
        if (!active) return;
        setData(res);
        setStatus("success");
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : String(err));
        setStatus("error");
      });
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  useEffect(() => {
    if (!refreshMs) return;
    const timer = setInterval(() => setNonce((n) => n + 1), refreshMs);
    return () => clearInterval(timer);
  }, [refreshMs]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  return { status, data, error, reload };
}
