/**
 * Shared UI, the hash router, and the one loading hook.
 *
 * No router library: the route is a few path segments and lives in the URL hash so a screen can
 * be linked to and a refresh lands where the reader was.
 *
 * The loading model is the part worth keeping. A screen keeps the last successful payload and
 * reports a failed poll *beside* it rather than instead of it: a console that blanks out when
 * one request loses a race throws away the answer it already had. A failed `GET /v1/jobs` is
 * also not the same as "no jobs", which is why errors are rendered as errors.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { ApiError } from "./api/client.ts";
import { isActive } from "./format.ts";
import { JOB_STATE, label, severityLabel, TRUST } from "./labels.ts";
import { parseRoute, type Route } from "./routes.ts";

// Re-exported so screens keep importing the route type from one place; the implementation is in
// `routes.ts` because that file has no JSX and is therefore testable.
export { parseRoute };
export type { Route };

export function useRoute(): [Route, (to: string) => void] {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  const navigate = useCallback((to: string) => {
    window.location.hash = to;
  }, []);
  return [route, navigate];
}

export function usePolled<T>(
  load: () => Promise<T>,
  deps: unknown[],
  options: { pollMs?: number; enabled?: boolean } = {},
): { data: T | null; error: ApiError | null; loading: boolean; reload: () => void } {
  const { pollMs = 0, enabled = true } = options;
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(enabled);
  const [nonce, setNonce] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;

  const reload = useCallback(() => setNonce((value) => value + 1), []);

  useEffect(() => {
    if (!enabled) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    let timer: number | undefined;

    const run = async () => {
      try {
        const result = await loadRef.current();
        if (cancelled) return;
        setData(result);
        setError(null);
      } catch (caught) {
        if (cancelled) return;
        setError(caught as ApiError);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    void run();
    if (pollMs > 0) {
      timer = window.setInterval(() => void run(), pollMs);
    }
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, pollMs, enabled, nonce]);

  return { data, error, loading, reload };
}

export function Banner({
  children,
  kind = "error",
}: {
  children: React.ReactNode;
  kind?: "error" | "warn" | "info";
}) {
  return <div className={`banner ${kind}`}>{children}</div>;
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="field">
      <span className="field-label">{label}</span>
      <span className="field-value">{children}</span>
    </div>
  );
}

export function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="stat">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
    </div>
  );
}

export function TrustBadge({ trust }: { trust: string }) {
  return <span className={`trust trust-${trust}`}>{label(TRUST, trust)}</span>;
}

export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  if (!severity) return null;
  // `severityLabel` 而不是 `label(SEVERITY, …)`：这个角标同时用于模型研判的严重度和 SARIF
  // 命中的等级，后者（error/warning/note/info）不在 SEVERITY 里，只查一张表会显示英文。
  return <span className={`severity severity-${severity}`}>{severityLabel(severity)}</span>;
}

export function StateBadge({
  state,
  cancelRequested,
}: {
  state: string;
  cancelRequested: boolean;
}) {
  const requested = cancelRequested && isActive(state);
  return (
    <span className={`state state-${state}`}>
      {requested ? `正在取消（${label(JOB_STATE, state)}）` : label(JOB_STATE, state)}
      {cancelRequested && !isActive(state) ? " · 已请求取消" : ""}
    </span>
  );
}

/** A table whose rows are supplied whole, so no screen has to build cells by index. */
export function Table<T>({
  rows,
  columns,
  rowKey,
  onRowClick,
}: {
  rows: T[];
  columns: Array<{ header: string; cell: (row: T) => React.ReactNode; numeric?: boolean }>;
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
}) {
  return (
    <table className="table">
      <thead>
        <tr>
          {columns.map((column) => (
            <th key={column.header} className={column.numeric ? "num" : ""}>
              {column.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr
            key={rowKey(row)}
            className={onRowClick ? "clickable" : ""}
            onClick={onRowClick ? () => onRowClick(row) : undefined}
          >
            {columns.map((column) => (
              <td key={column.header} className={column.numeric ? "num" : ""}>
                {column.cell(row)}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
