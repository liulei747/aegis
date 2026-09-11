/**
 * The console: four screens over the API's derived views.
 *
 * Information architecture follows `docs/VISUAL.md`. The route is kept in the URL hash so a
 * view can be linked to, and so a refresh lands where the reader was -- no router library,
 * because there are four screens and none of them has nested state worth a dependency.
 *
 * The loading model matters more than the rendering. Every screen loads through one hook
 * that keeps the last successful payload and reports failures beside it rather than instead
 * of it: a console that blanks out when a poll fails is a console that hides the answer it
 * already had. `GET /v1/jobs` failing is also not the same as "no jobs" -- that distinction
 * is why errors are displayed as errors.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { api, type ApiError } from "./api/client.ts";
import type { BundleSummary, Job, JobList, Observability } from "./api/types.ts";
import { formatTimestamp, isActive } from "./format.ts";
import { JobListScreen } from "./screens/JobList.tsx";
import { BundleListScreen } from "./screens/BundleList.tsx";
import { JobDetailScreen } from "./screens/JobDetail.tsx";
import { BundleScreen } from "./screens/BundleScreen.tsx";
import { CompareScreen } from "./screens/Compare.tsx";

type Route =
  | { screen: "jobs" }
  | { screen: "job"; jobId: string }
  | { screen: "bundles" }
  | { screen: "bundle"; bundleId: string }
  | { screen: "compare"; bundleId: string | null };

const POLL_MS = 2000;

function parseRoute(hash: string): Route {
  const path = hash.replace(/^#\/?/, "");
  const parts = path.split("/").filter(Boolean);
  if (parts[0] === "job" && parts[1]) return { screen: "job", jobId: parts[1] };
  if (parts[0] === "bundles") return { screen: "bundles" };
  if (parts[0] === "bundle" && parts[1]) return { screen: "bundle", bundleId: parts[1] };
  if (parts[0] === "compare") return { screen: "compare", bundleId: parts[1] ?? null };
  return { screen: "jobs" };
}

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

/**
 * One fetch, polled while it is still worth polling.
 *
 * `keepPrevious` is the important part: on a failed poll the previous data stays on screen
 * with the error shown alongside. Replacing the content with an error message would destroy
 * information the reader already had, and a queue console that goes blank every time a poll
 * loses a race is worse than one that admits the poll failed.
 */
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

export function App() {
  const [route, navigate] = useRoute();

  const jobList = usePolled<JobList>(() => api.jobs(), [], { pollMs: POLL_MS });
  const bundleList = usePolled<{ bundles: BundleSummary[] }>(() => api.bundles(), [], {
    pollMs: 10_000,
  });
  // The provider legend is a *published* mapping (provider -> trust), so the trust shown on
  // the list screen is the API's judgement rather than a prefix rule invented here. It comes
  // from the observability payload, which is where `views.PROVIDER_NOTES` is exposed.
  const legend = usePolled<Observability>(
    () => api.observability(bundleList.data?.bundles?.[0]?.bundle_id ?? ""),
    [bundleList.data?.bundles?.[0]?.bundle_id ?? ""],
    { enabled: (bundleList.data?.bundles?.length ?? 0) > 0 },
  );

  const activeJobs = (jobList.data?.jobs ?? []).filter((job) => isActive(job.state)).length;
  const queue = jobList.data?.queue ?? null;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <strong>Aegis</strong>
          <span className="muted">pipeline observability</span>
        </div>
        <nav>
          <button
            type="button"
            className={route.screen === "jobs" || route.screen === "job" ? "active" : ""}
            onClick={() => navigate("/jobs")}
          >
            Jobs {activeJobs > 0 ? <span className="badge">{activeJobs}</span> : null}
          </button>
          <button
            type="button"
            className={route.screen === "bundles" || route.screen === "bundle" ? "active" : ""}
            onClick={() => navigate("/bundles")}
          >
            Bundles
          </button>
        </nav>
        <div className="queue-state">
          {queue ? (
            <>
              <span title="jobs waiting to be claimed">queued {queue.queued}</span>
              <span title="entries delivered but not acknowledged">pending {queue.pending}</span>
              <span title="entries never delivered">lag {queue.lag ?? "—"}</span>
              <span title="workers that wrote a heartbeat recently">
                workers {queue.workers_alive}
              </span>
              {queue.degraded ? (
                <span className="warn" title={queue.detail ?? "queue degraded"}>
                  ⚠ queue degraded
                </span>
              ) : null}
            </>
          ) : (
            <span className="muted">queue unavailable</span>
          )}
        </div>
      </header>

      {jobList.error ? (
        <Banner>
          Could not read the job queue: {jobList.error.detail}
          {jobList.error.status === 503
            ? " — the gateway has no Redis configured, so jobs run synchronously."
            : ""}
        </Banner>
      ) : null}

      <main>
        {route.screen === "jobs" ? (
          <JobListScreen
            jobs={jobList.data?.jobs ?? []}
            loading={jobList.loading}
            onOpen={(jobId) => navigate(`/job/${jobId}`)}
            onSubmitted={jobList.reload}
          />
        ) : null}

        {route.screen === "job" ? (
          <JobDetailScreen
            jobId={route.jobId}
            onBack={() => navigate("/jobs")}
            onOpenBundle={(bundleId) => navigate(`/bundle/${bundleId}`)}
          />
        ) : null}

        {route.screen === "bundles" ? (
          <BundleListScreen
            bundles={bundleList.data?.bundles ?? []}
            loading={bundleList.loading}
            error={bundleList.error}
            legend={legend.data?.provider_legend ?? {}}
            onOpen={(bundleId) => navigate(`/bundle/${bundleId}`)}
            onCompare={(bundleId) => navigate(`/compare/${bundleId}`)}
          />
        ) : null}

        {route.screen === "bundle" ? (
          <BundleScreen
            bundleId={route.bundleId}
            onBack={() => navigate("/bundles")}
            onCompare={() => navigate(`/compare/${route.bundleId}`)}
          />
        ) : null}

        {route.screen === "compare" ? (
          <CompareScreen
            bundles={bundleList.data?.bundles ?? []}
            initialLeft={route.bundleId}
            onBack={() => navigate("/bundles")}
          />
        ) : null}
      </main>
    </div>
  );
}

export function Banner({ children }: { children: React.ReactNode }) {
  return <div className="banner">{children}</div>;
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function TrustBadge({ trust }: { trust: string }) {
  return <span className={`trust trust-${trust}`}>{trust}</span>;
}

export function StateBadge({ job }: { job: Job | JobList["jobs"][number] }) {
  const requested = job.cancel_requested && isActive(job.state);
  return (
    <span className={`state state-${job.state}`}>
      {requested ? `canceling (${job.state})` : job.state}
      {job.cancel_requested && !isActive(job.state) ? " · cancel requested" : ""}
    </span>
  );
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="field">
      <span className="field-label">{label}</span>
      <span className="field-value">{children}</span>
    </div>
  );
}

export { formatTimestamp };
