/**
 * Pure presentation helpers. No component imports anything else that does arithmetic.
 *
 * The rule this module exists to enforce is narrow and worth stating: **the console does not
 * compute metrics.** Every count, percentage, duration and delta it shows arrives in an API
 * response. What is left for the client is turning a value into a string -- digits, units,
 * a clock time -- and that is all this file does.
 *
 * The distinction is not pedantry. `views.py` is the single place that turns bundle facts
 * into numbers, and the tests there assert the funnel's every step is in the same unit and
 * that `lost` is always computable. A second implementation in TypeScript would be a second
 * answer to the same question, free to drift, and nothing would catch the drift: the page
 * would simply start disagreeing with the API it is reading.
 *
 * So: `formatDurationMs` formats a duration, it does not measure one. If a share, a rate or
 * a total is missing from a response, the fix belongs in `views.py`.
 */

/** A duration the API already measured. `null`/`undefined` mean "not measured yet". */
export function formatDurationMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds - minutes * 60);
  return `${minutes}m ${rest}s`;
}

/** An absolute timestamp, in the reader's locale. */
export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
}

/** A time of day, for the "last seen" style fields. */
export function formatClock(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleTimeString();
}

/** Thousands separators. Locale-driven, not a division. */
export function formatCount(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return value.toLocaleString();
}

/** A share the API computed, rendered as a percentage. */
export function formatPercent(share: number | null | undefined): string {
  if (share === null || share === undefined) return "—";
  return `${Math.round(share * 100)}%`;
}

/** A confidence the API computed, at a fixed precision so columns line up. */
export function formatConfidence(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return value.toFixed(2);
}

/**
 * A worker id, shortened for a badge. Truncation is presentational; the full value is the
 * title attribute so nothing is lost.
 */
export function shortenWorkerId(workerId: string | null | undefined): string {
  if (!workerId) return "—";
  const parts = workerId.split(":");
  if (parts.length >= 3 && parts[2]) return `${parts[0]}:${parts[1]}`;
  return workerId;
}

/** "3 of 19" from two numbers the API published, or "unknown total". */
export function formatUnits(done: number, total: number, label: string): string {
  const name = label || "units";
  if (!total) return `${done} ${name} (total unknown)`;
  return `${done} of ${total} ${name}`;
}

/**
 * Whether a job can still change. The two states that can are named by the contract, and
 * everything else is terminal -- derived from the API's state, not from a timer.
 */
export function isActive(state: string): boolean {
  return state === "queued" || state === "running";
}

/** The stage list with its labels, straight from the API's `stage_labels` map. */
export function stageLabel(stage: string, labels: Record<string, string>): string {
  return labels[stage] ?? stage;
}

/** A sign prefix for a delta the API computed. Presentation only. */
export function formatDelta(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return value > 0 ? `+${value.toLocaleString()}` : value.toLocaleString();
}
