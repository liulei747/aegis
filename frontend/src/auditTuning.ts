/** Browser preferences for future audits. Each submitted job still carries its own copy. */
export type AuditTuning = {
  concurrency?: number;
  max_tokens?: number;
  steps_per_agent?: number;
  timeout_s?: number;
  temperature?: number;
  max_rounds?: number;
};

const KEY = "aegis.audit.tuning.v1";
const limits: Record<keyof AuditTuning, [number, number]> = {
  concurrency: [1, 8],
  max_tokens: [0, 32768],
  steps_per_agent: [4, 16],
  timeout_s: [30, 600],
  temperature: [0, 2],
  max_rounds: [1, 5],
};

export function cleanAuditTuning(value: unknown): AuditTuning {
  if (!value || typeof value !== "object") return {};
  const source = value as Record<string, unknown>;
  const result: Record<string, number> = {};
  for (const [key, [min, max]] of Object.entries(limits)) {
    const number = source[key];
    if (typeof number !== "number" || !Number.isFinite(number) || number < min || number > max) continue;
    if (key !== "temperature" && !Number.isInteger(number)) continue;
    if (key === "max_tokens" && number !== 0 && number < 4096) continue;
    result[key] = number;
  }
  return result;
}

export function loadAuditTuning(): AuditTuning {
  try {
    return cleanAuditTuning(JSON.parse(localStorage.getItem(KEY) ?? "{}"));
  } catch {
    return {};
  }
}

export function saveAuditTuning(value: AuditTuning): boolean {
  try {
    localStorage.setItem(KEY, JSON.stringify(cleanAuditTuning(value)));
    return true;
  } catch {
    return false;
  }
}
