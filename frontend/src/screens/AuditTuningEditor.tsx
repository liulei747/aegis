import type { AuditTuning } from "../auditTuning.ts";

type Key = keyof AuditTuning;

export function AuditTuningEditor({ value, onChange }: {
  value: AuditTuning;
  onChange: (next: AuditTuning) => void;
}) {
  const set = (key: Key, raw: string) => {
    const next = { ...value };
    if (raw === "") delete next[key];
    else next[key] = Number(raw);
    onChange(next);
  };
  return (
    <div className="summary-grid">
      <label>并发数
        <select value={value.concurrency ?? ""} onChange={e => set("concurrency", e.target.value)}>
          <option value="">部署默认</option>
          {[1, 2, 4, 8].map(n => <option key={n} value={n}>{n}</option>)}
        </select>
      </label>
      <label>单次输出 Token
        <select value={value.max_tokens ?? ""} onChange={e => set("max_tokens", e.target.value)}>
          <option value="">部署默认</option>
          <option value="0">由服务商决定（不发送上限）</option>
          {[4096, 8192, 16384, 32768].map(n => <option key={n} value={n}>{n}</option>)}
        </select>
      </label>
      <label>每个 Agent 的步数
        <select value={value.steps_per_agent ?? ""} onChange={e => set("steps_per_agent", e.target.value)}>
          <option value="">部署默认</option>
          {[4, 8, 12, 16].map(n => <option key={n} value={n}>{n}</option>)}
        </select>
      </label>
      <label>单次请求超时（秒）
        <input type="number" min="30" max="600" step="1" placeholder="部署默认" value={value.timeout_s ?? ""}
          onChange={e => set("timeout_s", e.target.value)} />
      </label>
      <label>温度
        <input type="number" min="0" max="2" step="0.1" placeholder="部署默认" value={value.temperature ?? ""}
          onChange={e => set("temperature", e.target.value)} />
      </label>
      <label>最多重派发轮数
        <select value={value.max_rounds ?? ""} onChange={e => set("max_rounds", e.target.value)}>
          <option value="">部署默认</option>
          {[1, 2, 3, 4, 5].map(n => <option key={n} value={n}>{n}</option>)}
        </select>
      </label>
    </div>
  );
}
