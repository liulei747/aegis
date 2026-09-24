import { useEffect, useState } from "react";
import { apiBase } from "../api/config.ts";
import { api, type ApiError } from "../api/client.ts";
import type { LLMConfig, LLMConfigUpdate, SettingsView } from "../api/types.ts";
import { loadAuditTuning, saveAuditTuning } from "../auditTuning.ts";
import { Banner, Empty, Field, Stat, usePolled } from "../components.tsx";
import { AuditTuningEditor } from "./AuditTuningEditor.tsx";

type Page = "llm" | "audit" | "deployment" | "budget" | "queue" | "dataflow" | "cors";
const PAGES: { id: Page; label: string }[] = [
  { id: "llm", label: "LLM 配置" }, { id: "audit", label: "审计参数" },
  { id: "deployment", label: "部署信息" }, { id: "budget", label: "预算" },
  { id: "queue", label: "队列" }, { id: "dataflow", label: "数据流" },
  { id: "cors", label: "跨域与路径" },
];

function Section({ title, values }: { title: string; values: Record<string, unknown> }) {
  return <><h2>{title}</h2><div className="card summary-grid">
    {Object.entries(values).map(([key, value]) => <Field key={key} label={key}>
      <code>{value == null ? "—" : typeof value === "object" ? JSON.stringify(value) : String(value)}</code>
    </Field>)}
  </div></>;
}

function editable(config: LLMConfig): LLMConfigUpdate {
  const { enabled, base_url, model, timeout_s, concurrency, temperature, max_tokens, max_contexts } = config;
  return { enabled, base_url, model, timeout_s, concurrency, temperature, max_tokens, max_contexts };
}

export function SettingsScreen() {
  const settings = usePolled<SettingsView>(() => api.settings(), []);
  const llm = usePolled<LLMConfig>(() => api.aiConfig(), []);
  const [page, setPage] = useState<Page>("llm");
  const [tuning, setTuning] = useState(loadAuditTuning);
  const [auditMessage, setAuditMessage] = useState("");
  const [form, setForm] = useState<LLMConfigUpdate | null>(null);
  const [keyInput, setKeyInput] = useState("");
  const [clearKey, setClearKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [failure, setFailure] = useState("");

  useEffect(() => { if (llm.data) setForm(editable(llm.data)); }, [llm.data]);

  const saveLLM = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!form) return;
    setSaving(true); setFailure(""); setMessage("");
    try {
      const saved = await api.updateAIConfig({ ...form,
        ...(keyInput.trim() ? { api_key: keyInput.trim() } : {}),
        ...(clearKey ? { clear_api_key: true } : {}),
      });
      setKeyInput(""); setClearKey(false); setForm(editable(saved));
      setMessage("已保存；新启动的任务会使用这些 LLM 配置。正在运行的任务不变。");
      llm.reload(); settings.reload();
    } catch (caught) { setFailure((caught as ApiError).detail); }
    finally { setSaving(false); }
  };

  const resetLLM = async () => {
    setSaving(true); setFailure(""); setMessage("");
    try {
      const restored = await api.resetAIConfig();
      setForm(editable(restored)); setKeyInput(""); setClearKey(false);
      setMessage("已恢复部署环境中的 LLM 配置；新任务立即读取。");
      llm.reload(); settings.reload();
    } catch (caught) { setFailure((caught as ApiError).detail); }
    finally { setSaving(false); }
  };

  if (settings.error) return <section><Banner>{settings.error.detail}</Banner></section>;
  if (!settings.data) return <section><Empty>加载中…</Empty></section>;
  const data = settings.data;
  let origin = globalThis.location.origin;
  try { if (apiBase()) origin = new URL(apiBase()).origin; } catch { origin = apiBase(); }
  const allowed = data.cors.allow_origins.includes("*") || data.cors.allow_origins.includes(origin);
  const { ai: _ai, cors, note: _note, budget, queue, dataflow, ...paths } = data;

  return <div className="settings-layout">
    <nav className="settings-subnav" aria-label="参数设置分类">
      {PAGES.map(item => <button key={item.id} type="button"
        className={page === item.id ? "active" : ""}
        aria-current={page === item.id ? "page" : undefined}
        onClick={() => setPage(item.id)}>{item.label}</button>)}
    </nav>
    <section className="settings-content">
      {page === "llm" ? <>
        <h2>LLM 配置</h2>
        <p className="muted">保存在网关与 worker 专用的服务端配置目录。新任务立即读取；密钥不会回显。</p>
        {llm.error ? <Banner>{llm.error.detail}</Banner> : null}
        {failure ? <Banner>{failure}</Banner> : null}
        {message ? <Banner kind="info">{message}</Banner> : null}
        {form && llm.data ? <form className="card" onSubmit={saveLLM}>
          <div className="summary-grid">
            <label>启用 LLM<select value={String(form.enabled)} onChange={e => setForm({ ...form, enabled: e.target.value === "true" })}>
              <option value="true">启用</option><option value="false">关闭</option>
            </select></label>
            <label>模型地址<input type="url" required={form.enabled} value={form.base_url}
              placeholder="https://provider.example/v1" onChange={e => setForm({ ...form, base_url: e.target.value })} /></label>
            <label>模型名称<input required={form.enabled} value={form.model}
              onChange={e => setForm({ ...form, model: e.target.value })} /></label>
            <label>API 密钥<input type="password" autoComplete="new-password" value={keyInput} disabled={clearKey}
              placeholder={llm.data.api_key_present ? "已配置；留空保持原值" : "输入 API 密钥"}
              onChange={e => setKeyInput(e.target.value)} /></label>
            <label>请求超时（秒）<input type="number" min="10" max="600" required value={form.timeout_s}
              onChange={e => setForm({ ...form, timeout_s: Number(e.target.value) })} /></label>
            <label>并发数<input type="number" min="1" max="16" required value={form.concurrency}
              onChange={e => setForm({ ...form, concurrency: Number(e.target.value) })} /></label>
            <label>输出 Token 上限（0 为服务商决定）<input type="number" min="0" max="200000" required value={form.max_tokens}
              onChange={e => setForm({ ...form, max_tokens: Number(e.target.value) })} /></label>
            <label>温度<input type="number" min="0" max="2" step="0.1" required value={form.temperature}
              onChange={e => setForm({ ...form, temperature: Number(e.target.value) })} /></label>
            <label>快速研判最大上下文数<input type="number" min="1" max="500" required value={form.max_contexts}
              onChange={e => setForm({ ...form, max_contexts: Number(e.target.value) })} /></label>
          </div>
          <label className="inline"><input type="checkbox" checked={clearKey} onChange={e => { setClearKey(e.target.checked); if (e.target.checked) setKeyInput(""); }} />移除页面保存的密钥，改用部署环境中的密钥</label>
          <p className="muted">密钥：{llm.data.api_key_present ? "已配置" : "未配置"}；来源：{llm.data.api_key_source === "saved" ? "页面保存" : "部署环境"}。</p>
          <div className="row">
            <button type="submit" disabled={saving}>{saving ? "保存中…" : "保存 LLM 配置"}</button>
            <button type="button" disabled={saving || llm.data.source !== "saved"} onClick={() => void resetLLM()}>恢复部署配置</button>
          </div>
        </form> : <Empty>读取 LLM 配置中…</Empty>}
      </> : null}

      {page === "audit" ? <>
        <h2>审计参数</h2>
        <form className="card" onSubmit={event => { event.preventDefault(); setAuditMessage(saveAuditTuning(tuning) ? "已保存" : "浏览器无法保存偏好"); }}>
          <p className="muted">当前浏览器的默认值；提交下一次深度审计时写入任务。留空使用 LLM 配置中的值。</p>
          <AuditTuningEditor value={tuning} onChange={next => { setTuning(next); setAuditMessage(""); }} />
          <div className="row"><button type="submit">保存审计默认值</button>
            <button type="button" onClick={() => { setTuning({}); setAuditMessage(saveAuditTuning({}) ? "已恢复" : "浏览器无法保存偏好"); }}>恢复 LLM 默认值</button>
            {auditMessage ? <span>{auditMessage}</span> : null}
          </div>
        </form>
      </> : null}

      {page === "deployment" ? <><h2>部署信息</h2><div className="stats">
        <Stat label="API 地址" value={<code>{apiBase() || "同源"}</code>} />
        <Stat label="来源" value={<code>{origin}</code>} />
        <Stat label="CORS" value={allowed ? "允许" : "已阻止"} />
      </div><Section title="路径与日志" values={paths} /></> : null}
      {page === "budget" ? <Section title="预算（部署只读）" values={budget ?? {}} /> : null}
      {page === "queue" ? <Section title="队列（部署只读）" values={queue ?? {}} /> : null}
      {page === "dataflow" ? <Section title="数据流（部署只读）" values={dataflow ?? {}} /> : null}
      {page === "cors" ? <><Section title="跨域来源（部署只读）" values={{ allow_origins: cors.allow_origins }} />
        {!allowed ? <Banner>此来源未在网关 CORS 白名单中。请更新部署配置并重启网关。</Banner> : null}</> : null}
    </section>
  </div>;
}
