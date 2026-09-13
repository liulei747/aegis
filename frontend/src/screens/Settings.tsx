/**
 * Settings: the gateway's effective configuration, read-only.
 *
 * Read-only is not a missing feature -- the gateway's configuration comes from environment
 * variables, so "changing a setting" means changing a container's environment and restarting
 * it. An editable form here would either have to write those variables (a control plane this
 * project does not have) or pretend, so the screen shows where each value comes from instead.
 *
 * The CORS panel is the part specific to being a separately deployed front-end. If this origin
 * is not in `cors.allow_origins`, every request from this page fails with a browser-level error
 * that looks nothing like a permission problem; comparing the two here is what turns that into
 * a two-second diagnosis.
 */

import { apiBase } from "../api/config.ts";
import { api } from "../api/client.ts";
import type { SettingsView } from "../api/types.ts";
import { Banner, Empty, Field, Stat, usePolled } from "../components.tsx";

function originOf(base: string): string {
  if (base === "") return globalThis.location.origin;
  try {
    return new URL(base).origin;
  } catch {
    return base;
  }
}

function allowed(origins: string[], origin: string): boolean {
  return origins.includes("*") || origins.includes(origin);
}

/** Renders a flat config object; nested objects are shown as JSON so nothing is invented. */
function Section({ title, values }: { title: string; values: Record<string, unknown> }) {
  const rows = Object.entries(values);
  if (rows.length === 0) return null;
  return (
    <>
      <h2>{title}</h2>
      <div className="card summary-grid">
        {rows.map(([key, value]) => (
          <Field key={key} label={key}>
            {value === null || value === undefined ? (
              <span className="muted">—</span>
            ) : typeof value === "object" ? (
              <code>{JSON.stringify(value)}</code>
            ) : (
              <code>{String(value)}</code>
            )}
          </Field>
        ))}
      </div>
    </>
  );
}

export function SettingsScreen() {
  const settings = usePolled<SettingsView>(() => api.settings(), []);

  if (settings.error) {
    return (
      <section>
        <Banner>
          {settings.error.detail}
          {settings.error.status === 404
            ? " — 此网关不公开其配置。"
            : ""}
        </Banner>
      </section>
    );
  }
  if (!settings.data) {
    return (
      <section>
        <Empty>加载中…</Empty>
      </section>
    );
  }

  const data = settings.data;
  const origin = originOf(apiBase());
  const ok = allowed(data.cors?.allow_origins ?? [], origin);
  const { note, cors, ai, ...rest } = data;

  return (
    <section>
      <Banner kind="info">{note}</Banner>

      <h2>此部署</h2>
      <div className="stats">
        <Stat label="API 地址" value={<code>{apiBase() || "同源"}</code>} />
        <Stat label="来源" value={<code>{origin}</code>} />
        <Stat
          label="cors"
          value={ok ? <span className="ok">允许此来源</span> : <span className="error">已阻止</span>}
        />
      </div>
      {!ok ? (
        <Banner>
          网关只允许 {(cors?.allow_origins ?? []).join(", ") || "（无）"}。请将{" "}
          <code>{origin}</code> 加入 <code>AEGIS_CORS__ALLOW_ORIGINS</code> 并重启，
          否则本页面的所有请求都会失败。
        </Banner>
      ) : null}

      <h2>AI 阶段</h2>
      <div className="card summary-grid">
        <Field label="已启用">
          <code>{ai?.enabled ? "是" : "否"}</code>
        </Field>
        <Field label="模型">
          <code>{ai?.model || "—"}</code>
        </Field>
        <Field label="基础 URL">
          <code>{ai?.base_url || "—"}</code>
        </Field>
        <Field label="是否配置 API key">
          {ai?.api_key_present ? (
            <span className="ok">是</span>
          ) : (
            <span className="error">否</span>
          )}
        </Field>
        <Field label="API key 变量">
          {/* The variable's *name*, never its value: the API does not send the value at all. */}
          <code>{ai?.api_key_env || "—"}</code>
        </Field>
        <Field label="并发数">
          <code>{ai?.concurrency ?? "—"}</code>
        </Field>
        <Field label="最大上下文数">
          <code>{ai?.max_contexts ?? "—"}</code>
        </Field>
        <Field label="超时（秒）">
          <code>{ai?.timeout_s ?? "—"}</code>
        </Field>
      </div>

      <Section title="CORS" values={{ allow_origins: (cors?.allow_origins ?? []).join(", ") }} />
      <Section title="路径与日志" values={{ ...rest }} />
      <Section title="预算" values={data.budget ?? {}} />
      <Section title="队列" values={data.queue ?? {}} />
      <Section title="数据流" values={data.dataflow ?? {}} />
    </section>
  );
}
