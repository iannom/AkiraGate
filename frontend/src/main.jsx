import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  CircleX,
  CheckSquare,
  LogOut,
  CirclePlus,
  ChevronsLeft,
  ChevronsRight,
  Globe2,
  ListRestart,
  LoaderCircle,
  Network,
  Play,
  Power,
  RefreshCw,
  Save,
  Server,
  Shield,
  SquareTerminal,
  Trash2,
  Search,
  Wifi,
  Zap,
} from "lucide-react";
import "./styles.css";
import flagJpUrl from "./assets/flags/jp.svg";
import flagRoUrl from "./assets/flags/ro.svg";
import flagThUrl from "./assets/flags/th.svg";
import flagTwUrl from "./assets/flags/tw.svg";

class AuthError extends Error {}

const pages = [
  { id: "overview", label: "概览", icon: Activity },
  { id: "nodes", label: "节点", icon: Network },
  { id: "socks", label: "SOCKS5", icon: Wifi },
  { id: "settings", label: "设置", icon: Shield },
  { id: "runtime", label: "运行", icon: SquareTerminal },
];
const defaultPageID = "overview";
const activePageStorageKey = "akiragate.activePage";
const pageIDs = new Set(pages.map((page) => page.id));

function isKnownPageID(pageID) {
  return pageIDs.has(String(pageID || ""));
}

function getPageStorage() {
  try {
    if (typeof window === "undefined") {
      return null;
    }
    return window.localStorage || null;
  } catch (error) {
    console.warn("访问当前页面状态存储失败。", error);
    return null;
  }
}

function readStoredActivePage() {
  const storage = getPageStorage();
  if (!storage) {
    return defaultPageID;
  }
  try {
    const storedPage = storage.getItem(activePageStorageKey);
    if (isKnownPageID(storedPage)) {
      return storedPage;
    }
    if (storedPage) {
      storage.removeItem(activePageStorageKey);
    }
  } catch (error) {
    console.warn("读取当前页面状态失败，将使用默认首页。", error);
  }
  return defaultPageID;
}

function persistActivePage(pageID) {
  if (!isKnownPageID(pageID)) {
    return;
  }
  const storage = getPageStorage();
  if (!storage) {
    return;
  }
  try {
    storage.setItem(activePageStorageKey, pageID);
  } catch (error) {
    console.warn("保存当前页面状态失败。", error);
  }
}

const emptyForm = {
  web_host: "::",
  web_port: 8787,
  secret_path: "",
  admin_username: "admin",
  admin_password: "",
  openvpn_config: "",
  openvpn_auth: "",
  auto_connect: false,
  refresh_seconds: 960,
  routing_mode: "auto",
  force_country: "",
  fixed_node_id: "",
};

const nodePageSizes = [10, 25, 50, 100];
const ipTypeOptions = [
  ["", "全部类型"],
  ["unknown", "未知"],
  ["broadband", "宽带/住宅"],
  ["mobile", "移动网络"],
  ["proxy", "代理/VPN"],
  ["datacenter", "数据中心"],
];

const localFlagUrls = Object.freeze({
  jp: flagJpUrl,
  ro: flagRoUrl,
  th: flagThUrl,
  tw: flagTwUrl,
});

function normalizeCountryCode(code) {
  const normalized = String(code || "").trim().toLowerCase();
  return /^[a-z]{2}$/.test(normalized) ? normalized : "";
}

function countryCodeToFlagEmoji(normalizedCode) {
  return normalizedCode
    .toUpperCase()
    .split("")
    .map((letter) => String.fromCodePoint(0x1f1e6 + letter.charCodeAt(0) - 65))
    .join("");
}

function formatFlagFallbackText(code) {
  const fallback = String(code || "--").trim().slice(0, 2).toUpperCase();
  return fallback || "--";
}

function isNodeTestAction(actionName) {
  const name = String(actionName || "");
  return name === "test-nodes" || (name.startsWith("test-") && name !== "test-proxy");
}

function mergeNodeResults(state, nodeResults) {
  const results = Array.isArray(nodeResults) ? nodeResults : [nodeResults];
  const updates = new Map();
  for (const node of results) {
    if (node?.id) {
      updates.set(node.id, node);
    }
  }
  if (!state || !Array.isArray(state.nodes) || updates.size === 0) {
    return state;
  }

  let changed = false;
  const nodes = state.nodes.map((node) => {
    const update = updates.get(node.id);
    if (!update) {
      return node;
    }
    changed = true;
    return { ...node, ...update };
  });
  return changed ? { ...state, nodes } : state;
}

async function api(path, options = {}) {
  const response = await fetch(`./api/${path}`, {
    ...options,
    credentials: "same-origin",
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) {
    const error = response.status === 401
      ? new AuthError(data.error || "未登录或登录已过期")
      : new Error(data.error || response.statusText || "请求失败");
    error.status = response.status;
    throw error;
  }
  return data;
}

function stateToForm(state) {
  if (!state) {
    return emptyForm;
  }
  return {
    web_host: state.web_host || "::",
    web_port: state.web_port || 8787,
    secret_path: state.secret_path || "",
    admin_username: state.admin_username || "admin",
    admin_password: "",
    openvpn_config: state.openvpn_config || "",
    openvpn_auth: state.openvpn_auth || "",
    auto_connect: Boolean(state.auto_connect),
    refresh_seconds: state.refresh_seconds || 960,
    routing_mode: state.routing_mode || "auto",
    force_country: state.force_country || "",
    fixed_node_id: state.fixed_node_id || "",
  };
}

function defaultListener(index) {
  return {
    name: `socks${index + 1}`,
    host: "127.0.0.1",
    port: 7928 + index,
    username: "",
    password: "",
    enabled: true,
    backend_policy_enabled: false,
    country_code: "",
    entry_cidrs: [],
    fixed_node_id: "",
  };
}

function normalizeListener(listener, index) {
  const hasBackendPolicyValues = Boolean(
    listener?.country_code ||
    listener?.fixed_node_id ||
    (Array.isArray(listener?.entry_cidrs) && listener.entry_cidrs.length),
  );
  return {
    name: listener?.name || `socks${index + 1}`,
    host: listener?.host || "127.0.0.1",
    port: Number(listener?.port || 7928 + index),
    username: listener?.username || "",
    password: listener?.password || "",
    enabled: listener?.enabled !== false,
    backend_policy_enabled: listener?.backend_policy_enabled === true || (listener?.backend_policy_enabled === undefined && hasBackendPolicyValues),
    country_code: listener?.country_code || "",
    entry_cidrs: Array.isArray(listener?.entry_cidrs) ? listener.entry_cidrs : [],
    fixed_node_id: listener?.fixed_node_id || "",
  };
}

function parseCIDRInput(value) {
  return String(value || "")
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatListenAddress(listener) {
  const host = String(listener?.host || "127.0.0.1").trim();
  const port = Number(listener?.port || 0);
  if (!port) {
    return "";
  }
  const addressHost = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  return `${addressHost}:${port}`;
}

function listenerDisplayName(listener, index) {
  const name = String(listener?.name || `socks${index + 1}`).trim();
  const address = formatListenAddress(listener);
  return address ? `${name} (${address})` : name;
}

function apiBaseFromConfig(config) {
  return `/${encodeURIComponent(config?.secret_path || "")}/`;
}

function statusText(state) {
  if (!state) {
    return "加载中";
  }
  return state.connected ? "已连接" : "未连接";
}

function App() {
  const [auth, setAuth] = useState({ checked: false, authenticated: false, username: "" });
  const [loginForm, setLoginForm] = useState({ username: "admin", password: "" });
  const [loginMessage, setLoginMessage] = useState("");
  const [current, setCurrent] = useState(null);
  const [form, setForm] = useState(emptyForm);
  const [listeners, setListeners] = useState([]);
  const [logs, setLogs] = useState([]);
  const [gatewayComponents, setGatewayComponents] = useState([]);
  const [formDirty, setFormDirty] = useState(false);
  const [actionMsg, setActionMsg] = useState("");
  const [saveMsg, setSaveMsg] = useState("");
  const [busyAction, setBusyAction] = useState("");
  const [batchTestActive, setBatchTestActive] = useState(false);
  const [batchCancelPending, setBatchCancelPending] = useState(false);
  const [activePage, setActivePage] = useState(() => readStoredActivePage());

  const connected = Boolean(current?.connected);
  const runtimeWeb = `${current?.runtime_web_host || current?.web_host || "::"}:${current?.runtime_web_port || current?.web_port || 8787}`;
  const restartHint = current?.restart_needed
    ? "Web 监听地址或端口需要重启服务后生效"
    : "当前配置已生效";

  const handleAuthError = useCallback((error) => {
    if (error instanceof AuthError) {
      setAuth({ checked: true, authenticated: false, username: "" });
      setCurrent(null);
      setLoginMessage(error.message);
      return true;
    }
    return false;
  }, []);

  const loadState = useCallback(async (forceSync = false) => {
    try {
      const state = await api("state");
      setCurrent(state);
      if (forceSync || !formDirty) {
        setForm(stateToForm(state));
        setListeners((state.socks5_listeners || []).map(normalizeListener));
      }
    } catch (error) {
      if (!handleAuthError(error)) {
        throw error;
      }
    }
  }, [formDirty, handleAuthError]);

  const loadLogs = useCallback(async () => {
    try {
      const data = await api("logs");
      setLogs(data.logs || []);
    } catch (error) {
      if (!handleAuthError(error)) {
        throw error;
      }
    }
  }, [handleAuthError]);

  const loadGatewayStatus = useCallback(async () => {
    try {
      const data = await api("gateway_status");
      setGatewayComponents(data.components || []);
    } catch (error) {
      if (!handleAuthError(error)) {
        throw error;
      }
    }
  }, [handleAuthError]);

  const mergeNodeResultsIntoCurrent = useCallback((nodeResults) => {
    setCurrent((previous) => mergeNodeResults(previous, nodeResults));
  }, []);

  const handleBackgroundRefreshError = useCallback((error) => {
    if (!handleAuthError(error)) {
      setActionMsg(error.message || "后台刷新失败");
    }
  }, [handleAuthError]);

  const runAction = useCallback(
    async (name, pendingMessage, action, doneMessage) => {
      setBusyAction(name);
      setActionMsg(pendingMessage);
      try {
        const result = await action();
        setActionMsg(doneMessage(result));
        await loadState();
      } catch (error) {
        if (!handleAuthError(error)) {
          setActionMsg(error.message);
        }
      } finally {
        setBusyAction("");
      }
    },
    [handleAuthError, loadState],
  );

  useEffect(() => {
    api("session")
      .then((session) => {
        setAuth({ checked: true, authenticated: true, username: session.username || "" });
      })
      .catch((error) => {
        if (error instanceof AuthError) {
          setAuth({ checked: true, authenticated: false, username: "" });
          return;
        }
        setActionMsg(error.message);
        setAuth({ checked: true, authenticated: false, username: "" });
      });
  }, []);

  useEffect(() => {
    persistActivePage(activePage);
  }, [activePage]);

  useEffect(() => {
    if (!auth.authenticated) {
      return;
    }
    loadState()
      .then(loadLogs)
      .then(loadGatewayStatus)
      .catch((error) => {
        if (!handleAuthError(error)) {
          setActionMsg(error.message);
        }
      });
  }, [auth.authenticated, handleAuthError, loadGatewayStatus, loadLogs, loadState]);

  useEffect(() => {
    if (!auth.authenticated) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      loadState().catch(handleBackgroundRefreshError);
      loadLogs().catch(handleBackgroundRefreshError);
      loadGatewayStatus().catch(handleBackgroundRefreshError);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [auth.authenticated, handleBackgroundRefreshError, loadGatewayStatus, loadLogs, loadState]);

  useEffect(() => {
    if (!auth.authenticated || (!isNodeTestAction(busyAction) && !batchTestActive)) {
      return undefined;
    }
    let cancelled = false;
    const refreshNodeState = () => {
      loadState().catch((error) => {
        if (!cancelled && !handleAuthError(error)) {
          setActionMsg(error.message);
        }
      });
    };
    refreshNodeState();
    const timer = window.setInterval(refreshNodeState, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [auth.authenticated, batchTestActive, busyAction, handleAuthError, loadState]);

  const login = async (event) => {
    event.preventDefault();
    setBusyAction("login");
    setLoginMessage("正在登录...");
    try {
      const result = await api("login", {
        method: "POST",
        body: JSON.stringify({
          username: loginForm.username.trim(),
          password: loginForm.password,
        }),
      });
      setAuth({ checked: true, authenticated: true, username: result.username || loginForm.username.trim() });
      setLoginForm((previous) => ({ ...previous, password: "" }));
      setLoginMessage("");
    } catch (error) {
      setLoginMessage(error.message);
    } finally {
      setBusyAction("");
    }
  };

  const logout = async () => {
    setBusyAction("logout");
    try {
      await api("logout", { method: "POST" }).catch(() => {});
    } finally {
      setAuth({ checked: true, authenticated: false, username: "" });
      setCurrent(null);
      setLogs([]);
      setGatewayComponents([]);
      setBusyAction("");
    }
  };

  const updateForm = (field, value) => {
    setForm((previous) => ({ ...previous, [field]: value }));
    setFormDirty(true);
  };

  const updateListener = (index, field, value) => {
    setListeners((previous) =>
      previous.map((listener, idx) =>
        idx === index ? { ...listener, [field]: value } : listener,
      ),
    );
    setFormDirty(true);
  };

  const addListener = () => {
    setListeners((previous) => [...previous, defaultListener(previous.length)]);
    setFormDirty(true);
  };

  const removeListener = (index) => {
    setListeners((previous) => previous.filter((_, idx) => idx !== index));
    setFormDirty(true);
  };

  const payload = useMemo(
    () => ({
      web_host: String(form.web_host || "::").trim(),
      web_port: Number(form.web_port),
      secret_path: String(form.secret_path || "").trim(),
      admin_username: String(form.admin_username || "").trim(),
      admin_password: String(form.admin_password || "").trim(),
      openvpn_config: String(form.openvpn_config || "").trim(),
      openvpn_auth: String(form.openvpn_auth || "").trim(),
      auto_connect: Boolean(form.auto_connect),
      refresh_seconds: Number(form.refresh_seconds) || 960,
      routing_mode: form.routing_mode,
      force_country: String(form.force_country || "").trim().toUpperCase(),
      fixed_node_id: String(form.fixed_node_id || "").trim(),
      socks5_listeners: listeners.map((listener, index) => ({
        name: String(listener.name || `socks${index + 1}`).trim(),
        host: String(listener.host || "127.0.0.1").trim(),
        port: Number(listener.port),
        username: String(listener.username || "").trim(),
        password: String(listener.password || "").trim(),
        enabled: listener.enabled !== false,
        backend_policy_enabled: listener.backend_policy_enabled === true,
        country_code: String(listener.country_code || "").trim().toUpperCase(),
        entry_cidrs: Array.isArray(listener.entry_cidrs)
          ? listener.entry_cidrs.map((value) => String(value || "").trim()).filter(Boolean)
          : parseCIDRInput(listener.entry_cidrs),
        fixed_node_id: String(listener.fixed_node_id || "").trim(),
      })),
    }),
    [form, listeners],
  );

  const saveSettings = async () => {
    setBusyAction("save");
    setSaveMsg("正在保存...");
    const oldBase = apiBaseFromConfig(current);
    const oldAdminUsername = current?.admin_username || "admin";
    const adminPasswordChanged = Boolean(payload.admin_password);
    const body = {
      ...payload,
      admin_password: payload.admin_password || current?.admin_password || "",
    };

    try {
      const result = await api("settings", {
        method: "POST",
        body: JSON.stringify(body),
      });
      const newBase = apiBaseFromConfig(body);
      if (newBase !== oldBase) {
        setSaveMsg("已保存，正在打开新的安全后缀地址。");
        window.location.href = newBase;
        return;
      }
      if (body.admin_username !== oldAdminUsername || adminPasswordChanged) {
        setSaveMsg("已保存，登录信息已更新。请重新打开页面并使用新凭据登录。");
        setFormDirty(false);
        setAuth({ checked: true, authenticated: false, username: "" });
        return;
      }
      setSaveMsg(result.message || "已保存，重新连接后生效。");
      setFormDirty(false);
      await loadState(true);
    } catch (error) {
      if (!handleAuthError(error)) {
        setSaveMsg(error.message);
      }
    } finally {
      setBusyAction("");
    }
  };

  const connect = () =>
    runAction(
      "connect",
      "正在发送连接请求...",
      () => api("connect", { method: "POST" }),
      (result) => result.message || "已启动",
    );

  const connectNode = (nodeID, listenAddress) =>
    runAction(
      `connect-${nodeID}`,
      "正在连接节点...",
      () => api("connect", { method: "POST", body: JSON.stringify({ node_id: nodeID, listen_address: listenAddress }) }),
      (result) => result.message || "已启动",
    );

  const testNode = (nodeID) =>
    runAction(
      `test-${nodeID}`,
      "正在测试节点...",
      async () => {
        const result = await api("test_node", { method: "POST", body: JSON.stringify({ node_id: nodeID }) });
        mergeNodeResultsIntoCurrent(result.node);
        return result;
      },
      (result) => `节点测试完成: ${result.node?.probe_status || "unknown"}`,
    );

  const testNodes = async (nodeIDs) => {
    setBusyAction("test-nodes");
    setBatchTestActive(true);
    setBatchCancelPending(false);
    setActionMsg("正在批量测试节点真实出口...");
    try {
      const result = await api("test_nodes", { method: "POST", body: JSON.stringify({ node_ids: nodeIDs }) });
      mergeNodeResultsIntoCurrent(result.nodes || []);
      setActionMsg(
        result.cancelled
          ? `批量测试已取消: ${(result.nodes || []).length} 个节点返回结果`
          : `批量测试完成: ${(result.nodes || []).length} 个节点返回结果`,
      );
      await loadState();
    } catch (error) {
      if (!handleAuthError(error)) {
        setActionMsg(error.message);
      }
    } finally {
      setBusyAction("");
      setBatchTestActive(false);
      setBatchCancelPending(false);
    }
  };

  const cancelTestNodes = async () => {
    if (!batchTestActive || batchCancelPending) {
      return;
    }
    setBatchCancelPending(true);
    setActionMsg("正在取消批量测试...");
    try {
      const result = await api("cancel_test_nodes", { method: "POST" });
      setActionMsg(result.message || "已请求取消批量测试");
      await loadState();
    } catch (error) {
      if (!handleAuthError(error)) {
        setActionMsg(error.message);
      }
      setBatchCancelPending(false);
    }
  };

  const disconnect = () =>
    runAction(
      "disconnect",
      "正在断开...",
      () => api("disconnect", { method: "POST" }),
      () => "已断开",
    );

  const refreshNodes = () =>
    runAction(
      "refresh-nodes",
      "正在拉取 VPNGate 节点...",
      () => api("refresh_nodes", { method: "POST" }),
      (result) => `已拉取 ${(result.nodes || []).length} 个节点`,
    );

  const testProxy = () =>
    runAction(
      "test-proxy",
      "正在检测 SOCKS5 出口...",
      () => api("test_proxy", { method: "POST" }),
      (result) => `出口 IP ${result.ip || "-"}，延迟 ${result.latency_ms || 0} ms`,
    );

  if (!auth.checked) {
    return (
      <main className="auth-shell">
        <div className="auth-panel">
          <SectionTitle icon={Shield} title="正在检查登录状态" />
          <p className="muted">请稍候。</p>
        </div>
      </main>
    );
  }

  if (!auth.authenticated) {
    return (
      <main className="auth-shell">
        <form className="auth-panel" onSubmit={login}>
          <p className="eyebrow">AkiraGate</p>
          <h1>登录管理端</h1>
          <div className="stacked-fields">
            <TextInput label="管理账号" value={loginForm.username} onChange={(value) => setLoginForm((previous) => ({ ...previous, username: value }))} autoComplete="username" />
            <TextInput label="管理密码" type="password" value={loginForm.password} onChange={(value) => setLoginForm((previous) => ({ ...previous, password: value }))} autoComplete="current-password" />
          </div>
          <div className="actions">
            <button type="submit" className="primary" disabled={busyAction === "login"}>
              {busyAction === "login" ? <LoaderCircle className="spin" size={16} aria-hidden="true" /> : <Shield size={16} aria-hidden="true" />}
              <span>登录</span>
            </button>
          </div>
          <Message text={loginMessage} />
        </form>
      </main>
    );
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">AkiraGate</p>
          <h1>AkiraGate 管理端</h1>
          <p className="muted">用户态 OpenVPN、多 SOCKS5 端口、可选用户名密码鉴权</p>
        </div>
        <div className="topbar-actions">
          <StatusBadge connected={connected} text={statusText(current)} />
          <ActionButton icon={LogOut} label={`退出 ${auth.username || ""}`} compact busy={busyAction === "logout"} onClick={logout} />
        </div>
      </header>

      <nav className="page-tabs" aria-label="管理页面">
        {pages.map((page) => (
          <TabButton
            key={page.id}
            icon={page.icon}
            label={page.label}
            active={activePage === page.id}
            onClick={() => setActivePage(page.id)}
          />
        ))}
      </nav>

      {activePage === "overview" ? (
        <OverviewPage
          current={current}
          runtimeWeb={runtimeWeb}
          restartHint={restartHint}
          actionMsg={actionMsg}
          busyAction={busyAction}
          onConnect={connect}
          onDisconnect={disconnect}
          onTestProxy={testProxy}
          onRefresh={() => loadState(true).catch((error) => setActionMsg(error.message))}
        />
      ) : null}

      {activePage === "nodes" ? (
        <NodesPage
          current={current}
          busyAction={busyAction}
          batchTestActive={batchTestActive}
          batchCancelPending={batchCancelPending}
          actionMsg={actionMsg}
          onRefreshNodes={refreshNodes}
          onTest={testNode}
          onTestBatch={testNodes}
          onCancelBatchTest={cancelTestNodes}
          onConnect={connectNode}
        />
      ) : null}

      {activePage === "socks" ? (
        <SocksPage
          listeners={listeners}
          saveMsg={saveMsg}
          busyAction={busyAction}
          onAdd={addListener}
          onUpdate={updateListener}
          onRemove={removeListener}
          onSave={saveSettings}
        />
      ) : null}

      {activePage === "settings" ? (
        <SettingsPage
          form={form}
          saveMsg={saveMsg}
          busyAction={busyAction}
          onUpdateForm={updateForm}
          onSave={saveSettings}
        />
      ) : null}

      {activePage === "runtime" ? (
        <RuntimePage
          gatewayComponents={gatewayComponents}
          logs={logs}
          onRefreshGateway={() => loadGatewayStatus().catch((error) => setActionMsg(error.message))}
          onRefreshLogs={() => loadLogs().catch((error) => setActionMsg(error.message))}
        />
      ) : null}
    </main>
  );
}

function OverviewPage({ current, runtimeWeb, restartHint, actionMsg, busyAction, onConnect, onDisconnect, onTestProxy, onRefresh }) {
  return (
    <section className="panel">
      <SectionTitle icon={Activity} title="连接概览" />
      <div className="field-grid">
        <Readout label="状态" value={current?.message || current?.status || "-"} />
        <Readout
          label="本地代理地址"
          value={(current?.local_proxy_urls || []).length ? current.local_proxy_urls : ["-"]}
          mono
        />
        <Readout label="当前 Web 监听" value={runtimeWeb} mono />
        <Readout label="配置生效状态" value={restartHint} />
      </div>
      <div className="actions">
        <ActionButton icon={Play} label="连接" primary busy={busyAction === "connect"} onClick={onConnect} />
        <ActionButton icon={Power} label="断开" danger busy={busyAction === "disconnect"} onClick={onDisconnect} />
        <ActionButton icon={Globe2} label="检测出口" busy={busyAction === "test-proxy"} onClick={onTestProxy} />
        <ActionButton icon={RefreshCw} label="刷新状态" onClick={onRefresh} />
      </div>
      <Message text={actionMsg} />
    </section>
  );
}

function NodesPage({
  current,
  busyAction,
  batchTestActive,
  batchCancelPending,
  actionMsg,
  onRefreshNodes,
  onTest,
  onTestBatch,
  onCancelBatchTest,
  onConnect,
}) {
  const nodes = current?.nodes || [];
  const listeners = current?.socks5_listeners || [];
  const batchTesting = Boolean(batchTestActive);
  const cancellingBatchTest = Boolean(batchCancelPending);
  const batchActionActive = batchTesting || cancellingBatchTest;
  const [filters, setFilters] = useState({ keyword: "", country: "", ipType: "" });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [selectedIDs, setSelectedIDs] = useState([]);

  const countries = useMemo(() => {
    const values = new Map();
    for (const node of nodes) {
      const code = (node.country_short || node.country || "").trim().toUpperCase();
      if (!code) {
        continue;
      }
      values.set(code, node.country || code);
    }
    return [...values.entries()].sort((left, right) => left[1].localeCompare(right[1]));
  }, [nodes]);

  const filteredNodes = useMemo(() => {
    const keyword = filters.keyword.trim().toLowerCase();
    const country = filters.country.trim().toUpperCase();
    const ipType = filters.ipType;
    return nodes.filter((node) => {
      const nodeCountry = (node.country_short || "").toUpperCase();
      const type = node.exit_ip_info?.ip_type || "unknown";
      if (country && nodeCountry !== country) {
        return false;
      }
      if (ipType && type !== ipType) {
        return false;
      }
      if (!keyword) {
        return true;
      }
      const haystack = [
        node.country,
        node.country_short,
        formatEndpoint(node),
        formatProbeStatus(node),
        formatExitQualityText(node),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(keyword);
    });
  }, [filters, nodes]);

  const totalPages = Math.max(1, Math.ceil(filteredNodes.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pageNodes = filteredNodes.slice((safePage - 1) * pageSize, safePage * pageSize);
  const pageNodeIDs = pageNodes.map((node) => node.id).filter(Boolean);
  const selectedOnPage = pageNodeIDs.filter((id) => selectedIDs.includes(id));

  useEffect(() => {
    setPage(1);
  }, [filters.keyword, filters.country, filters.ipType, pageSize]);

  useEffect(() => {
    setSelectedIDs((previous) => previous.filter((id) => nodes.some((node) => node.id === id)));
  }, [nodes]);

  const listenerOptions = useMemo(
    () =>
      listeners
        .map((listener, index) => ({
          key: formatListenAddress(listener),
          label: listenerDisplayName(listener, index),
          enabled: listener.enabled !== false,
        }))
        .filter((listener) => listener.key && listener.enabled),
    [listeners],
  );

  const updateFilter = (field, value) => {
    setFilters((previous) => ({ ...previous, [field]: value }));
  };

  const toggleNode = (nodeID) => {
    if (batchActionActive || !nodeID) {
      return;
    }
    setSelectedIDs((previous) =>
      previous.includes(nodeID) ? previous.filter((id) => id !== nodeID) : [...previous, nodeID],
    );
  };

  const togglePage = () => {
    if (batchActionActive) {
      return;
    }
    if (selectedOnPage.length === pageNodeIDs.length) {
      setSelectedIDs((previous) => previous.filter((id) => !pageNodeIDs.includes(id)));
      return;
    }
    setSelectedIDs((previous) => [...new Set([...previous, ...pageNodeIDs])]);
  };

  const runBatchTest = () => {
    if (batchActionActive) {
      return;
    }
    const ids = selectedIDs.length ? selectedIDs : pageNodeIDs;
    if (!ids.length) {
      return;
    }
    onTestBatch(ids);
  };

  return (
    <section className="panel nodes-panel">
      <PanelHead
        icon={Network}
        title="VPNGate 节点"
        aside={`${filteredNodes.length} / ${nodes.length} 个节点`}
      />
      <div className="node-toolbar">
        <div className="search-field">
          <Search size={16} aria-hidden="true" />
          <input
            value={filters.keyword}
            onChange={(event) => updateFilter("keyword", event.target.value)}
            placeholder="搜索 IP、ASN、企业、国家或状态"
          />
        </div>
        <select value={filters.country} onChange={(event) => updateFilter("country", event.target.value)}>
          <option value="">全部国家</option>
          {countries.map(([code, label]) => (
            <option key={code} value={code}>
              {label} ({code})
            </option>
          ))}
        </select>
        <select value={filters.ipType} onChange={(event) => updateFilter("ipType", event.target.value)}>
          {ipTypeOptions.map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </div>
      <div className="page-actions split-actions">
        <div className="actions">
          <ActionButton icon={CheckSquare} label={selectedOnPage.length === pageNodeIDs.length && pageNodeIDs.length ? "取消本页" : "选择本页"} compact disabled={!pageNodeIDs.length || batchActionActive} onClick={togglePage} />
          <ActionButton icon={Zap} label={batchTesting ? "批量真测中" : selectedIDs.length ? `批量真测 ${selectedIDs.length}` : `真测本页 ${pageNodeIDs.length}`} compact busy={batchTesting} disabled={batchActionActive || (!selectedIDs.length && !pageNodeIDs.length)} onClick={runBatchTest} />
          {batchActionActive ? (
            <ActionButton icon={CircleX} label="取消批量测试" compact danger busy={cancellingBatchTest} disabled={!batchTesting || cancellingBatchTest} onClick={onCancelBatchTest} />
          ) : null}
        </div>
        <ActionButton icon={ListRestart} label="刷新 VPNGate 节点" busy={busyAction === "refresh-nodes"} disabled={batchActionActive} onClick={onRefreshNodes} />
      </div>
      <NodeList
        nodes={pageNodes}
        selectedIDs={selectedIDs}
        busyAction={busyAction}
        batchTesting={batchActionActive}
        listenerOptions={listenerOptions}
        onToggle={toggleNode}
        onTest={onTest}
        onConnect={onConnect}
      />
      <Pagination
        page={safePage}
        totalPages={totalPages}
        total={filteredNodes.length}
        pageSize={pageSize}
        pageSizes={nodePageSizes}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
      />
      <Message text={actionMsg} />
    </section>
  );
}

function SocksPage({ listeners, saveMsg, busyAction, onAdd, onUpdate, onRemove, onSave }) {
  return (
    <section className="panel">
      <PanelHead icon={Wifi} title="SOCKS5 监听端口" action={<ActionButton icon={CirclePlus} label="新增端口" compact onClick={onAdd} />} />
      <ListenerEditor listeners={listeners} onUpdate={onUpdate} onRemove={onRemove} />
      <div className="actions">
        <ActionButton icon={Save} label="保存 SOCKS5 设置" primary busy={busyAction === "save"} onClick={onSave} />
      </div>
      <Message text={saveMsg} />
    </section>
  );
}

function SettingsPage({ form, saveMsg, busyAction, onUpdateForm, onSave }) {
  return (
    <section className="panel">
      <SectionTitle icon={Shield} title="Web 与 OpenVPN 设置" />
      <div className="form-grid">
        <TextInput label="Web 监听地址" value={form.web_host} onChange={(value) => onUpdateForm("web_host", value)} placeholder="::" />
        <TextInput label="Web 监听端口" type="number" min="1" max="65535" value={form.web_port} onChange={(value) => onUpdateForm("web_port", value)} />
        <TextInput label="登录安全后缀" value={form.secret_path} onChange={(value) => onUpdateForm("secret_path", value)} />
        <TextInput label="管理账号" value={form.admin_username} onChange={(value) => onUpdateForm("admin_username", value)} />
        <TextInput label="管理密码" type="password" value={form.admin_password} onChange={(value) => onUpdateForm("admin_password", value)} placeholder="留空表示不修改" autoComplete="new-password" />
        <TextInput label="OpenVPN auth-user-pass 文件" value={form.openvpn_auth} onChange={(value) => onUpdateForm("openvpn_auth", value)} placeholder="/opt/akiragate/vpngate_auth.txt" />
        <SelectInput
          label="启动时自动连接 OpenVPN 配置"
          value={String(form.auto_connect)}
          onChange={(value) => onUpdateForm("auto_connect", value === "true")}
          options={[
            ["true", "启用"],
            ["false", "停用"],
          ]}
        />
        <TextInput label="节点刷新间隔（秒）" type="number" min="60" max="86400" value={form.refresh_seconds} onChange={(value) => onUpdateForm("refresh_seconds", value)} />
        <SelectInput
          label="出站路由模式"
          value={form.routing_mode}
          onChange={(value) => onUpdateForm("routing_mode", value)}
          options={[
            ["auto", "自动选择"],
            ["fixed_region", "固定国家地区"],
            ["fixed_ip", "固定节点"],
          ]}
        />
        <TextInput label="固定国家代码" value={form.force_country} onChange={(value) => onUpdateForm("force_country", value)} placeholder="JP" />
      </div>
      <div className="stacked-fields">
        <TextInput label="固定节点 ID" value={form.fixed_node_id} onChange={(value) => onUpdateForm("fixed_node_id", value)} placeholder="从节点列表复制 ID" />
        <TextInput label="OpenVPN 配置文件" value={form.openvpn_config} onChange={(value) => onUpdateForm("openvpn_config", value)} placeholder="/opt/akiragate/client.ovpn" />
      </div>
      <div className="actions form-actions">
        <ActionButton icon={Save} label="保存设置" primary busy={busyAction === "save"} onClick={onSave} />
      </div>
      <Message text={saveMsg} />
    </section>
  );
}

function RuntimePage({ gatewayComponents, logs, onRefreshGateway, onRefreshLogs }) {
  return (
    <div className="runtime-grid">
      <section className="panel">
        <PanelHead
          icon={Server}
          title="网关状态"
          action={<ActionButton icon={RefreshCw} label="刷新状态" compact onClick={onRefreshGateway} />}
        />
        <GatewayStatus components={gatewayComponents} />
      </section>
      <section className="panel">
        <PanelHead
          icon={SquareTerminal}
          title="运行日志"
          action={<ActionButton icon={RefreshCw} label="刷新日志" compact onClick={onRefreshLogs} />}
        />
        <LogView logs={logs} />
      </section>
    </div>
  );
}

function SectionTitle({ icon: Icon, title }) {
  return (
    <div className="section-title">
      <Icon size={18} aria-hidden="true" />
      <h2>{title}</h2>
    </div>
  );
}

function PanelHead({ icon: Icon, title, aside, action }) {
  return (
    <div className="panel-head">
      <SectionTitle icon={Icon} title={title} />
      {aside ? <span className="muted">{aside}</span> : action}
    </div>
  );
}

function TabButton({ icon: Icon, label, active, onClick }) {
  return (
    <button
      type="button"
      className={`tab-button ${active ? "active" : ""}`}
      onClick={onClick}
      aria-current={active ? "page" : undefined}
    >
      <Icon size={16} aria-hidden="true" />
      <span>{label}</span>
    </button>
  );
}

function StatusBadge({ connected, text }) {
  return <span className={`badge ${connected ? "ok" : ""}`}>{text}</span>;
}

function Message({ text }) {
  if (!text) {
    return null;
  }
  return <div className="message">{text}</div>;
}

function Readout({ label, value, mono = false }) {
  const values = Array.isArray(value) ? value : [value];
  return (
    <div>
      <label>{label}</label>
      <div className={`readout ${mono ? "mono" : ""}`}>
        {values.map((item, index) => (
          <React.Fragment key={`${item}-${index}`}>
            {index > 0 ? <br /> : null}
            {item}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

function TextInput({ label, value, onChange, type = "text", ...props }) {
  return (
    <div>
      <label>{label}</label>
      <input type={type} value={value ?? ""} onChange={(event) => onChange(event.target.value)} {...props} />
    </div>
  );
}

function SelectInput({ label, value, onChange, options }) {
  return (
    <div>
      <label>{label}</label>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue} value={optionValue}>
            {optionLabel}
          </option>
        ))}
      </select>
    </div>
  );
}

function ActionButton({ icon: Icon, label, onClick, primary = false, danger = false, compact = false, busy = false, disabled = false }) {
  return (
    <button
      type="button"
      className={`${primary ? "primary" : ""} ${danger ? "danger" : ""} ${compact ? "compact" : ""}`}
      onClick={onClick}
      disabled={busy || disabled}
    >
      {busy ? <LoaderCircle className="spin" size={16} aria-hidden="true" /> : <Icon size={16} aria-hidden="true" />}
      <span>{label}</span>
    </button>
  );
}

function formatEndpoint(node) {
  const host = node.remote_host || node.ip || "-";
  return node.remote_port ? `${host}:${node.remote_port}` : host;
}

function formatProbeStatus(node) {
  const status = node.probe_status || "not_checked";
  if (status === "not_checked") {
    return "未测试";
  }
  if (status === "testing") {
    return "测试中";
  }
  if (status === "cancelled") {
    return "已取消";
  }
  if (status === "unavailable") {
    return "不可用";
  }

  const latency = Number(node.probe_latency_ms);
  return Number.isFinite(latency) && latency > 0 ? `${latency} ms` : "可用";
}

function formatIPTypeLabel(type) {
  return ipTypeOptions.find(([value]) => value === type)?.[1] || "未知";
}

function includesAny(text, keywords) {
  return keywords.some((keyword) => text.includes(keyword));
}

function formatProbeFailureText(message) {
  const raw = String(message || "").trim();
  if (!raw) {
    return "测试失败";
  }

  const text = raw.toLowerCase();
  if (includesAny(raw, ["节点不存在"])) {
    return "节点已失效，请刷新列表";
  }
  if (includesAny(raw, ["节点缺少 OpenVPN 配置", "OpenVPN 配置路径不能为空", "OpenVPN 配置不可读"])) {
    return "OpenVPN 配置不可用";
  }
  if (includesAny(text, ["auth_failed", "auth-failed", "authentication failed", "username", "password"]) || includesAny(raw, ["认证", "用户名", "密码"])) {
    return "OpenVPN 认证失败";
  }
  if (includesAny(text, ["x509", "certificate", "tls"]) || includesAny(raw, ["证书"])) {
    return "TLS 或证书校验失败";
  }
  if (includesAny(raw, ["OpenVPN 未下发有效 IPv4 地址"])) {
    return "隧道地址获取失败";
  }
  if (includesAny(raw, ["初始化用户态 TCP/IP 栈失败", "创建用户态链路端点失败", "创建用户态 NIC 失败", "配置用户态 IPv4 地址失败"])) {
    return "用户态网络栈初始化失败";
  }
  if (includesAny(raw, ["临时 SOCKS5 服务异常退出"])) {
    return "临时代理异常退出";
  }
  if (includesAny(raw, ["临时 SOCKS5 服务启动失败"])) {
    return "临时代理启动失败";
  }
  if (includesAny(raw, ["等待临时 SOCKS5 服务启动超时"])) {
    return "临时代理启动超时";
  }
  if (includesAny(raw, ["解析目标域名失败"])) {
    return "出口检测域名解析失败";
  }
  if (includesAny(raw, ["域名没有可用 IP"])) {
    return "出口检测域名无可用 IP";
  }
  if (includesAny(raw, ["目标主机不能为空", "目标端口不能为空"])) {
    return "出口检测目标无效";
  }
  if (includesAny(raw, ["用户态 TCP 连接失败"])) {
    if (includesAny(text, ["timeout", "deadline exceeded", "i/o timeout"]) || includesAny(raw, ["超时"])) {
      return "出口检测连接超时";
    }
    if (includesAny(text, ["connection refused", "refused"]) || includesAny(raw, ["拒绝"])) {
      return "出口检测连接被拒绝";
    }
    if (includesAny(text, ["unreachable", "no route"]) || includesAny(raw, ["不可达"])) {
      return "出口检测网络不可达";
    }
    return "出口检测连接失败";
  }
  if (includesAny(raw, ["ippure 出口画像 HTTP"])) {
    return "出口画像服务异常";
  }
  if (includesAny(raw, ["解析 ippure 出口画像失败"])) {
    return "出口画像解析失败";
  }
  if (includesAny(raw, ["ippure 返回的出口 IP 无效"])) {
    return "出口画像返回无效 IP";
  }
  if (includesAny(raw, ["启动用户态 OpenVPN 隧道失败"])) {
    if (includesAny(text, ["timeout", "deadline exceeded", "i/o timeout"]) || includesAny(raw, ["超时"])) {
      return "OpenVPN 握手超时";
    }
    if (includesAny(text, ["handshake"]) || includesAny(raw, ["握手"])) {
      return "OpenVPN 握手失败";
    }
    if (includesAny(text, ["connection refused", "refused"]) || includesAny(raw, ["拒绝"])) {
      return "节点拒绝连接";
    }
    if (includesAny(text, ["unreachable", "no route"]) || includesAny(raw, ["不可达"])) {
      return "节点网络不可达";
    }
    return "OpenVPN 连接失败";
  }
  if (includesAny(text, ["context canceled"]) || includesAny(raw, ["取消"])) {
    return "测试已取消";
  }
  if (includesAny(text, ["timeout", "deadline exceeded", "i/o timeout"]) || includesAny(raw, ["超时"])) {
    return "测试超时";
  }
  return "测试失败";
}

function formatExitQualityText(node) {
  const info = node.exit_ip_info;
  if (!info) {
    if (node.probe_status === "testing") {
      return "正在测试节点真实出口";
    }
    if (node.probe_status === "cancelled") {
      return "批量测试已取消";
    }
    if (node.probe_status === "unavailable") {
      return formatProbeFailureText(node.probe_message);
    }
    return "无质量信息";
  }

  const location = [info.country, info.city].filter(Boolean).join(" / ");
  return [
    formatIPTypeLabel(info.ip_type),
    info.ip,
    info.asn,
    info.as_organization || info.organization,
    location,
    Number.isFinite(Number(info.fraud_score)) ? `Fraud ${info.fraud_score}` : "",
  ]
    .filter(Boolean)
    .join(" / ");
}

function NodeList({ nodes, selectedIDs, busyAction, batchTesting, listenerOptions, onToggle, onTest, onConnect }) {
  const defaultListenerKey = listenerOptions[0]?.key || "";
  const [selectedListeners, setSelectedListeners] = useState({});

  useEffect(() => {
    setSelectedListeners((previous) => {
      const nodeIDs = new Set(nodes.map((node) => String(node.id || "")).filter(Boolean));
      const listenerKeys = new Set(listenerOptions.map((listener) => listener.key));
      let changed = false;
      const next = {};
      for (const [nodeID, listenerKey] of Object.entries(previous)) {
        if (!nodeIDs.has(nodeID)) {
          changed = true;
          continue;
        }
        if (listenerKey && !listenerKeys.has(listenerKey)) {
          changed = true;
          continue;
        }
        next[nodeID] = listenerKey;
      }
      return changed ? next : previous;
    });
  }, [listenerOptions, nodes]);

  if (!nodes.length) {
    return <div className="readout">暂无匹配节点。</div>;
  }
  return (
    <div className="list-scroll">
      <div className="node-row node-head" aria-hidden="true">
        <span></span>
        <span>国家</span>
        <span>节点地址</span>
        <span>状态</span>
        <span>真实出口测试</span>
        <span>绑定入口</span>
        <span>操作</span>
      </div>
      {nodes.map((node) => {
        const nodeID = String(node.id || "");
        const hasNodeID = Boolean(nodeID);
        const nodeTesting = node.probe_status === "testing";
        const nodeActionDisabled = batchTesting || nodeTesting || !hasNodeID;
        const selectedListener = selectedListeners[nodeID] || defaultListenerKey;
        const connectDisabled = nodeActionDisabled || !selectedListener;
        return (
          <div className={`node-row ${nodeTesting ? "testing" : ""}`} key={node.id || `${node.remote_host}-${node.remote_port}`}>
            <label className="node-check">
              <input
                type="checkbox"
                checked={hasNodeID && selectedIDs.includes(nodeID)}
                disabled={batchTesting || !hasNodeID}
                onChange={() => onToggle(nodeID)}
                aria-label={`选择节点 ${node.id || node.remote_host || ""}`}
              />
            </label>
            <div className="node-title">
              <CountryFlag code={node.country_short} label={node.country} />
              <strong>{node.country || node.country_short || "-"}</strong>
              {node.active ? <span className="badge ok">已连接</span> : null}
            </div>
            <div className="node-cell mono">{formatEndpoint(node)}</div>
            <div className="node-cell muted">{formatProbeStatus(node)}</div>
            <ExitTestInfo node={node} />
            <select
              className="node-listener-select"
              value={selectedListener}
              disabled={nodeActionDisabled || !listenerOptions.length}
              aria-label={`选择节点 ${node.id || node.remote_host || ""} 绑定的 SOCKS5 入口`}
              onChange={(event) => setSelectedListeners((previous) => ({ ...previous, [nodeID]: event.target.value }))}
            >
              {listenerOptions.length ? null : <option value="">无可用入口</option>}
              {listenerOptions.map((listener) => (
                <option key={listener.key} value={listener.key}>
                  {listener.label}
                </option>
              ))}
            </select>
            <div className="row-actions">
              <ActionButton icon={Zap} label={nodeTesting ? "测试中" : "测试"} compact busy={busyAction === `test-${nodeID}` || nodeTesting} disabled={nodeActionDisabled} onClick={() => onTest(nodeID)} />
              <ActionButton icon={Play} label="连接" compact busy={busyAction === `connect-${nodeID}`} disabled={connectDisabled} onClick={() => onConnect(nodeID, selectedListener)} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function CountryFlag({ code, label }) {
  const normalized = normalizeCountryCode(code);
  const accessibleLabel = label || (normalized ? normalized.toUpperCase() : "flag");
  const [failedCode, setFailedCode] = useState("");

  useEffect(() => {
    setFailedCode("");
  }, [normalized]);

  if (!normalized) {
    return (
      <span className="flag-fallback" title={accessibleLabel}>
        {formatFlagFallbackText(code)}
      </span>
    );
  }

  const localFlagUrl = localFlagUrls[normalized];
  if (!localFlagUrl || failedCode === normalized) {
    return (
      <span className="country-flag country-flag-emoji" role="img" aria-label={accessibleLabel} title={accessibleLabel}>
        {countryCodeToFlagEmoji(normalized)}
      </span>
    );
  }

  return (
    <img
      className="country-flag"
      src={localFlagUrl}
      alt={accessibleLabel}
      loading="lazy"
      onError={() => setFailedCode(normalized)}
    />
  );
}

function ExitTestInfo({ node }) {
  const quality = formatExitQualityText(node);
  return (
    <div className="node-exit-test" title={quality}>
      <span className="node-quality">{quality}</span>
    </div>
  );
}

function Pagination({ page, totalPages, total, pageSize, pageSizes, onPageChange, onPageSizeChange }) {
  return (
    <div className="pagination">
      <div className="muted">共 {total} 条，第 {page} / {totalPages} 页</div>
      <div className="pagination-controls">
        <select value={pageSize} onChange={(event) => onPageSizeChange(Number(event.target.value))}>
          {pageSizes.map((size) => (
            <option key={size} value={size}>
              每页 {size}
            </option>
          ))}
        </select>
        <ActionButton icon={ChevronsLeft} label="上一页" compact disabled={page <= 1} onClick={() => onPageChange(Math.max(1, page - 1))} />
        <ActionButton icon={ChevronsRight} label="下一页" compact disabled={page >= totalPages} onClick={() => onPageChange(Math.min(totalPages, page + 1))} />
      </div>
    </div>
  );
}

function GatewayStatus({ components }) {
  if (!components.length) {
    return <div className="readout">暂无状态。</div>;
  }
  return (
    <div className="component-list">
      {components.map((item) => {
        const ok = item.status === "running";
        return (
          <div className="component" key={item.name}>
            <div>
              <strong>{item.name || "-"}</strong>
              <div className="muted">{item.details || ""}</div>
              {item.error ? <div className="muted">{item.error}</div> : null}
            </div>
            <span className={`badge ${ok ? "ok" : "err"}`}>{item.status || "-"}</span>
          </div>
        );
      })}
    </div>
  );
}

function ListenerEditor({ listeners, onUpdate, onRemove }) {
  if (!listeners.length) {
    return <div className="readout">至少需要启用一个 SOCKS5 监听端口。</div>;
  }
  return (
    <div className="listener-list">
      {listeners.map((listener, index) => {
        const backendPolicyEnabled = listener.backend_policy_enabled === true;
        return (
          <div className="listener" key={`${listener.name}-${index}`}>
            <div className="listener-head">
              <strong>{listener.name || `socks${index + 1}`}</strong>
              <ActionButton icon={Trash2} label="删除" danger compact onClick={() => onRemove(index)} />
            </div>
            <div className="form-grid">
              <TextInput label="名称" value={listener.name} onChange={(value) => onUpdate(index, "name", value)} />
              <SelectInput
                label="启用"
                value={String(listener.enabled !== false)}
                onChange={(value) => onUpdate(index, "enabled", value === "true")}
                options={[
                  ["true", "启用"],
                  ["false", "停用"],
                ]}
              />
              <TextInput label="监听地址" value={listener.host} onChange={(value) => onUpdate(index, "host", value)} />
              <TextInput label="监听端口" type="number" min="1024" max="65535" value={listener.port} onChange={(value) => onUpdate(index, "port", value)} />
              <TextInput label="SOCKS5 用户名" value={listener.username} onChange={(value) => onUpdate(index, "username", value)} autoComplete="off" placeholder="留空则无鉴权" />
              <TextInput label="SOCKS5 密码" type="password" value={listener.password} onChange={(value) => onUpdate(index, "password", value)} autoComplete="new-password" placeholder="公网监听必须填写" />
              <SelectInput
                label="绑定策略"
                value={String(backendPolicyEnabled)}
                onChange={(value) => onUpdate(index, "backend_policy_enabled", value === "true")}
                options={[
                  ["false", "关闭"],
                  ["true", "开启"],
                ]}
              />
              <TextInput label="绑定国家代码" value={listener.country_code} onChange={(value) => onUpdate(index, "country_code", value)} placeholder="JP" disabled={!backendPolicyEnabled} />
              <TextInput label="绑定入口网段" value={(listener.entry_cidrs || []).join("\n")} onChange={(value) => onUpdate(index, "entry_cidrs", parseCIDRInput(value))} placeholder="203.0.113.0/24" disabled={!backendPolicyEnabled} />
              <TextInput label="绑定节点 ID" value={listener.fixed_node_id} onChange={(value) => onUpdate(index, "fixed_node_id", value)} placeholder="可选，优先级最高" disabled={!backendPolicyEnabled} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function LogView({ logs }) {
  if (!logs.length) {
    return <div className="logs">暂无日志。</div>;
  }
  return (
    <div className="logs">
      {logs.map((item, index) => {
        const fields = item.fields
          ? Object.entries(item.fields)
              .map(([key, value]) => ` ${key}=${value}`)
              .join("")
          : "";
        const level = item.level || "INFO";
        return (
          <div className="log-line" key={`${item.time}-${index}`}>
            <span className="log-time">{item.time || ""}</span>{" "}
            <span className={`log-level ${level}`}>{level}</span> {item.message || ""}
            {fields}
          </div>
        );
      })}
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
