import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
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

class AuthError extends Error {}

const pages = [
  { id: "overview", label: "概览", icon: Activity },
  { id: "nodes", label: "节点", icon: Network },
  { id: "socks", label: "SOCKS5", icon: Wifi },
  { id: "settings", label: "设置", icon: Shield },
  { id: "runtime", label: "运行", icon: SquareTerminal },
];

const emptyForm = {
  web_host: "::",
  web_port: 8787,
  secret_path: "",
  admin_username: "admin",
  admin_password: "",
  openvpn_config: "",
  openvpn_auth: "",
  auto_connect: true,
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
    auto_connect: state.auto_connect !== false,
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
  };
}

function normalizeListener(listener, index) {
  return {
    name: listener?.name || `socks${index + 1}`,
    host: listener?.host || "127.0.0.1",
    port: Number(listener?.port || 7928 + index),
    username: listener?.username || "",
    password: listener?.password || "",
    enabled: listener?.enabled !== false,
  };
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
  const [activePage, setActivePage] = useState("overview");

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
      loadState().catch(() => {});
      loadLogs().catch(() => {});
      loadGatewayStatus().catch(() => {});
    }, 5000);
    return () => window.clearInterval(timer);
  }, [loadGatewayStatus, loadLogs, loadState]);

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

  const connectNode = (nodeID) =>
    runAction(
      `connect-${nodeID}`,
      "正在连接节点...",
      () => api("connect", { method: "POST", body: JSON.stringify({ node_id: nodeID }) }),
      (result) => result.message || "已启动",
    );

  const testNode = (nodeID) =>
    runAction(
      `test-${nodeID}`,
      "正在测试节点...",
      () => api("test_node", { method: "POST", body: JSON.stringify({ node_id: nodeID }) }),
      (result) => `节点测试完成: ${result.node?.probe_status || "unknown"}`,
    );

  const testNodes = (nodeIDs) =>
    runAction(
      "test-nodes",
      "正在批量测试节点真实出口...",
      () => api("test_nodes", { method: "POST", body: JSON.stringify({ node_ids: nodeIDs }) }),
      (result) => `批量测试完成: ${(result.nodes || []).length} 个节点返回结果`,
    );

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
          <p className="eyebrow">AimiliVPN</p>
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
          <p className="eyebrow">AimiliVPN</p>
          <h1>AimiliVPN 管理端</h1>
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
          actionMsg={actionMsg}
          onRefreshNodes={refreshNodes}
          onTest={testNode}
          onTestBatch={testNodes}
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

function NodesPage({ current, busyAction, actionMsg, onRefreshNodes, onTest, onTestBatch, onConnect }) {
  const nodes = current?.nodes || [];
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
        node.id,
        node.country,
        node.country_short,
        node.ip,
        node.hostname,
        node.remote_host,
        node.proto,
        node.probe_status,
        node.exit_ip_info?.ip,
        node.exit_ip_info?.asn,
        node.exit_ip_info?.as_organization,
        node.exit_ip_info?.organization,
        node.exit_ip_info?.country,
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

  const updateFilter = (field, value) => {
    setFilters((previous) => ({ ...previous, [field]: value }));
  };

  const toggleNode = (nodeID) => {
    setSelectedIDs((previous) =>
      previous.includes(nodeID) ? previous.filter((id) => id !== nodeID) : [...previous, nodeID],
    );
  };

  const togglePage = () => {
    if (selectedOnPage.length === pageNodeIDs.length) {
      setSelectedIDs((previous) => previous.filter((id) => !pageNodeIDs.includes(id)));
      return;
    }
    setSelectedIDs((previous) => [...new Set([...previous, ...pageNodeIDs])]);
  };

  const runBatchTest = () => {
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
            placeholder="搜索 IP、ASN、企业、国家或节点 ID"
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
          <ActionButton icon={CheckSquare} label={selectedOnPage.length === pageNodeIDs.length && pageNodeIDs.length ? "取消本页" : "选择本页"} compact disabled={!pageNodeIDs.length} onClick={togglePage} />
          <ActionButton icon={Zap} label={selectedIDs.length ? `批量真测 ${selectedIDs.length}` : `真测本页 ${pageNodeIDs.length}`} compact busy={busyAction === "test-nodes"} disabled={!selectedIDs.length && !pageNodeIDs.length} onClick={runBatchTest} />
        </div>
        <ActionButton icon={ListRestart} label="刷新 VPNGate 节点" busy={busyAction === "refresh-nodes"} onClick={onRefreshNodes} />
      </div>
      <NodeList
        nodes={pageNodes}
        selectedIDs={selectedIDs}
        busyAction={busyAction}
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
        <TextInput label="OpenVPN auth-user-pass 文件" value={form.openvpn_auth} onChange={(value) => onUpdateForm("openvpn_auth", value)} placeholder="/opt/aimilivpn/vpngate_auth.txt" />
        <SelectInput
          label="自动连接 VPNGate 节点"
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
        <TextInput label="OpenVPN 配置文件" value={form.openvpn_config} onChange={(value) => onUpdateForm("openvpn_config", value)} placeholder="/opt/aimilivpn/client.ovpn" />
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

function NodeList({ nodes, selectedIDs, busyAction, onToggle, onTest, onConnect }) {
  if (!nodes.length) {
    return <div className="readout">暂无匹配节点。</div>;
  }
  return (
    <div className="list-scroll">
      {nodes.map((node) => (
        <div className="node-row" key={node.id || `${node.remote_host}-${node.remote_port}`}>
          <label className="node-check">
            <input
              type="checkbox"
              checked={selectedIDs.includes(node.id)}
              onChange={() => onToggle(node.id)}
              aria-label={`选择节点 ${node.id || node.remote_host || ""}`}
            />
          </label>
          <div className="node-main">
            <div className="node-title">
              <CountryFlag code={node.country_short} label={node.country} />
              <strong>{node.country || node.country_short || "-"}</strong>
              <span>{node.remote_host || node.ip || ""}:{node.remote_port || ""}</span>
              {node.active ? <span className="badge ok">已连接</span> : null}
              <IPTypeBadge type={node.exit_ip_info?.ip_type} />
            </div>
            <div className="node-meta muted">
              ID {node.id || "-"} · Ping {node.ping || "-"} ms · Score {node.score || "-"} · {node.proto || "-"} · 探测 {node.probe_status || "not_checked"}
              {node.probe_latency_ms ? ` ${node.probe_latency_ms} ms` : ""}
            </div>
            <ExitInfo info={node.exit_ip_info} />
          </div>
          <div className="row-actions">
            <ActionButton icon={Zap} label="测试" compact busy={busyAction === `test-${node.id}`} onClick={() => onTest(node.id)} />
            <ActionButton icon={Play} label="连接" compact busy={busyAction === `connect-${node.id}`} onClick={() => onConnect(node.id)} />
          </div>
        </div>
      ))}
    </div>
  );
}

function CountryFlag({ code, label }) {
  const normalized = String(code || "").trim().toLowerCase();
  if (!/^[a-z]{2}$/.test(normalized)) {
    return <span className="flag-fallback">{String(code || "--").slice(0, 2).toUpperCase()}</span>;
  }
  return (
    <img
      className="country-flag"
      src={`https://flagcdn.com/${normalized}.svg`}
      alt={label || code || "flag"}
      loading="lazy"
      referrerPolicy="no-referrer"
    />
  );
}

function IPTypeBadge({ type }) {
  const normalized = type || "unknown";
  const label = ipTypeOptions.find(([value]) => value === normalized)?.[1] || "未知";
  return <span className={`badge ip-type ${normalized}`}>{label}</span>;
}

function ExitInfo({ info }) {
  if (!info) {
    return <div className="node-exit muted">真实出口未测试</div>;
  }
  const location = [info.country, info.city].filter(Boolean).join(" / ");
  return (
    <div className="node-exit">
      <span>出口 {info.ip || "-"}</span>
      <span>{info.asn || "-"}</span>
      <span>{info.as_organization || info.organization || "-"}</span>
      {location ? <span>{location}</span> : null}
      {Number.isFinite(Number(info.fraud_score)) ? <span>Fraud {info.fraud_score}</span> : null}
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
      {listeners.map((listener, index) => (
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
          </div>
        </div>
      ))}
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
