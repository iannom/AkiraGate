import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ArrowUpDown,
  CircleX,
  CheckSquare,
  ClipboardList,
  LogOut,
  CirclePlus,
  ChevronsLeft,
  ChevronsRight,
  Copy,
  CopyCheck,
  Dices,
  Eye,
  EyeOff,
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
const nodeSortColumns = Object.freeze([
  { key: "country", label: "国家" },
  { key: "endpoint", label: "节点地址" },
  { key: "probe", label: "状态" },
  { key: "exit", label: "真实出口测试" },
  { key: "network", label: "ASN / 运营商" },
]);
const nodeSortColumnKeys = new Set(nodeSortColumns.map((column) => column.key));
const defaultNodeSort = Object.freeze({ key: "", direction: "asc" });
const nodeSortDirectionLabels = Object.freeze({ asc: "升序", desc: "降序" });
const nodeSortCollator = new Intl.Collator("zh-CN", { numeric: true, sensitivity: "base" });
const nodeProbeStatusRank = Object.freeze({
  available: 0,
  testing: 1,
  not_checked: 2,
  cancelled: 3,
  unavailable: 4,
});
const socksCredentialUsernameAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const socksCredentialPasswordAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
const socksCredentialUsernameLength = 12;
const socksCredentialPasswordLength = 24;

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

function getCryptoRandomValues(buffer) {
  const cryptoSource = globalThis.crypto;
  if (!cryptoSource || typeof cryptoSource.getRandomValues !== "function") {
    throw new Error("当前浏览器不支持安全随机数生成。");
  }
  cryptoSource.getRandomValues(buffer);
  return buffer;
}

function randomString(length, alphabet) {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error("随机字符串长度必须是正整数。");
  }
  if (typeof alphabet !== "string" || alphabet.length < 2 || alphabet.length > 256) {
    throw new Error("随机字符串字符集无效。");
  }

  const output = [];
  const maxAcceptedByte = Math.floor(256 / alphabet.length) * alphabet.length;
  while (output.length < length) {
    const bytes = getCryptoRandomValues(new Uint8Array(length - output.length));
    for (const byte of bytes) {
      if (byte >= maxAcceptedByte) {
        continue;
      }
      output.push(alphabet[byte % alphabet.length]);
      if (output.length === length) {
        break;
      }
    }
  }
  return output.join("");
}

function generateSocksCredentials() {
  return {
    username: `u_${randomString(socksCredentialUsernameLength, socksCredentialUsernameAlphabet)}`,
    password: randomString(socksCredentialPasswordLength, socksCredentialPasswordAlphabet),
  };
}

async function copyTextToClipboard(text) {
  const value = String(text ?? "");
  if (!value) {
    throw new Error("没有可复制的内容。");
  }
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  if (typeof document === "undefined" || typeof document.execCommand !== "function") {
    throw new Error("当前浏览器不支持复制到剪贴板。");
  }
  if (!document.body) {
    throw new Error("当前页面暂时无法复制到剪贴板。");
  }

  const textArea = document.createElement("textarea");
  textArea.value = value;
  textArea.setAttribute("readonly", "");
  textArea.style.position = "fixed";
  textArea.style.left = "-9999px";
  textArea.style.top = "0";
  document.body.appendChild(textArea);
  try {
    textArea.select();
    const copied = document.execCommand("copy");
    if (!copied) {
      throw new Error("复制到剪贴板失败。");
    }
  } finally {
    document.body.removeChild(textArea);
  }
}

function normalizeNodeSortKey(key) {
  const normalized = String(key || "");
  return nodeSortColumnKeys.has(normalized) ? normalized : "";
}

function normalizeNodeSortDirection(direction) {
  return direction === "desc" ? "desc" : "asc";
}

function compareTextValue(left, right) {
  return nodeSortCollator.compare(String(left ?? "").trim(), String(right ?? "").trim());
}

function compareNumberValue(left, right) {
  const leftNumber = Number(left);
  const rightNumber = Number(right);
  const leftValid = Number.isFinite(leftNumber);
  const rightValid = Number.isFinite(rightNumber);
  if (leftValid && rightValid) {
    return leftNumber - rightNumber;
  }
  if (leftValid) {
    return -1;
  }
  if (rightValid) {
    return 1;
  }
  return 0;
}

function nodeCountrySortText(node) {
  return node?.country || node?.country_short || "";
}

function nodeProbeSortRank(node) {
  const status = String(node?.probe_status || "not_checked").trim() || "not_checked";
  if (status !== "not_checked" && status !== "testing" && status !== "cancelled" && status !== "unavailable") {
    return nodeProbeStatusRank.available;
  }
  return nodeProbeStatusRank[status] ?? Number.MAX_SAFE_INTEGER;
}

function compareNodeProbeStatus(left, right) {
  const rankCompare = compareNumberValue(nodeProbeSortRank(left), nodeProbeSortRank(right));
  if (rankCompare) {
    return rankCompare;
  }
  const latencyCompare = compareNumberValue(left?.probe_latency_ms, right?.probe_latency_ms);
  if (latencyCompare) {
    return latencyCompare;
  }
  return compareTextValue(formatProbeStatus(left || {}), formatProbeStatus(right || {}));
}

function compareNodeExitQuality(left, right) {
  const fraudCompare = compareNumberValue(left?.exit_ip_info?.fraud_score, right?.exit_ip_info?.fraud_score);
  if (fraudCompare) {
    return fraudCompare;
  }
  const typeCompare = compareTextValue(
    formatIPTypeLabel(left?.exit_ip_info?.ip_type),
    formatIPTypeLabel(right?.exit_ip_info?.ip_type),
  );
  if (typeCompare) {
    return typeCompare;
  }
  return compareTextValue(formatExitQualityText(left || {}), formatExitQualityText(right || {}));
}

function compareNodeNetwork(left, right) {
  return compareTextValue(formatIPNetworkText(left?.exit_ip_info), formatIPNetworkText(right?.exit_ip_info));
}

function compareNodeBySortKey(left, right, key) {
  switch (key) {
    case "endpoint":
      return (
        compareTextValue(left?.remote_host || left?.ip, right?.remote_host || right?.ip) ||
        compareNumberValue(left?.remote_port, right?.remote_port)
      );
    case "probe":
      return compareNodeProbeStatus(left, right);
    case "exit":
      return compareNodeExitQuality(left, right);
    case "network":
      return compareNodeNetwork(left, right);
    case "country":
    default:
      return compareTextValue(nodeCountrySortText(left), nodeCountrySortText(right));
  }
}

function compareNodeFallback(left, right) {
  return (
    compareTextValue(nodeCountrySortText(left), nodeCountrySortText(right)) ||
    compareTextValue(formatEndpoint(left || {}), formatEndpoint(right || {})) ||
    compareTextValue(left?.id, right?.id)
  );
}

function sortNodes(nodes, sort) {
  if (!Array.isArray(nodes) || nodes.length === 0) {
    return [];
  }
  const key = normalizeNodeSortKey(sort?.key);
  if (!key) {
    return nodes;
  }
  const direction = normalizeNodeSortDirection(sort?.direction);
  const multiplier = direction === "desc" ? -1 : 1;
  return nodes
    .map((node, index) => ({ node, index }))
    .sort((left, right) => {
      const primaryCompare = compareNodeBySortKey(left.node, right.node, key);
      if (primaryCompare) {
        return primaryCompare * multiplier;
      }
      const fallbackCompare = compareNodeFallback(left.node, right.node);
      return fallbackCompare ? fallbackCompare * multiplier : left.index - right.index;
    })
    .map((item) => item.node);
}

function isNodeTestAction(actionName) {
  const name = String(actionName || "");
  return name === "test-nodes" || (name.startsWith("test-") && name !== "test-proxy");
}

function hasNodeProbeResult(node) {
  const status = String(node?.probe_status || "").trim();
  return status !== "" && status !== "not_checked";
}

function mergeStateWithPreviousNodeResults(nextState, previousState) {
  if (!nextState || !Array.isArray(nextState.nodes) || !Array.isArray(previousState?.nodes)) {
    return nextState;
  }

  const previousNodes = new Map();
  for (const node of previousState.nodes) {
    if (node?.id && hasNodeProbeResult(node)) {
      previousNodes.set(node.id, node);
    }
  }
  if (!previousNodes.size) {
    return nextState;
  }

  let changed = false;
  const nodes = nextState.nodes.map((node) => {
    if (!node?.id || hasNodeProbeResult(node)) {
      return node;
    }
    const previous = previousNodes.get(node.id);
    if (!previous) {
      return node;
    }
    changed = true;
    return {
      ...node,
      probe_status: previous.probe_status,
      probe_message: previous.probe_message,
      probe_latency_ms: previous.probe_latency_ms,
      exit_ip_info: previous.exit_ip_info,
    };
  });

  return changed ? { ...nextState, nodes } : nextState;
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
  const { allowErrorData = false, ...fetchOptions } = options;
  const response = await fetch(`./api/${path}`, {
    ...fetchOptions,
    credentials: "same-origin",
    headers: {
      ...(fetchOptions.body ? { "Content-Type": "application/json" } : {}),
      ...(fetchOptions.headers || {}),
    },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) {
    if (allowErrorData && response.status !== 401) {
      return { ...data, http_status: response.status };
    }
    const error =
      response.status === 401
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

function normalizeText(value) {
  return String(value ?? "").trim();
}

function normalizeTextList(values) {
  if (!Array.isArray(values)) {
    return [];
  }
  return values.map((item) => normalizeText(item)).filter(Boolean);
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

function listenerBackendPolicyEnabled(listener) {
  if (!listener) {
    return false;
  }
  if (listener.backend_policy_enabled === true) {
    return true;
  }
  if (listener.backend_policy_enabled === false) {
    return false;
  }
  return Boolean(
    normalizeText(listener.country_code) ||
      normalizeText(listener.fixed_node_id) ||
      normalizeTextList(listener.entry_cidrs).length,
  );
}

function formatOverviewStatus(current) {
  if (!current) {
    return "加载中";
  }
  const status = normalizeText(current.status);
  return status ? formatBackendStatus(status) : statusText(current);
}

function formatListenerOverviewSummary(current) {
  if (!current) {
    return "加载中";
  }

  const listeners = Array.isArray(current.socks5_listeners) ? current.socks5_listeners : [];
  const backends = Array.isArray(current.listener_backends) ? current.listener_backends : [];
  if (!listeners.length) {
    return "未配置 SOCKS5 入口";
  }

  const enabledCount = listeners.filter((listener) => listener?.enabled !== false).length;
  const runningCount = backends.filter((backend) => backend?.status === "running").length;
  const errorCount = backends.filter((backend) => backend?.status === "error" || backend?.error).length;
  const parts = [`共 ${listeners.length} 个入口`, `${enabledCount} 个启用`, `${runningCount} 个运行`];
  if (errorCount) {
    parts.push(`${errorCount} 个异常`);
  }
  return parts.join(" / ");
}

function findBackendForListener(listener, index, backendIndexes) {
  const listenAddress = formatListenAddress(listener);
  const listenerName = normalizeText(listener?.name || `socks${index + 1}`);
  return (
    (listenAddress ? backendIndexes.byListenAddress.get(listenAddress) : null) ||
    (listenerName ? backendIndexes.byListenerName.get(listenerName) : null) ||
    null
  );
}

function formatListenerPolicy(listener, backend, entryCIDRs) {
  const safeEntryCIDRs = Array.isArray(entryCIDRs) ? entryCIDRs : [];
  const countryCode = normalizeText(backend?.country_code || listener?.country_code).toUpperCase();
  const fixedNodeID = normalizeText(listener?.fixed_node_id);
  const hasPolicy = listenerBackendPolicyEnabled(listener) || countryCode || fixedNodeID || safeEntryCIDRs.length;
  if (!hasPolicy) {
    return "自动选择";
  }

  const parts = [];
  if (countryCode) {
    parts.push(`国家 ${countryCode}`);
  }
  if (fixedNodeID) {
    parts.push(`固定节点 ${fixedNodeID}`);
  }
  if (safeEntryCIDRs.length) {
    parts.push(`入口网段 ${safeEntryCIDRs.join(", ")}`);
  }
  return parts.length ? parts.join(" / ") : "已开启";
}

function formatListenerOverviewMessage(backend, status, connected) {
  const error = normalizeText(backend?.error);
  if (error) {
    return error;
  }

  const message = normalizeText(backend?.message);
  if (message) {
    return message;
  }

  switch (status) {
    case "disabled":
      return "入口已停用";
    case "running":
      return "入口后端运行正常";
    case "switching":
      return "入口后端正在切换";
    case "starting":
      return "入口后端正在启动";
    case "stopped":
      return connected ? "入口后端已停止" : "网关未连接";
    default:
      return connected ? "等待后端上报状态" : "网关未连接";
  }
}

function buildListenerOverviewItem(listener, backend, index, connected) {
  const listenerName = normalizeText(listener?.name || backend?.listener_name) || `socks${index + 1}`;
  const listenAddress = normalizeText(backend?.listen_address) || formatListenAddress(listener);
  const backendEntryCIDRs = normalizeTextList(backend?.entry_cidrs);
  const listenerEntryCIDRs = normalizeTextList(listener?.entry_cidrs);
  const entryCIDRs = backendEntryCIDRs.length ? backendEntryCIDRs : listenerEntryCIDRs;
  const enabled = listener ? listener.enabled !== false : true;
  const status = enabled ? normalizeText(backend?.status) || (connected ? "starting" : "stopped") : "disabled";

  return {
    key: `${listenAddress || listenerName}-${index}`,
    title: listenerName,
    listenAddress: listenAddress || "-",
    proxyURL: normalizeText(backend?.proxy_url),
    status,
    message: formatListenerOverviewMessage(backend, status, connected),
    hasError: Boolean(normalizeText(backend?.error)),
    policy: formatListenerPolicy(listener, backend, entryCIDRs),
    nodeID: normalizeText(backend?.node_id),
    entryIP: normalizeText(backend?.entry_ip),
    exitIP: normalizeText(backend?.exit_ip),
  };
}

function listenerOverviewItems(current) {
  const listeners = Array.isArray(current?.socks5_listeners) ? current.socks5_listeners : [];
  const backends = Array.isArray(current?.listener_backends) ? current.listener_backends : [];
  const connected = Boolean(current?.connected);
  const backendIndexes = {
    byListenAddress: new Map(),
    byListenerName: new Map(),
  };

  for (const backend of backends) {
    const listenAddress = normalizeText(backend?.listen_address);
    const listenerName = normalizeText(backend?.listener_name);
    if (listenAddress && !backendIndexes.byListenAddress.has(listenAddress)) {
      backendIndexes.byListenAddress.set(listenAddress, backend);
    }
    if (listenerName && !backendIndexes.byListenerName.has(listenerName)) {
      backendIndexes.byListenerName.set(listenerName, backend);
    }
  }

  if (listeners.length) {
    return listeners.map((listener, index) =>
      buildListenerOverviewItem(listener, findBackendForListener(listener, index, backendIndexes), index, connected),
    );
  }

  return backends.map((backend, index) => buildListenerOverviewItem(null, backend, index, connected));
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
  const [auditLogs, setAuditLogs] = useState([]);
  const [gatewayComponents, setGatewayComponents] = useState([]);
  const [proxyTestResult, setProxyTestResult] = useState(null);
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
      setProxyTestResult(null);
      setLoginMessage(error.message);
      return true;
    }
    return false;
  }, []);

  const loadState = useCallback(async (forceSync = false) => {
    try {
      const state = await api("state");
      setCurrent((previous) => mergeStateWithPreviousNodeResults(state, previous));
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

  const loadAuditLogs = useCallback(async () => {
    try {
      const data = await api("audit_logs");
      setAuditLogs(data.audit_logs || []);
    } catch (error) {
      if (!handleAuthError(error)) {
        throw error;
      }
    }
  }, [handleAuthError]);

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
      .then(loadAuditLogs)
      .then(loadGatewayStatus)
      .catch((error) => {
        if (!handleAuthError(error)) {
          setActionMsg(error.message);
        }
      });
  }, [auth.authenticated, handleAuthError, loadAuditLogs, loadGatewayStatus, loadLogs, loadState]);

  useEffect(() => {
    if (!auth.authenticated) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      loadState().catch(handleBackgroundRefreshError);
      loadLogs().catch(handleBackgroundRefreshError);
      loadAuditLogs().catch(handleBackgroundRefreshError);
      loadGatewayStatus().catch(handleBackgroundRefreshError);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [auth.authenticated, handleBackgroundRefreshError, loadAuditLogs, loadGatewayStatus, loadLogs, loadState]);

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
      setAuditLogs([]);
      setGatewayComponents([]);
      setProxyTestResult(null);
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
      () => {
        setProxyTestResult(null);
        return api("connect", { method: "POST" });
      },
      (result) => result.message || "已启动",
    );

  const connectNode = (nodeID, listenAddress) =>
    runAction(
      `connect-${nodeID}`,
      "正在连接节点...",
      () => {
        setProxyTestResult(null);
        return api("connect", { method: "POST", body: JSON.stringify({ node_id: nodeID, listen_address: listenAddress }) });
      },
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

  const cancelTestNode = (nodeID) =>
    runAction(
      `cancel-test-${nodeID}`,
      "正在取消节点测试...",
      async () => {
        const result = await api("cancel_test_node", { method: "POST", body: JSON.stringify({ node_id: nodeID }) });
        if (result.node) {
          mergeNodeResultsIntoCurrent(result.node);
        }
        return result;
      },
      (result) => result.message || "已请求取消节点测试",
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
      () => {
        setProxyTestResult(null);
        return api("disconnect", { method: "POST" });
      },
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
      async () => {
        const result = await api("test_proxy", { method: "POST", allowErrorData: true });
        setProxyTestResult(result);
        return result;
      },
      (result) => formatProxyTestMessage(result),
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
          proxyTestResult={proxyTestResult}
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
          onCancelTest={cancelTestNode}
          onTestBatch={testNodes}
          onCancelBatchTest={cancelTestNodes}
          onConnect={connectNode}
          onDisconnect={disconnect}
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
          auditLogs={auditLogs}
          onRefreshGateway={() => loadGatewayStatus().catch((error) => setActionMsg(error.message))}
          onRefreshLogs={() => loadLogs().catch((error) => setActionMsg(error.message))}
          onRefreshAuditLogs={() => loadAuditLogs().catch((error) => setActionMsg(error.message))}
        />
      ) : null}
    </main>
  );
}

function OverviewPage({ current, runtimeWeb, restartHint, actionMsg, busyAction, proxyTestResult, onConnect, onDisconnect, onTestProxy, onRefresh }) {
  const localProxyURLs = Array.isArray(current?.local_proxy_urls) ? current.local_proxy_urls : [];
  return (
    <section className="panel">
      <SectionTitle icon={Activity} title="连接概览" />
      <div className="field-grid">
        <Readout label="连接状态" value={formatOverviewStatus(current)} />
        <Readout label="入口概况" value={formatListenerOverviewSummary(current)} />
        <Readout
          label="本地代理地址"
          value={localProxyURLs.length ? localProxyURLs : ["-"]}
          mono
        />
        <Readout label="当前 Web 监听" value={runtimeWeb} mono />
        <Readout label="配置生效状态" value={restartHint} />
        <Readout label="状态说明" value={current?.message || "-"} />
      </div>
      <ListenerBackendOverview current={current} />
      <ProxyTestDetails result={proxyTestResult} />
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

function ListenerBackendOverview({ current }) {
  const entries = listenerOverviewItems(current);
  if (!entries.length) {
    return (
      <div className="overview-section">
        <label>SOCKS5 入口连接</label>
        <div className="readout">{current ? "暂无 SOCKS5 入口配置。" : "正在加载入口状态。"}</div>
      </div>
    );
  }
  return (
    <div className="overview-section">
      <div className="overview-title-line">
        <label>SOCKS5 入口连接</label>
        <span className="muted">{entries.length} 个入口</span>
      </div>
      <div className="backend-grid">
        {entries.map((entry) => (
          <div className={`backend-card ${entry.hasError ? "is-error" : entry.status === "disabled" ? "is-disabled" : ""}`} key={entry.key}>
            <div className="backend-head">
              <strong>{entry.title}</strong>
              <span className={`badge ${backendStatusBadgeClass(entry.status)}`}>{formatBackendStatus(entry.status)}</span>
            </div>
            <div className="backend-detail-grid">
              <BackendDetailItem label="监听地址" value={entry.listenAddress} mono />
              <BackendDetailItem label="代理地址" value={entry.proxyURL || "-"} mono />
              <BackendDetailItem label="绑定策略" value={entry.policy} />
              <BackendDetailItem label="当前节点" value={entry.nodeID || "-"} mono />
              <BackendDetailItem label="入口 IP" value={entry.entryIP || "-"} mono />
              <BackendDetailItem label="出口 IP" value={entry.exitIP || "-"} mono />
              <BackendDetailItem label={entry.hasError ? "错误" : "说明"} value={entry.message} danger={entry.hasError} wide />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function BackendDetailItem({ label, value, mono = false, danger = false, wide = false }) {
  return (
    <div className={`backend-detail ${wide ? "wide" : ""}`}>
      <span className="backend-detail-label">{label}</span>
      <span className={`backend-detail-value ${mono ? "mono" : ""} ${danger ? "danger" : ""}`}>{value || "-"}</span>
    </div>
  );
}

function ProxyTestDetails({ result }) {
  if (!result) {
    return null;
  }
  const results = proxyResultsFromResponse(result);
  return (
    <div className="overview-section">
      <div className="overview-title-line">
        <label>出口检测结果</label>
        <span className={`badge ${result.ok ? "ok" : "err"}`}>{result.ok ? "通过" : "失败"}</span>
      </div>
      <div className="backend-grid">
        {results.map((item, index) => (
          <div className="backend-card" key={`${item.listen || item.proxy_url || item.ip || "proxy"}-${index}`}>
            <div className="backend-head">
              <strong>{formatProxyResultTitle(item, index)}</strong>
              <span className={`badge ${item.ok ? "ok" : "err"}`}>{item.ok ? "通过" : "失败"}</span>
            </div>
            <div className="detail-lines">
              {item.listen ? <span>监听 {item.listen}</span> : null}
              {item.proxy_url ? <span className="mono">代理 {item.proxy_url}</span> : null}
              {item.ip ? <span>出口 IP {item.ip}</span> : null}
              {Number.isFinite(Number(item.latency_ms)) && Number(item.latency_ms) > 0 ? <span>延迟 {item.latency_ms} ms</span> : null}
              {item.info ? <span>{formatIPInfoSummary(item.info)}</span> : null}
              {item.error ? <span className="error-text">{item.error}</span> : null}
            </div>
          </div>
        ))}
      </div>
      {!results.length && result.error ? <div className="readout">{result.error}</div> : null}
    </div>
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
  onCancelTest,
  onTestBatch,
  onCancelBatchTest,
  onConnect,
  onDisconnect,
}) {
  const nodes = current?.nodes || [];
  const listeners = current?.socks5_listeners || [];
  const listenerBackends = current?.listener_backends || [];
  const batchTesting = Boolean(batchTestActive);
  const cancellingBatchTest = Boolean(batchCancelPending);
  const batchActionActive = batchTesting || cancellingBatchTest;
  const [filters, setFilters] = useState({ keyword: "", country: "", ipType: "" });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [selectedIDs, setSelectedIDs] = useState([]);
  const [nodeSort, setNodeSort] = useState(defaultNodeSort);

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
        formatIPNetworkText(node.exit_ip_info),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(keyword);
    });
  }, [filters, nodes]);

  const sortedNodes = useMemo(() => sortNodes(filteredNodes, nodeSort), [filteredNodes, nodeSort]);
  const totalPages = Math.max(1, Math.ceil(sortedNodes.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pageNodes = sortedNodes.slice((safePage - 1) * pageSize, safePage * pageSize);
  const pageNodeIDs = pageNodes.map((node) => node.id).filter(Boolean);
  const selectedOnPage = pageNodeIDs.filter((id) => selectedIDs.includes(id));

  useEffect(() => {
    setPage(1);
  }, [filters.keyword, filters.country, filters.ipType, nodeSort.direction, nodeSort.key, pageSize]);

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
  const listenerBackendsByListen = useMemo(() => {
    const values = new Map();
    for (const backend of listenerBackends) {
      const listen = String(backend.listen_address || "").trim();
      if (listen) {
        values.set(listen, backend);
      }
    }
    return values;
  }, [listenerBackends]);

  const updateFilter = (field, value) => {
    setFilters((previous) => ({ ...previous, [field]: value }));
  };

  const updateNodeSort = (key) => {
    const nextKey = normalizeNodeSortKey(key);
    setNodeSort((previous) => {
      const previousKey = normalizeNodeSortKey(previous?.key);
      const previousDirection = normalizeNodeSortDirection(previous?.direction);
      return {
        key: nextKey,
        direction: previousKey === nextKey && previousDirection === "asc" ? "desc" : "asc",
      };
    });
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
        sort={nodeSort}
        selectedIDs={selectedIDs}
        busyAction={busyAction}
        batchTesting={batchActionActive}
        listenerOptions={listenerOptions}
        currentConnected={Boolean(current?.connected)}
        listenerBackendsByListen={listenerBackendsByListen}
        onToggle={toggleNode}
        onTest={onTest}
        onCancelTest={onCancelTest}
        onConnect={onConnect}
        onDisconnect={onDisconnect}
        onSort={updateNodeSort}
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

function RuntimePage({ gatewayComponents, logs, auditLogs, onRefreshGateway, onRefreshLogs, onRefreshAuditLogs }) {
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
      <section className="panel">
        <PanelHead
          icon={ClipboardList}
          title="审计日志"
          action={<ActionButton icon={RefreshCw} label="刷新审计" compact onClick={onRefreshAuditLogs} />}
        />
        <AuditLogView logs={auditLogs} />
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

function PasswordInput({ label, value, onChange, disabled = false, ...props }) {
  const [visible, setVisible] = useState(false);
  const [copied, setCopied] = useState(false);
  const password = String(value ?? "");
  const VisibilityIcon = visible ? EyeOff : Eye;
  const CopyIcon = copied ? CopyCheck : Copy;

  useEffect(() => {
    setCopied(false);
  }, [password]);

  useEffect(() => {
    if (!copied || typeof window === "undefined") {
      return undefined;
    }
    const timer = window.setTimeout(() => setCopied(false), 1400);
    return () => window.clearTimeout(timer);
  }, [copied]);

  const copyPassword = async () => {
    try {
      await copyTextToClipboard(password);
      setCopied(true);
    } catch (error) {
      const message = error?.message || "复制 SOCKS5 密码失败。";
      console.error(message, error);
      if (typeof window !== "undefined" && typeof window.alert === "function") {
        window.alert(message);
      }
    }
  };

  return (
    <div>
      <label>{label}</label>
      <div className="input-action-row">
        <input
          type={visible ? "text" : "password"}
          value={password}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
          {...props}
        />
        <button
          type="button"
          className="input-icon-button"
          aria-label={visible ? "隐藏 SOCKS5 密码" : "显示 SOCKS5 密码"}
          aria-pressed={visible}
          disabled={disabled}
          title={visible ? "隐藏密码" : "显示密码"}
          onClick={() => setVisible((previous) => !previous)}
        >
          <VisibilityIcon size={16} aria-hidden="true" />
        </button>
        <button
          type="button"
          className="input-icon-button"
          aria-label={copied ? "已复制 SOCKS5 密码" : "复制 SOCKS5 密码"}
          disabled={disabled || !password}
          title={copied ? "已复制" : "复制密码"}
          onClick={copyPassword}
        >
          <CopyIcon size={16} aria-hidden="true" />
        </button>
      </div>
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

function backendStatusBadgeClass(status) {
  switch (status) {
    case "running":
      return "ok";
    case "error":
      return "err";
    case "switching":
    case "starting":
      return "warn";
    default:
      return "";
  }
}

function formatBackendStatus(status) {
  switch (status) {
    case "running":
      return "运行中";
    case "switching":
      return "切换中";
    case "starting":
      return "启动中";
    case "error":
      return "异常";
    case "stopped":
      return "已停止";
    case "disabled":
      return "已停用";
    default:
      return status || "-";
  }
}

function proxyResultsFromResponse(result) {
  if (!result) {
    return [];
  }
  if (Array.isArray(result.results) && result.results.length) {
    return result.results;
  }
  if (result.ip || result.error || result.proxy_url || result.info) {
    return [result];
  }
  return [];
}

function formatProxyResultTitle(item, index) {
  return item.listener || item.listen || item.proxy_url || `入口 ${index + 1}`;
}

function formatIPInfoSummary(info) {
  if (!info) {
    return "";
  }
  const location = [info.country, info.region, info.city].filter(Boolean).join(" / ");
  return [
    formatIPTypeLabel(info.ip_type),
    info.asn,
    info.as_organization || info.organization || info.isp,
    location,
    Number.isFinite(Number(info.fraud_score)) ? `Fraud ${info.fraud_score}` : "",
  ]
    .filter(Boolean)
    .join(" / ");
}

function formatProxyTestMessage(result) {
  const results = proxyResultsFromResponse(result);
  if (!results.length) {
    return result?.error || "出口检测完成";
  }
  const passed = results.filter((item) => item.ok).length;
  const total = results.length;
  const ips = [...new Set(results.map((item) => item.ip).filter(Boolean))];
  const suffix = ips.length ? `，出口 ${ips.join(", ")}` : result?.error ? `，${result.error}` : "";
  return `出口检测${result?.ok ? "通过" : "失败"}: ${passed}/${total} 个入口通过${suffix}`;
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
    location,
    Number.isFinite(Number(info.fraud_score)) ? `Fraud ${info.fraud_score}` : "",
  ]
    .filter(Boolean)
    .join(" / ");
}

function formatIPASN(info) {
  const asn = String(info?.asn || "").trim();
  if (asn) {
    return asn;
  }
  const asnNumber = Number(info?.asn_number);
  if (!Number.isInteger(asnNumber) || asnNumber <= 0) {
    return "";
  }
  return `AS${asnNumber}`;
}

function formatIPNetworkText(info) {
  if (!info) {
    return "";
  }
  const provider = String(info.as_organization || info.organization || info.isp || "").trim();
  return [formatIPASN(info), provider].filter(Boolean).join(" / ");
}

function NodeList({
  nodes,
  selectedIDs,
  busyAction,
  batchTesting,
  listenerOptions,
  currentConnected,
  listenerBackendsByListen,
  onToggle,
  onTest,
  onCancelTest,
  onConnect,
  onDisconnect,
  onSort,
  sort,
}) {
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
      <div className="node-row node-head">
        <span aria-hidden="true"></span>
        {nodeSortColumns.map((column) => (
          <SortableNodeHeader key={column.key} column={column} sort={sort} onSort={onSort} />
        ))}
        <span>绑定入口</span>
        <span>操作</span>
      </div>
      {nodes.map((node) => {
        const nodeID = String(node.id || "");
        const hasNodeID = Boolean(nodeID);
        const nodeTesting = node.probe_status === "testing";
        const testDisabled = nodeTesting || !hasNodeID;
        const selectedListener = selectedListeners[nodeID] || defaultListenerKey;
        const selectedBackend = listenerBackendsByListen?.get(selectedListener);
        const listenerHasConnection = Boolean(selectedBackend?.node_id || selectedBackend?.status === "running");
        const connecting = busyAction === `connect-${nodeID}`;
        const cancellingTest = busyAction === `cancel-test-${nodeID}`;
        const connectDisabled = nodeTesting || !hasNodeID || (!node.active && !selectedListener);
        const connectLabel = node.active ? "断开" : currentConnected ? "切换" : "连接";
        const connectIcon = node.active ? Power : Play;
        const handleConnect = () => {
          if (node.active) {
            onDisconnect();
            return;
          }
          if (listenerHasConnection && selectedBackend?.node_id !== nodeID) {
            const currentNode = selectedBackend?.node_id ? `节点 ${selectedBackend.node_id}` : "已有连接";
            if (!window.confirm(`入口 ${selectedListener} 当前已连接 ${currentNode}。是否切换到节点 ${nodeID}？`)) {
              return;
            }
          }
          onConnect(nodeID, selectedListener);
        };
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
            <NodeNetworkInfo node={node} />
            <select
              className="node-listener-select"
              value={selectedListener}
              disabled={nodeTesting || !listenerOptions.length}
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
              {nodeTesting ? (
                <ActionButton icon={CircleX} label="取消" compact danger busy={cancellingTest} onClick={() => onCancelTest(nodeID)} />
              ) : (
                <ActionButton icon={Zap} label="测试" compact busy={busyAction === `test-${nodeID}`} disabled={testDisabled} onClick={() => onTest(nodeID)} />
              )}
              <ActionButton icon={connectIcon} label={connectLabel} compact danger={node.active} busy={connecting || (node.active && busyAction === "disconnect")} disabled={connectDisabled} onClick={handleConnect} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function SortableNodeHeader({ column, sort, onSort }) {
  const sortKey = normalizeNodeSortKey(sort?.key);
  const direction = normalizeNodeSortDirection(sort?.direction);
  const active = sortKey === column.key;
  const nextDirection = active && direction === "asc" ? "desc" : "asc";
  const currentText = active ? `当前${nodeSortDirectionLabels[direction]}` : "当前未排序";
  const sortable = typeof onSort === "function";

  return (
    <button
      type="button"
      className={`node-sort-button ${active ? "active" : ""}`}
      aria-label={`${column.label}，${currentText}，点击${nodeSortDirectionLabels[nextDirection]}排序`}
      aria-pressed={active}
      disabled={!sortable}
      title={`按${column.label}${nodeSortDirectionLabels[nextDirection]}排序`}
      onClick={() => {
        if (sortable) {
          onSort(column.key);
        }
      }}
    >
      <span>{column.label}</span>
      <ArrowUpDown className={`sort-icon ${active ? direction : ""}`} size={14} aria-hidden="true" />
    </button>
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

function NodeNetworkInfo({ node }) {
  const network = formatIPNetworkText(node?.exit_ip_info);
  return (
    <div className="node-cell node-network" title={network || "无 ASN / 运营商信息"}>
      {network || "-"}
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
        const generateListenerCredentials = () => {
          try {
            const credentials = generateSocksCredentials();
            onUpdate(index, "username", credentials.username);
            onUpdate(index, "password", credentials.password);
          } catch (error) {
            const message = error?.message || "生成 SOCKS5 随机用户名和密码失败。";
            console.error(message, error);
            if (typeof window !== "undefined" && typeof window.alert === "function") {
              window.alert(message);
            }
          }
        };
        return (
          <div className="listener" key={`${listener.name}-${index}`}>
            <div className="listener-head">
              <strong>{listener.name || `socks${index + 1}`}</strong>
              <div className="listener-head-actions">
                <ActionButton icon={Dices} label="随机账号密码" compact onClick={generateListenerCredentials} />
                <ActionButton icon={Trash2} label="删除" danger compact onClick={() => onRemove(index)} />
              </div>
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
              <PasswordInput label="SOCKS5 密码" value={listener.password} onChange={(value) => onUpdate(index, "password", value)} autoComplete="new-password" placeholder="公网监听必须填写" />
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

function LogList({ logs, className, lineClassName, timeClassName, levelClassName, emptyText }) {
  if (!logs.length) {
    return <div className={className}>{emptyText}</div>;
  }
  return (
    <div className={className}>
      {logs.map((item, index) => {
        const fields = item.fields
          ? Object.entries(item.fields)
              .map(([key, value]) => ` ${key}=${value}`)
              .join("")
          : "";
        const level = item.level || "INFO";
        return (
          <div className={lineClassName} key={`${item.time}-${index}`}>
            <span className={timeClassName}>{item.time || ""}</span>{" "}
            <span className={`${levelClassName} ${level}`}>{level}</span> {item.message || ""}
            {fields}
          </div>
        );
      })}
    </div>
  );
}

function LogView({ logs }) {
  return (
    <LogList
      logs={logs}
      className="logs"
      lineClassName="log-line"
      timeClassName="log-time"
      levelClassName="log-level"
      emptyText="暂无日志。"
    />
  );
}

function AuditLogView({ logs }) {
  return (
    <LogList
      logs={logs}
      className="audit-logs"
      lineClassName="audit-log-line"
      timeClassName="audit-log-time"
      levelClassName="audit-log-level"
      emptyText="暂无审计日志。"
    />
  );
}

createRoot(document.getElementById("root")).render(<App />);
