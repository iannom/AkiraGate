package vpngate

import (
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const DefaultAPIURL = "https://www.vpngate.net/api/iphone/"

type Node struct {
	ID           string    `json:"id"`
	Country      string    `json:"country"`
	CountryShort string    `json:"country_short"`
	IP           string    `json:"ip"`
	Hostname     string    `json:"hostname"`
	RemoteHost   string    `json:"remote_host"`
	RemotePort   int       `json:"remote_port"`
	Proto        string    `json:"proto"`
	Score        int       `json:"score"`
	Ping         int       `json:"ping"`
	Speed        int       `json:"speed"`
	Sessions     int       `json:"sessions"`
	ConfigText   string    `json:"-"`
	FetchedAt    time.Time `json:"fetched_at"`
	Active       bool      `json:"active"`
	ProbeStatus  string    `json:"probe_status"`
	ProbeMessage string    `json:"probe_message,omitempty"`
	ProbeLatency int       `json:"probe_latency_ms,omitempty"`
	ExitIPInfo   *IPInfo   `json:"exit_ip_info,omitempty"`
}

type IPInfo struct {
	IP             string `json:"ip"`
	Status         string `json:"status,omitempty"`
	Country        string `json:"country,omitempty"`
	CountryCode    string `json:"country_code,omitempty"`
	Region         string `json:"region,omitempty"`
	City           string `json:"city,omitempty"`
	ISP            string `json:"isp,omitempty"`
	Organization   string `json:"organization,omitempty"`
	ASN            string `json:"asn,omitempty"`
	ASNNumber      int    `json:"asn_number,omitempty"`
	ASOrganization string `json:"as_organization,omitempty"`
	IPType         string `json:"ip_type,omitempty"`
	Mobile         bool   `json:"mobile,omitempty"`
	Proxy          bool   `json:"proxy,omitempty"`
	Hosting        bool   `json:"hosting,omitempty"`
	Residential    bool   `json:"residential,omitempty"`
	FraudScore     int    `json:"fraud_score,omitempty"`
	Error          string `json:"error,omitempty"`
	FetchedAt      string `json:"fetched_at,omitempty"`
}

func FetchNodes(client *http.Client, apiURL string) ([]Node, error) {
	if apiURL == "" {
		apiURL = DefaultAPIURL
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AimiliVPN-Go/1.0")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("VPNGate API 返回 HTTP %d", res.StatusCode)
	}
	return ParseNodes(res.Body)
}

func ParseNodes(reader io.Reader) ([]Node, error) {
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	headerIndex := findHeaderIndex(lines)
	if headerIndex < 0 {
		return nil, errors.New("VPNGate CSV 缺少包含 HostName 和 OpenVPN_ConfigData_Base64 的表头")
	}
	csvLines := append([]string{normalizeHeaderLine(lines[headerIndex])}, lines[headerIndex+1:]...)
	csvText := strings.Join(csvLines, "\n")
	csvReader := csv.NewReader(strings.NewReader(csvText))
	csvReader.FieldsPerRecord = -1
	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, errors.New("VPNGate CSV 没有节点记录")
	}
	headers := normalizeHeaders(records[0])
	if !hasRequiredHeaders(headers) {
		return nil, errors.New("VPNGate CSV 表头缺少必要字段")
	}
	var nodes []Node
	seen := map[string]struct{}{}
	candidateRows := 0
	skippedRows := 0
	for _, record := range records[1:] {
		if isMetadataRecord(record) {
			continue
		}
		candidateRows++
		row := map[string]string{}
		for idx, header := range headers {
			if idx < len(record) {
				row[header] = strings.TrimSpace(record[idx])
			}
		}
		encoded := row["OpenVPN_ConfigData_Base64"]
		if encoded == "" {
			skippedRows++
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			skippedRows++
			continue
		}
		configText := string(decoded)
		remoteHost, remotePort, proto := ParseRemote(configText, row["IP"])
		if remoteHost == "" || remotePort == 0 {
			skippedRows++
			continue
		}
		id := safeID(row["CountryShort"], remoteHost, strconv.Itoa(remotePort), proto)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		nodes = append(nodes, Node{
			ID:           id,
			Country:      row["CountryLong"],
			CountryShort: row["CountryShort"],
			IP:           row["IP"],
			Hostname:     row["HostName"],
			RemoteHost:   remoteHost,
			RemotePort:   remotePort,
			Proto:        proto,
			Score:        parseInt(row["Score"]),
			Ping:         parseInt(row["Ping"]),
			Speed:        parseInt(row["Speed"]),
			Sessions:     parseInt(row["NumVpnSessions"]),
			ConfigText:   configText,
			FetchedAt:    time.Now(),
			ProbeStatus:  "not_checked",
		})
	}
	if len(nodes) == 0 {
		if candidateRows == 0 {
			return nil, errors.New("VPNGate CSV 没有节点记录")
		}
		return nil, fmt.Errorf("VPNGate CSV 未解析到可用节点: 记录数=%d, 跳过=%d", candidateRows, skippedRows)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Ping != nodes[j].Ping {
			if nodes[i].Ping == 0 {
				return false
			}
			if nodes[j].Ping == 0 {
				return true
			}
			return nodes[i].Ping < nodes[j].Ping
		}
		return nodes[i].Score > nodes[j].Score
	})
	return nodes, nil
}

func findHeaderIndex(lines []string) int {
	for idx, line := range lines {
		headers, ok := parseHeaderLine(line)
		if ok && hasRequiredHeaders(headers) {
			return idx
		}
	}
	return -1
}

func parseHeaderLine(line string) ([]string, bool) {
	normalized := normalizeHeaderLine(line)
	if !strings.Contains(normalized, ",") {
		return nil, false
	}
	reader := csv.NewReader(strings.NewReader(normalized))
	reader.FieldsPerRecord = -1
	record, err := reader.Read()
	if err != nil {
		return nil, false
	}
	return normalizeHeaders(record), true
}

func normalizeHeaderLine(line string) string {
	normalized := strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
	if normalized == "" {
		return ""
	}
	if strings.HasPrefix(normalized, "#") || strings.HasPrefix(normalized, "*") {
		normalized = normalized[1:]
	}
	return strings.TrimSpace(normalized)
}

func normalizeHeaders(headers []string) []string {
	normalized := make([]string, 0, len(headers))
	for _, header := range headers {
		normalized = append(normalized, strings.TrimSpace(strings.TrimPrefix(header, "\ufeff")))
	}
	return normalized
}

func hasRequiredHeaders(headers []string) bool {
	found := map[string]bool{}
	for _, header := range headers {
		found[header] = true
	}
	return found["HostName"] && found["IP"] && found["OpenVPN_ConfigData_Base64"]
}

func isMetadataRecord(record []string) bool {
	if len(record) == 0 {
		return true
	}
	first := strings.TrimSpace(record[0])
	return first == "" || strings.HasPrefix(first, "#") || strings.HasPrefix(first, "*")
}

func ParseRemote(configText string, fallbackHost string) (string, int, string) {
	for _, raw := range strings.Split(configText, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "remote" {
			port := parseInt(fields[2])
			proto := "udp"
			if len(fields) >= 4 {
				proto = strings.ToLower(fields[3])
			}
			return fields[1], port, proto
		}
	}
	return fallbackHost, 0, "udp"
}

func parseInt(value string) int {
	parsed, _ := strconv.Atoi(strings.TrimSpace(value))
	return parsed
}

func safeID(parts ...string) string {
	value := strings.Join(parts, "_")
	var builder strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			builder.WriteRune(r)
		} else {
			builder.WriteByte('_')
		}
	}
	id := strings.Trim(builder.String(), "._")
	if id == "" {
		return "node"
	}
	return id
}
