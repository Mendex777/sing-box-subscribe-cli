package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var controlOutboundTypes = map[string]bool{
	"selector": true,
	"urltest":  true,
	"direct":   true,
	"block":    true,
	"dns":      true,
}

var uriPrefixes = []string{
	"vless://",
	"vmess://",
	"trojan://",
	"ss://",
	"hysteria://",
	"hysteria2://",
	"hy2://",
	"tuic://",
	"socks://",
	"socks5://",
	"http://",
	"https://",
}

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type config struct {
	template    string
	subs        stringList
	subsFile    string
	out         string
	target      string
	prefix      string
	onlyNodes   bool
	strict      bool
	keepGoing   bool
	printStdout bool
	timeout     time.Duration
	userAgent   string
}

type incompatibleError struct {
	message string
}

func (e incompatibleError) Error() string {
	return e.message
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	cfg := parseFlags(argv)
	if cfg == nil {
		return 2
	}
	if err := build(*cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func parseFlags(argv []string) *config {
	fs := flag.NewFlagSet("sbs", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfg := &config{}
	fs.StringVar(&cfg.template, "template", "", "template URL or local JSON file")
	fs.Var(&cfg.subs, "sub", "subscription URL/file/raw URI; may be repeated; optional form: tag=source")
	fs.StringVar(&cfg.subsFile, "subs-file", "", "file or URL with one subscription source per line")
	fs.StringVar(&cfg.out, "out", "config.json", "output file path, or '-' for stdout")
	fs.StringVar(&cfg.target, "target", "sing-box", "config compatibility target: sing-box or extended")
	fs.StringVar(&cfg.prefix, "prefix", "", "prefix to add to every node tag")
	fs.BoolVar(&cfg.onlyNodes, "only-nodes", false, "write only parsed sing-box outbounds")
	fs.BoolVar(&cfg.strict, "strict", false, "fail if no compatible nodes are found")
	fs.BoolVar(&cfg.keepGoing, "keep-going", false, "skip failed subscriptions instead of failing")
	fs.BoolVar(&cfg.printStdout, "print", false, "print JSON to stdout")
	timeout := fs.Int("timeout", 30, "HTTP timeout in seconds")
	fs.StringVar(&cfg.userAgent, "user-agent", "sbs-cli-go/0.1", "User-Agent used for downloading subscriptions and templates")
	if err := fs.Parse(argv); err != nil {
		return nil
	}
	cfg.timeout = time.Duration(*timeout) * time.Second
	if cfg.template == "" {
		fmt.Fprintln(os.Stderr, "error: --template is required")
		return nil
	}
	if cfg.target != "sing-box" && cfg.target != "extended" {
		fmt.Fprintln(os.Stderr, "error: --target must be sing-box or extended")
		return nil
	}
	return cfg
}

func build(cfg config) error {
	template, err := loadTemplate(cfg.template, cfg)
	if err != nil {
		return err
	}
	subValues, err := collectSubscriptions(cfg)
	if err != nil {
		return err
	}
	groups := map[string][]map[string]any{}
	var warnings []string
	for i, value := range subValues {
		group, nodes, groupWarnings, err := loadSubscription(value, i+1, cfg)
		warnings = append(warnings, groupWarnings...)
		if err != nil {
			if cfg.keepGoing {
				warnings = append(warnings, err.Error())
				continue
			}
			return err
		}
		groups[group] = append(groups[group], nodes...)
	}
	allNodes := flattenGroups(groups)
	uniqueTags(allNodes)
	if len(allNodes) == 0 && cfg.strict {
		return errors.New("no compatible nodes found")
	}
	var result any
	if cfg.onlyNodes {
		result = allNodes
	} else {
		result, err = combineConfig(template, groups)
		if err != nil {
			return err
		}
	}
	if err := writeJSON(cfg.out, result, cfg.printStdout); err != nil {
		return err
	}
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	fmt.Fprintf(os.Stderr, "compatible nodes: %d\n", len(allNodes))
	if cfg.out != "-" && !cfg.printStdout {
		fmt.Fprintln(os.Stderr, "written:", cfg.out)
	}
	return nil
}

func isExtended(target string) bool {
	return target == "extended"
}

func collectSubscriptions(cfg config) ([]string, error) {
	values := append([]string{}, cfg.subs...)
	if cfg.subsFile != "" {
		content, err := readSource(cfg.subsFile, cfg)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				values = append(values, line)
			}
		}
	}
	if len(values) == 0 {
		return nil, errors.New("at least one --sub or --subs-file is required")
	}
	return values, nil
}

func loadTemplate(source string, cfg config) (map[string]any, error) {
	content, err := readSource(source, cfg)
	if err != nil {
		return nil, err
	}
	var template map[string]any
	decoder := json.NewDecoder(strings.NewReader(content))
	decoder.UseNumber()
	if err := decoder.Decode(&template); err != nil {
		return nil, fmt.Errorf("template is not valid JSON: %w", err)
	}
	return template, nil
}

func loadSubscription(value string, index int, cfg config) (string, []map[string]any, []string, error) {
	group, source := parseSubArg(value, index)
	content, err := readSource(source, cfg)
	if err != nil {
		return group, nil, nil, err
	}
	var warnings []string
	nodes, err := parseContent(content, cfg.target, &warnings)
	if err != nil {
		return group, nil, warnings, fmt.Errorf("%s: failed to parse subscription: %w", group, err)
	}
	filtered := make([]map[string]any, 0, len(nodes))
	for _, node := range nodes {
		normalized, err := normalizeExistingOutbound(node, cfg.target)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", getString(node, "tag", group), err))
			continue
		}
		if cfg.prefix != "" {
			normalized["tag"] = cfg.prefix + getString(normalized, "tag", "node")
			if detour, ok := normalized["detour"].(string); ok && detour != "" {
				normalized["detour"] = cfg.prefix + detour
			}
		}
		filtered = append(filtered, normalized)
	}
	return group, filtered, warnings, nil
}

func parseSubArg(value string, index int) (string, string) {
	eq := strings.Index(value, "=")
	scheme := strings.Index(value, "://")
	if eq > 0 && (scheme == -1 || eq < scheme) {
		tag := strings.TrimSpace(value[:eq])
		source := strings.TrimSpace(value[eq+1:])
		if tag != "" && source != "" {
			return tag, source
		}
	}
	return fmt.Sprintf("sub%d", index), value
}

func readSource(source string, cfg config) (string, error) {
	if isHTTPURL(source) {
		return fetchText(source, cfg)
	}
	if stat, err := os.Stat(source); err == nil && !stat.IsDir() {
		data, err := os.ReadFile(source)
		if err != nil {
			return "", err
		}
		return strings.TrimPrefix(string(data), "\ufeff"), nil
	}
	return source, nil
}

func isHTTPURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func fetchText(source string, cfg config) (string, error) {
	client := &http.Client{Timeout: cfg.timeout}
	req, err := http.NewRequest(http.MethodGet, source, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", cfg.userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to load %s: %w", source, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d while loading %s", resp.StatusCode, source)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(string(data), "\ufeff"), nil
}

func parseContent(content string, target string, warnings *[]string) ([]map[string]any, error) {
	if nodes, ok, err := parseJSONNodes(content, target, warnings); ok || err != nil {
		return nodes, err
	}
	nodes := parseLines(content, target, warnings)
	if len(nodes) > 0 {
		return nodes, nil
	}
	if decoded, ok := decodeBase64(content); ok && decoded != content {
		return parseContent(decoded, target, warnings)
	}
	return nil, nil
}

func parseJSONNodes(content string, target string, warnings *[]string) ([]map[string]any, bool, error) {
	decoder := json.NewDecoder(strings.NewReader(content))
	decoder.UseNumber()
	var data any
	if err := decoder.Decode(&data); err != nil {
		return nil, false, nil
	}
	var candidates []any
	switch typed := data.(type) {
	case map[string]any:
		if outbounds, ok := typed["outbounds"].([]any); ok {
			candidates = outbounds
		} else if _, ok := typed["type"]; ok {
			candidates = []any{typed}
		} else {
			return nil, true, nil
		}
	case []any:
		candidates = typed
	default:
		return nil, true, nil
	}
	var nodes []map[string]any
	for i, candidate := range candidates {
		node, ok := candidate.(map[string]any)
		if !ok {
			continue
		}
		normalized, err := normalizeExistingOutbound(node, target)
		if err != nil {
			if warnings != nil {
				*warnings = append(*warnings, fmt.Sprintf("json outbound %d: %v", i+1, err))
			}
			continue
		}
		nodes = append(nodes, normalized)
	}
	return nodes, true, nil
}

func parseLines(content string, target string, warnings *[]string) []map[string]any {
	var nodes []map[string]any
	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "sub://") {
			if decoded, ok := decodeBase64(strings.TrimPrefix(line, "sub://")); ok {
				subNodes, _ := parseContent(decoded, target, warnings)
				nodes = append(nodes, subNodes...)
			}
			continue
		}
		if !looksLikeURI(line) {
			continue
		}
		node, err := parseURI(line, target)
		if err != nil {
			if warnings != nil {
				*warnings = append(*warnings, fmt.Sprintf("line %d: %v", i+1, err))
			}
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func looksLikeURI(line string) bool {
	lower := strings.ToLower(line)
	for _, prefix := range uriPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func parseURI(line string, target string) (map[string]any, error) {
	lower := strings.ToLower(line)
	switch {
	case strings.HasPrefix(lower, "vless://"):
		return parseVLESS(line, target)
	case strings.HasPrefix(lower, "vmess://"):
		return parseVMess(line)
	case strings.HasPrefix(lower, "trojan://"):
		return parseTrojan(line)
	case strings.HasPrefix(lower, "ss://"):
		return parseShadowsocks(line)
	case strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hy2://"):
		return parseHysteria(strings.Replace(line, "hy2://", "hysteria2://", 1), 2)
	case strings.HasPrefix(lower, "hysteria://"):
		return parseHysteria(line, 1)
	case strings.HasPrefix(lower, "tuic://"):
		return parseTUIC(line)
	case strings.HasPrefix(lower, "socks://"), strings.HasPrefix(lower, "socks5://"):
		return parseSocks(strings.Replace(line, "socks5://", "socks://", 1))
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
		return parseHTTPProxy(line)
	default:
		return nil, errors.New("unsupported URI")
	}
}

func normalizeExistingOutbound(node map[string]any, target string) (map[string]any, error) {
	typ := getString(node, "type", "")
	if controlOutboundTypes[typ] {
		return nil, incompatibleError{"control outbound skipped: " + typ}
	}
	if typ == "vless" && !isExtended(target) {
		if transport, ok := node["transport"].(map[string]any); ok && getString(transport, "type", "") == "xhttp" {
			return nil, incompatibleError{"vless xhttp transport requires --target extended"}
		}
	}
	return cloneMap(node), nil
}

func parseVLESS(raw string, target string) (map[string]any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("missing uuid")
	}
	host := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	query := firstQueryValues(u.Query())
	transportType := query["type"]
	if transportType == "xhttp" && !isExtended(target) {
		return nil, incompatibleError{"vless xhttp transport requires --target extended"}
	}
	node := map[string]any{
		"tag":             fragment(u),
		"type":            "vless",
		"server":          host,
		"server_port":     port,
		"uuid":            u.User.Username(),
		"packet_encoding": firstNonEmpty(query["packetEncoding"], "xudp"),
	}
	if node["tag"] == "" {
		node["tag"] = "vless"
	}
	if encryption := query["encryption"]; encryption != "" && encryption != "none" {
		if !isExtended(target) {
			return nil, incompatibleError{"vless encryption requires --target extended"}
		}
		node["encryption"] = encryption
	}
	if flow := query["flow"]; flow != "" {
		node["flow"] = flow
	}
	if shouldEnableTLS(query) {
		tls := map[string]any{
			"enabled":  true,
			"insecure": parseBool(firstNonEmpty(query["allowInsecure"], query["insecure"]), false),
		}
		if serverName := firstNonEmpty(query["sni"], query["peer"], query["serverName"]); serverName != "" && serverName != "None" {
			tls["server_name"] = serverName
		}
		if alpn := query["alpn"]; alpn != "" {
			tls["alpn"] = splitCSV(alpn)
		}
		if query["security"] == "reality" || query["pbk"] != "" {
			reality := map[string]any{"enabled": true, "public_key": query["pbk"]}
			if sid := query["sid"]; sid != "" && strings.ToLower(sid) != "none" {
				reality["short_id"] = sid
			}
			tls["reality"] = reality
		}
		if fp := query["fp"]; fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		node["tls"] = tls
	}
	switch transportType {
	case "ws", "websocket":
		path := firstNonEmpty(query["path"], "/")
		transport := map[string]any{"type": "ws", "path": strings.Split(path, "?ed=")[0]}
		if hostHeader := firstNonEmpty(query["host"], query["peer"], query["sni"]); hostHeader != "" && hostHeader != "None" {
			transport["headers"] = map[string]any{"Host": hostHeader}
		}
		if match := regexp.MustCompile(`\?ed=(\d+)$`).FindStringSubmatch(path); len(match) == 2 {
			transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
			transport["max_early_data"], _ = strconv.Atoi(match[1])
		}
		node["transport"] = transport
	case "grpc":
		node["transport"] = map[string]any{"type": "grpc", "service_name": query["serviceName"]}
	case "http", "h2":
		transport := map[string]any{"type": "http"}
		if host := query["host"]; host != "" {
			transport["host"] = splitCSV(host)
		}
		if path := query["path"]; path != "" {
			transport["path"] = path
		}
		node["transport"] = transport
	case "httpupgrade":
		transport := map[string]any{"type": "httpupgrade"}
		if host := query["host"]; host != "" {
			transport["host"] = host
		}
		if path := query["path"]; path != "" {
			transport["path"] = path
		}
		node["transport"] = transport
	case "quic":
		node["transport"] = map[string]any{"type": "quic"}
	case "mkcp", "kcp":
		if !isExtended(target) {
			return nil, incompatibleError{"vless mKCP transport requires --target extended"}
		}
		node["transport"] = parseMKCPTransport(query)
	case "xhttp":
		node["transport"] = parseXHTTPTransport(query, node)
	case "", "tcp":
	default:
		return nil, incompatibleError{"unsupported vless transport: " + transportType}
	}
	return node, nil
}

func parseVMess(raw string) (map[string]any, error) {
	decoded, ok := decodeBase64(strings.TrimPrefix(raw, "vmess://"))
	if !ok {
		return nil, errors.New("invalid vmess base64")
	}
	var item map[string]any
	if err := json.Unmarshal([]byte(decoded), &item); err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(fmt.Sprint(item["port"]))
	security := fmt.Sprint(item["scy"])
	if security == "" || security == "<nil>" || security == "http" || security == "gun" {
		security = "auto"
	}
	alterID, _ := strconv.Atoi(firstNonEmpty(fmt.Sprint(item["aid"]), "0"))
	node := map[string]any{
		"tag":             firstNonEmpty(strings.TrimSpace(fmt.Sprint(item["ps"])), "vmess"),
		"type":            "vmess",
		"server":          item["add"],
		"server_port":     port,
		"uuid":            item["id"],
		"security":        security,
		"alter_id":        alterID,
		"packet_encoding": "xudp",
	}
	if tlsValue := fmt.Sprint(item["tls"]); tlsValue != "" && tlsValue != "<nil>" && tlsValue != "none" {
		tls := map[string]any{"enabled": true, "insecure": true}
		if sni := fmt.Sprint(item["sni"]); sni != "" && sni != "<nil>" {
			tls["server_name"] = sni
		} else if host := fmt.Sprint(item["host"]); host != "" && host != "<nil>" && item["net"] != "h2" && item["net"] != "http" {
			tls["server_name"] = host
		}
		if fp := fmt.Sprint(item["fp"]); fp != "" && fp != "<nil>" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		node["tls"] = tls
	}
	switch fmt.Sprint(item["net"]) {
	case "ws", "websocket":
		path := firstNonEmpty(fmt.Sprint(item["path"]), "/")
		transport := map[string]any{"type": "ws", "path": strings.Split(path, "?ed=")[0]}
		if host := fmt.Sprint(item["host"]); host != "" && host != "<nil>" {
			transport["headers"] = map[string]any{"Host": host}
		}
		node["transport"] = transport
	case "grpc":
		node["transport"] = map[string]any{"type": "grpc", "service_name": item["path"]}
	case "h2", "http":
		node["transport"] = map[string]any{"type": "http"}
	case "", "<nil>", "tcp":
	default:
		return nil, incompatibleError{"unsupported vmess transport: " + fmt.Sprint(item["net"])}
	}
	return node, nil
}

func parseTrojan(raw string) (map[string]any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	password := ""
	address := u.Host
	if u.User != nil {
		password = u.User.Username()
	}
	host := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, err
	}
	query := firstQueryValues(u.Query())
	transportType := query["type"]
	if transportType == "xhttp" {
		return nil, incompatibleError{"trojan xhttp transport is not supported"}
	}
	_ = address
	node := map[string]any{
		"tag":         firstNonEmpty(fragment(u), "trojan"),
		"type":        "trojan",
		"server":      host,
		"server_port": port,
		"password":    password,
		"tls": map[string]any{
			"enabled":  true,
			"insecure": parseBool(query["allowInsecure"], false),
		},
	}
	tls := node["tls"].(map[string]any)
	if sni := query["sni"]; sni != "" {
		tls["server_name"] = sni
	}
	if alpn := query["alpn"]; alpn != "" {
		tls["alpn"] = splitCSV(alpn)
	}
	if fp := query["fp"]; fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	switch transportType {
	case "ws", "websocket":
		transport := map[string]any{"type": "ws", "path": firstNonEmpty(query["path"], "/")}
		if hostHeader := query["host"]; hostHeader != "" {
			transport["headers"] = map[string]any{"Host": hostHeader}
		}
		node["transport"] = transport
	case "grpc":
		node["transport"] = map[string]any{"type": "grpc", "service_name": query["serviceName"]}
	case "h2", "http":
		node["transport"] = map[string]any{"type": "http", "path": firstNonEmpty(query["path"], "/")}
	case "", "tcp":
	default:
		return nil, incompatibleError{"unsupported trojan transport: " + transportType}
	}
	return node, nil
}

func parseShadowsocks(raw string) (map[string]any, error) {
	param := strings.TrimPrefix(raw, "ss://")
	tag := "shadowsocks"
	if hash := strings.Index(param, "#"); hash >= 0 {
		tag = urlDecode(param[hash+1:])
		param = param[:hash]
	}
	query := ""
	if q := strings.Index(param, "?"); q >= 0 {
		query = param[q+1:]
		param = param[:q]
	}
	var userInfo, address string
	if at := strings.LastIndex(param, "@"); at >= 0 {
		userInfo = param[:at]
		address = param[at+1:]
		if decoded, ok := decodeBase64(userInfo); ok {
			userInfo = decoded
		} else {
			userInfo = urlDecode(userInfo)
		}
	} else {
		decoded, ok := decodeBase64(param)
		if !ok {
			return nil, errors.New("invalid ss link")
		}
		at := strings.LastIndex(decoded, "@")
		if at < 0 {
			return nil, errors.New("invalid ss link")
		}
		userInfo = decoded[:at]
		address = decoded[at+1:]
	}
	method, password, ok := strings.Cut(userInfo, ":")
	if !ok {
		return nil, errors.New("invalid ss credentials")
	}
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	node := map[string]any{
		"tag":         firstNonEmpty(tag, "shadowsocks"),
		"type":        "shadowsocks",
		"server":      host,
		"server_port": port,
		"method":      method,
		"password":    password,
	}
	if strings.Contains(query, "uot=1") {
		node["udp_over_tcp"] = map[string]any{"enabled": true, "version": 2}
	}
	return node, nil
}

func parseHysteria(raw string, version int) (map[string]any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	query := firstQueryValues(u.Query())
	hostPort := u.Host
	if strings.Contains(hostPort, "@") {
		hostPort = hostPort[strings.LastIndex(hostPort, "@")+1:]
	}
	hostPort = strings.Split(hostPort, ",")[0]
	host, port, err := splitHostPort(hostPort)
	if err != nil {
		return nil, err
	}
	nodeType := "hysteria"
	if version == 2 {
		nodeType = "hysteria2"
	}
	node := map[string]any{
		"tag":         firstNonEmpty(fragment(u), nodeType),
		"type":        nodeType,
		"server":      host,
		"server_port": port,
		"up_mbps":     firstIntFromString(firstNonEmpty(query["upmbps"], "10")),
		"down_mbps":   firstIntFromString(firstNonEmpty(query["downmbps"], "100")),
		"tls": map[string]any{
			"enabled":  true,
			"insecure": parseBool(firstNonEmpty(query["insecure"], query["allowInsecure"]), false),
		},
	}
	tls := node["tls"].(map[string]any)
	if serverName := firstNonEmpty(query["sni"], query["peer"]); serverName != "" && serverName != "None" {
		tls["server_name"] = serverName
	}
	if alpn := query["alpn"]; alpn != "" {
		tls["alpn"] = splitCSV(alpn)
	}
	if version == 2 {
		password := query["auth"]
		if password == "" && u.User != nil {
			password = u.User.Username()
		}
		node["password"] = password
		if obfs := query["obfs"]; obfs != "" && obfs != "none" {
			node["obfs"] = map[string]any{"type": obfs, "password": query["obfs-password"]}
		}
	} else {
		node["auth_str"] = query["auth"]
		if obfs := query["obfs"]; obfs != "" && obfs != "none" {
			node["obfs"] = obfs
		}
	}
	return node, nil
}

func parseTUIC(raw string) (map[string]any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, errors.New("missing tuic auth")
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, err
	}
	query := firstQueryValues(u.Query())
	password, _ := u.User.Password()
	node := map[string]any{
		"tag":                firstNonEmpty(fragment(u), "tuic"),
		"type":               "tuic",
		"server":             host,
		"server_port":        port,
		"uuid":               u.User.Username(),
		"password":           firstNonEmpty(password, query["password"]),
		"congestion_control": firstNonEmpty(query["congestion_control"], "bbr"),
		"udp_relay_mode":     query["udp_relay_mode"],
		"zero_rtt_handshake": false,
		"heartbeat":          "10s",
		"tls":                map[string]any{"enabled": true, "alpn": splitCSV(firstNonEmpty(query["alpn"], "h3")), "insecure": parseBool(query["allow_insecure"], false)},
	}
	if serverName := firstNonEmpty(query["sni"], query["peer"]); serverName != "" {
		node["tls"].(map[string]any)["server_name"] = serverName
	}
	return removeNilEmpty(node), nil
}

func parseSocks(raw string) (map[string]any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, err
	}
	node := map[string]any{
		"tag":         firstNonEmpty(fragment(u), "socks"),
		"type":        "socks",
		"version":     "5",
		"server":      host,
		"server_port": port,
	}
	if u.User != nil {
		node["username"] = u.User.Username()
		if password, ok := u.User.Password(); ok {
			node["password"] = password
		}
	}
	return node, nil
}

func parseHTTPProxy(raw string) (map[string]any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, err
	}
	node := map[string]any{
		"tag":         firstNonEmpty(fragment(u), "http"),
		"type":        "http",
		"server":      host,
		"server_port": port,
	}
	if u.Scheme == "https" {
		node["tls"] = map[string]any{"enabled": true, "insecure": true}
	}
	if u.User != nil {
		node["username"] = u.User.Username()
		if password, ok := u.User.Password(); ok {
			node["password"] = password
		}
	}
	return node, nil
}

func parseXHTTPTransport(query map[string]string, node map[string]any) map[string]any {
	extra := parseExtraJSON(query)
	transport := map[string]any{
		"type":            "xhttp",
		"mode":            firstNonEmpty(query["mode"], asString(extra["mode"]), "auto"),
		"path":            firstNonEmpty(query["path"], asString(extra["path"]), "/"),
		"x_padding_bytes": firstNonEmpty(asString(extra["xPaddingBytes"]), "100-1000"),
	}
	addIfPresent(transport, "host", firstNonEmpty(query["host"], asString(extra["host"])))
	if headers, ok := extra["headers"].(map[string]any); ok {
		clean := map[string]any{}
		for k, v := range headers {
			if strings.EqualFold(k, "host") || v == nil {
				continue
			}
			clean[k] = fmt.Sprint(v)
		}
		if len(clean) > 0 {
			transport["headers"] = clean
		}
	}
	mapping := map[string]string{
		"noGRPCHeader":         "no_grpc_header",
		"noSSEHeader":          "no_sse_header",
		"scMaxEachPostBytes":   "sc_max_each_post_bytes",
		"scMinPostsIntervalMs": "sc_min_posts_interval_ms",
		"scMaxBufferedPosts":   "sc_max_buffered_posts",
		"scStreamUpServerSecs": "sc_stream_up_server_secs",
		"xPaddingObfsMode":     "x_padding_obfs_mode",
		"xPaddingKey":          "x_padding_key",
		"xPaddingHeader":       "x_padding_header",
		"xPaddingPlacement":    "x_padding_placement",
		"xPaddingMethod":       "x_padding_method",
		"uplinkHTTPMethod":     "uplink_http_method",
		"sessionPlacement":     "session_placement",
		"sessionKey":           "session_key",
		"seqPlacement":         "seq_placement",
		"seqKey":               "seq_key",
		"uplinkDataPlacement":  "uplink_data_placement",
		"uplinkDataKey":        "uplink_data_key",
		"uplinkChunkSize":      "uplink_chunk_size",
	}
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, source := range keys {
		addIfPresent(transport, mapping[source], extra[source])
	}
	if xmux := parseXmux(extra); len(xmux) > 0 {
		transport["xmux"] = xmux
	}
	if download, ok := extra["downloadSettings"].(map[string]any); ok {
		nestedExtra, _ := json.Marshal(download)
		nestedQuery := copyStringMap(query)
		nestedQuery["extra"] = string(nestedExtra)
		dl := parseXHTTPTransport(nestedQuery, node)
		delete(dl, "type")
		delete(dl, "mode")
		if server := node["server"]; server != nil {
			dl["server"] = server
		}
		if port := node["server_port"]; port != nil {
			dl["server_port"] = port
		}
		if tls := node["tls"]; tls != nil {
			dl["tls"] = cloneValue(tls)
		}
		transport["download"] = dl
	}
	return transport
}

func parseMKCPTransport(query map[string]string) map[string]any {
	transport := map[string]any{"type": "mkcp"}
	mapping := map[string]string{
		"mtu":               "mtu",
		"tti":               "tti",
		"uplinkCapacity":    "uplink_capacity",
		"uplink_capacity":   "uplink_capacity",
		"downlinkCapacity":  "downlink_capacity",
		"downlink_capacity": "downlink_capacity",
		"readBufferSize":    "read_buffer_size",
		"read_buffer_size":  "read_buffer_size",
		"writeBufferSize":   "write_buffer_size",
		"write_buffer_size": "write_buffer_size",
		"headerType":        "header_type",
		"header_type":       "header_type",
		"seed":              "seed",
	}
	for source, dest := range mapping {
		if value, ok := query[source]; ok {
			addIfPresent(transport, dest, value)
		}
	}
	if value, ok := query["congestion"]; ok {
		transport["congestion"] = parseBool(value, false)
	}
	return transport
}

func parseExtraJSON(query map[string]string) map[string]any {
	raw := query["extra"]
	if raw == "" {
		return map[string]any{}
	}
	var extra map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&extra); err != nil {
		return map[string]any{}
	}
	return extra
}

func parseXmux(extra map[string]any) map[string]any {
	raw, ok := extra["xmux"].(map[string]any)
	if !ok {
		return nil
	}
	mapping := map[string]string{
		"maxConcurrency":   "max_concurrency",
		"maxConnections":   "max_connections",
		"cMaxReuseTimes":   "c_max_reuse_times",
		"hMaxRequestTimes": "h_max_request_times",
		"hMaxReusableSecs": "h_max_reusable_secs",
		"hKeepAlivePeriod": "h_keep_alive_period",
	}
	out := map[string]any{}
	for source, dest := range mapping {
		addIfPresent(out, dest, raw[source])
	}
	return out
}

func combineConfig(template map[string]any, groups map[string][]map[string]any) (map[string]any, error) {
	final := cloneMap(template)
	outbounds, ok := final["outbounds"].([]any)
	if !ok {
		return nil, errors.New("template does not contain an outbounds array")
	}
	directTag := findDirectTag(outbounds)
	for _, rawOutbound := range outbounds {
		outbound, ok := rawOutbound.(map[string]any)
		if !ok {
			continue
		}
		rawList, ok := outbound["outbounds"].([]any)
		if !ok {
			continue
		}
		filterValue := outbound["filter"]
		var expanded []any
		seen := map[string]bool{}
		for _, rawItem := range rawList {
			item := fmt.Sprint(rawItem)
			var tags []string
			if strings.HasPrefix(item, "{") && strings.HasSuffix(item, "}") {
				tags = expandPlaceholder(strings.TrimSuffix(strings.TrimPrefix(item, "{"), "}"), groups, filterValue)
			} else {
				tags = []string{item}
			}
			for _, tag := range tags {
				if tag != "" && !seen[tag] {
					expanded = append(expanded, tag)
					seen[tag] = true
				}
			}
		}
		if len(expanded) == 0 {
			expanded = []any{directTag}
		}
		outbound["outbounds"] = expanded
		delete(outbound, "filter")
	}
	for _, node := range flattenGroups(groups) {
		outbounds = append(outbounds, node)
	}
	final["outbounds"] = outbounds
	return final, nil
}

func expandPlaceholder(placeholder string, groups map[string][]map[string]any, filterValue any) []string {
	var selected []map[string]any
	if placeholder == "all" {
		keys := make([]string, 0, len(groups))
		for group := range groups {
			keys = append(keys, group)
		}
		sort.Strings(keys)
		for _, group := range keys {
			selected = append(selected, applyFilter(groups[group], filterValue, group)...)
		}
	} else if nodes, ok := groups[placeholder]; ok {
		selected = append(selected, applyFilter(nodes, filterValue, placeholder)...)
	}
	tags := make([]string, 0, len(selected))
	for _, node := range selected {
		tags = append(tags, getString(node, "tag", ""))
	}
	return tags
}

func applyFilter(nodes []map[string]any, filterValue any, group string) []map[string]any {
	if filterValue == nil {
		return nodes
	}
	var rules []any
	if list, ok := filterValue.([]any); ok {
		rules = list
	} else {
		rules = []any{filterValue}
	}
	result := append([]map[string]any{}, nodes...)
	for _, rawRule := range rules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			continue
		}
		if onlyFor, ok := rule["for"].([]any); ok && len(onlyFor) > 0 {
			matchedGroup := false
			for _, item := range onlyFor {
				if fmt.Sprint(item) == group {
					matchedGroup = true
					break
				}
			}
			if !matchedGroup {
				continue
			}
		}
		action := fmt.Sprint(rule["action"])
		keywords := stringSlice(rule["keywords"])
		if len(keywords) == 0 {
			continue
		}
		var next []map[string]any
		for _, node := range result {
			name := getString(node, "tag", "")
			matched := false
			for _, keyword := range keywords {
				if keywordMatches(name, keyword) {
					matched = true
					break
				}
			}
			if (action == "include" && matched) || (action == "exclude" && !matched) {
				next = append(next, node)
			}
		}
		result = next
	}
	return result
}

func keywordMatches(name, keyword string) bool {
	re, err := regexp.Compile(keyword)
	if err != nil {
		return strings.Contains(name, keyword)
	}
	return re.MatchString(name)
}

func findDirectTag(outbounds []any) string {
	for _, candidate := range []string{"direct", "DIRECT"} {
		for _, raw := range outbounds {
			outbound, ok := raw.(map[string]any)
			if ok && getString(outbound, "tag", "") == candidate {
				return candidate
			}
		}
	}
	for _, raw := range outbounds {
		outbound, ok := raw.(map[string]any)
		if ok && getString(outbound, "type", "") == "direct" {
			return getString(outbound, "tag", "direct")
		}
	}
	return "direct"
}

func writeJSON(path string, value any, printStdout bool) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if printStdout || path == "-" {
		fmt.Println(string(data))
		return nil
	}
	parent := filepath.Dir(path)
	if parent != "." && parent != "" {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func uniqueTags(nodes []map[string]any) {
	seen := map[string]bool{}
	for _, node := range nodes {
		base := getString(node, "tag", "node")
		candidate := base
		index := 2
		for seen[candidate] {
			candidate = fmt.Sprintf("%s %d", base, index)
			index++
		}
		node["tag"] = candidate
		seen[candidate] = true
	}
}

func flattenGroups(groups map[string][]map[string]any) []map[string]any {
	keys := make([]string, 0, len(groups))
	for group := range groups {
		keys = append(keys, group)
	}
	sort.Strings(keys)
	var all []map[string]any
	for _, group := range keys {
		all = append(all, groups[group]...)
	}
	return all
}

func shouldEnableTLS(query map[string]string) bool {
	security := query["security"]
	return (security != "" && security != "none" && security != "None") || query["tls"] == "1"
}

func firstQueryValues(values url.Values) map[string]string {
	out := map[string]string{}
	for key, list := range values {
		if len(list) > 0 {
			out[key] = list[len(list)-1]
		}
	}
	return out
}

func decodeBase64(value string) (string, bool) {
	cleaned := strings.Join(strings.Fields(strings.TrimSpace(value)), "")
	cleaned = urlDecode(cleaned)
	if cleaned == "" {
		return "", false
	}
	for len(cleaned)%4 != 0 {
		cleaned += "="
	}
	encodings := []*base64.Encoding{base64.URLEncoding, base64.StdEncoding}
	for _, encoding := range encodings {
		data, err := encoding.DecodeString(cleaned)
		if err == nil && utf8ish(data) {
			return strings.TrimPrefix(string(data), "\ufeff"), true
		}
	}
	return "", false
}

func utf8ish(data []byte) bool {
	return bytes.IndexByte(data, 0) == -1
}

func splitHostPort(value string) (string, int, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end < 0 || end+2 >= len(value) || value[end+1] != ':' {
			return "", 0, errors.New("invalid IPv6 host:port")
		}
		port, err := strconv.Atoi(firstNumber(value[end+2:]))
		return strings.Trim(value[:end+1], "[]"), port, err
	}
	host, portText, ok := strings.Cut(value, ":")
	if strings.Count(value, ":") > 1 {
		index := strings.LastIndex(value, ":")
		host, portText, ok = value[:index], value[index+1:], true
	}
	if !ok {
		return "", 0, errors.New("missing port")
	}
	port, err := strconv.Atoi(firstNumber(portText))
	return strings.Trim(host, "[]"), port, err
}

func firstNumber(value string) string {
	re := regexp.MustCompile(`\d+`)
	match := re.FindString(value)
	if match == "" {
		return "0"
	}
	return match
}

func firstIntFromString(value string) int {
	number, _ := strconv.Atoi(firstNumber(value))
	return number
}

func parseBool(value string, fallback bool) bool {
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func splitCSV(value string) []any {
	value = strings.Trim(value, "{}")
	parts := strings.Split(value, ",")
	out := make([]any, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" && value != "<nil>" {
			return value
		}
	}
	return ""
}

func fragment(u *url.URL) string {
	return urlDecode(u.Fragment)
}

func urlDecode(value string) string {
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func getString(m map[string]any, key, fallback string) string {
	if value, ok := m[key]; ok && value != nil {
		text := fmt.Sprint(value)
		if text != "" && text != "<nil>" {
			return text
		}
	}
	return fallback
}

func asString(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func addIfPresent(target map[string]any, key string, value any) {
	if value == nil {
		return
	}
	switch typed := value.(type) {
	case string:
		typed = strings.TrimSpace(typed)
		if typed == "" {
			return
		}
		if regexp.MustCompile(`^-?\d+$`).MatchString(typed) {
			number, _ := strconv.Atoi(typed)
			target[key] = number
		} else {
			target[key] = typed
		}
	case json.Number:
		if number, err := typed.Int64(); err == nil {
			target[key] = number
		} else {
			target[key] = typed.String()
		}
	default:
		target[key] = typed
	}
}

func stringSlice(value any) []string {
	switch typed := value.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

func copyStringMap(input map[string]string) map[string]string {
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func cloneMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = cloneValue(value)
	}
	return out
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneValue(item)
		}
		return out
	default:
		return typed
	}
}

func removeNilEmpty(input map[string]any) map[string]any {
	for key, value := range input {
		if value == nil || value == "" {
			delete(input, key)
		}
	}
	return input
}
