package edgefrp

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/pinksaucepasta/paperboat-tunnel/internal/admission"
	"github.com/pinksaucepasta/paperboat-tunnel/internal/route"
)

type LoginResolver interface {
	ResolveLogin(context.Context, LoginContent) (admission.Request, error)
}

const AdmissionMetadataKey = "paperboat.admission"

type LoginContent struct {
	User         string            `json:"user,omitempty"`
	PrivilegeKey string            `json:"privilege_key,omitempty"`
	RunID        string            `json:"run_id,omitempty"`
	Metas        map[string]string `json:"metas,omitempty"`
	Timestamp    int64             `json:"timestamp,omitempty"`
}

type userInfo struct {
	RunID string `json:"run_id"`
}

type newProxyContent struct {
	User              userInfo          `json:"user"`
	ProxyName         string            `json:"proxy_name,omitempty"`
	ProxyType         string            `json:"proxy_type,omitempty"`
	UseEncryption     bool              `json:"use_encryption,omitempty"`
	UseCompression    bool              `json:"use_compression,omitempty"`
	BandwidthLimit    string            `json:"bandwidth_limit,omitempty"`
	BandwidthMode     string            `json:"bandwidth_limit_mode,omitempty"`
	Group             string            `json:"group,omitempty"`
	GroupKey          string            `json:"group_key,omitempty"`
	Metas             map[string]string `json:"metas,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	RemotePort        int               `json:"remote_port,omitempty"`
	CustomDomains     []string          `json:"custom_domains,omitempty"`
	SubDomain         string            `json:"subdomain,omitempty"`
	Locations         []string          `json:"locations,omitempty"`
	HTTPUser          string            `json:"http_user,omitempty"`
	HTTPPwd           string            `json:"http_pwd,omitempty"`
	HostHeaderRewrite string            `json:"host_header_rewrite,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	ResponseHeaders   map[string]string `json:"response_headers,omitempty"`
	RouteByHTTPUser   string            `json:"route_by_http_user,omitempty"`
	Sk                string            `json:"sk,omitempty"`
	AllowUsers        []string          `json:"allow_users,omitempty"`
	Multiplexer       string            `json:"multiplexer,omitempty"`
}

type runContent struct {
	User         userInfo `json:"user"`
	RunID        string   `json:"run_id,omitempty"`
	ProxyName    string   `json:"proxy_name,omitempty"`
	ProxyType    string   `json:"proxy_type,omitempty"`
	Timestamp    int64    `json:"timestamp,omitempty"`
	PrivilegeKey string   `json:"privilege_key,omitempty"`
}

type trafficContent struct {
	User       userInfo `json:"user"`
	ProxyName  string   `json:"proxy_name"`
	ProxyType  string   `json:"proxy_type"`
	TrafficIn  uint64   `json:"traffic_in"`
	TrafficOut uint64   `json:"traffic_out"`
}

type Policy struct {
	Adapter           *Adapter
	Resolver          LoginResolver
	InternalAuthToken string
}

func (p Policy) SessionKey(ctx context.Context, op string, content json.RawMessage) (string, error) {
	if op != "Login" {
		return "", nil
	}
	var login LoginContent
	if err := json.Unmarshal(content, &login); err != nil {
		return "", route.ErrInvalid
	}
	request, err := p.Resolver.ResolveLogin(ctx, login)
	if err != nil {
		return "", err
	}
	return request.Credential, nil
}

func (p Policy) Handle(ctx context.Context, op string, content json.RawMessage) (json.RawMessage, error) {
	if p.Adapter == nil || p.Resolver == nil || len(p.InternalAuthToken) < 32 {
		return nil, errors.New("frp policy unavailable")
	}
	switch op {
	case "Login":
		var login LoginContent
		if err := json.Unmarshal(content, &login); err != nil || login.PrivilegeKey == "" {
			return nil, route.ErrInvalid
		}
		request, err := p.Resolver.ResolveLogin(ctx, login)
		if err != nil {
			return nil, err
		}
		var response admission.Response
		if login.RunID == "" {
			response, err = p.Adapter.Login(ctx, request)
		} else {
			response, err = p.Adapter.Resume(ctx, request, login.RunID)
			if errors.Is(err, ErrRunUnknown) {
				response, err = p.Adapter.Login(ctx, request)
			}
		}
		if err != nil {
			return nil, err
		}
		var raw map[string]any
		if err := json.Unmarshal(content, &raw); err != nil {
			return nil, err
		}
		raw["run_id"] = response.RunID.Value
		raw["privilege_key"] = internalAuthKey(p.InternalAuthToken, login.Timestamp)
		delete(raw, "metas")
		return json.Marshal(raw)
	case "NewProxy":
		var proxy newProxyContent
		if err := json.Unmarshal(content, &proxy); err != nil {
			return nil, route.ErrInvalid
		}
		if fields := invalidProxyFields(proxy); len(fields) != 0 {
			p.Adapter.Revoke(proxy.User.RunID)
			return nil, proxyShapeError(fields)
		}
		if err := p.Adapter.AuthorizeProxy(proxy.User.RunID, proxy.ProxyName, proxy.ProxyType, proxy.CustomDomains[0], proxy.Group, proxy.GroupKey); err != nil {
			p.Adapter.Revoke(proxy.User.RunID)
			return nil, err
		}
		return content, nil
	case "NewWorkConn", "Ping":
		var event runContent
		if err := json.Unmarshal(content, &event); err != nil {
			return nil, route.ErrInvalid
		}
		if err := p.Adapter.AuthorizeProxyRun(event.User.RunID); err != nil {
			return nil, err
		}
		var raw map[string]any
		if err := json.Unmarshal(content, &raw); err != nil {
			return nil, route.ErrInvalid
		}
		raw["privilege_key"] = internalAuthKey(p.InternalAuthToken, event.Timestamp)
		return json.Marshal(raw)
	case "NewUserConn":
		var event runContent
		if err := json.Unmarshal(content, &event); err != nil || event.ProxyType != "http" {
			return nil, route.ErrInvalid
		}
		if err := p.Adapter.AuthorizeStream(event.User.RunID, event.ProxyName, event.ProxyType); err != nil {
			return nil, err
		}
		return content, nil
	case "CloseUserConn":
		var event runContent
		if err := json.Unmarshal(content, &event); err != nil {
			return nil, route.ErrInvalid
		}
		p.Adapter.CloseStream(event.User.RunID, event.ProxyName)
		return content, nil
	case "CloseProxy":
		var event runContent
		if err := json.Unmarshal(content, &event); err != nil {
			return nil, route.ErrInvalid
		}
		p.Adapter.CloseProxy(event.User.RunID, event.ProxyName)
		return content, nil
	case "Traffic":
		var event trafficContent
		if err := json.Unmarshal(content, &event); err != nil {
			return nil, route.ErrInvalid
		}
		if err := p.Adapter.RecordTraffic(event.User.RunID, event.ProxyName, event.ProxyType, event.TrafficIn, event.TrafficOut); err != nil {
			return nil, err
		}
		return content, nil
	default:
		return nil, route.ErrInvalid
	}
}

type proxyShapeError []string

func (e proxyShapeError) Error() string      { return "proxy shape rejected" }
func (e proxyShapeError) SafeReason() string { return "proxy_shape:" + strings.Join(e, ",") }

func invalidProxyFields(proxy newProxyContent) []string {
	var fields []string
	if proxy.ProxyType != "http" {
		fields = append(fields, "type")
	}
	if proxy.ProxyName == "" {
		fields = append(fields, "name")
	}
	if len(proxy.CustomDomains) != 1 || len(proxy.CustomDomains) == 1 && proxy.CustomDomains[0] == "" {
		fields = append(fields, "domains")
	}
	if proxy.UseEncryption {
		fields = append(fields, "encryption")
	}
	if proxy.UseCompression {
		fields = append(fields, "compression")
	}
	if proxy.BandwidthLimit != "" {
		fields = append(fields, "bandwidth")
	}
	if proxy.BandwidthMode != "" {
		fields = append(fields, "bandwidth_mode")
	}
	if proxy.Group == "" || proxy.GroupKey == "" {
		fields = append(fields, "group")
	}
	if len(proxy.Metas) != 0 {
		fields = append(fields, "metas")
	}
	if len(proxy.Annotations) != 0 {
		fields = append(fields, "annotations")
	}
	if proxy.RemotePort != 0 {
		fields = append(fields, "remote_port")
	}
	if proxy.SubDomain != "" {
		fields = append(fields, "subdomain")
	}
	if len(proxy.Locations) != 0 {
		fields = append(fields, "locations")
	}
	if proxy.HTTPUser != "" || proxy.HTTPPwd != "" {
		fields = append(fields, "http_auth")
	}
	if proxy.HostHeaderRewrite != "" {
		fields = append(fields, "host_rewrite")
	}
	if len(proxy.Headers) != 0 || len(proxy.ResponseHeaders) != 0 {
		fields = append(fields, "headers")
	}
	if proxy.RouteByHTTPUser != "" {
		fields = append(fields, "route_user")
	}
	if proxy.Sk != "" || len(proxy.AllowUsers) != 0 {
		fields = append(fields, "visitor")
	}
	if proxy.Multiplexer != "" {
		fields = append(fields, "multiplexer")
	}
	return fields
}

func NewInternalAuthToken() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

// frp v0.70.0 requires this legacy digest for its built-in verifier. It only
// authenticates the private plugin-to-frps bridge; Paperboat admission remains
// the authoritative Ed25519 decision.
func internalAuthKey(token string, timestamp int64) string {
	digest := md5.Sum([]byte(token + strconv.FormatInt(timestamp, 10)))
	return hex.EncodeToString(digest[:])
}
