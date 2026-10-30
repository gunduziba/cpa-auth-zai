package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Verified and candidate z.ai endpoints. The login/poll contract is a
// third-party report, not an official integration contract; see
// docs/compatibility.md before changing these.
const (
	apiZaiBase  = "https://api.z.ai"
	zcodeBase   = "https://zcode.z.ai"
	monitorBase = apiZaiBase + "/api/monitor"

	codingChatCompletionsURL = apiZaiBase + "/api/coding/paas/v4/chat/completions"
	codingResponsesURL       = apiZaiBase + "/api/v1/responses"
	codingAnthropicURL       = apiZaiBase + "/api/anthropic/v1/messages"
	codingModelsURL          = apiZaiBase + "/api/coding/paas/v4/models"
	usageDetailURL           = monitorBase + "/token-usage/usage-detail"
	quotaLimitURL            = monitorBase + "/usage/quota/limit"
	businessLoginURL         = apiZaiBase + "/api/auth/z/login"
	customerInfoURL          = apiZaiBase + "/api/biz/customer/getCustomerInfo"
	cliInitURL               = zcodeBase + "/api/v1/oauth/cli/init"
	cliPollURL               = zcodeBase + "/api/v1/oauth/cli/poll/"
)

// storageVersion tags the persisted credential schema in AuthData.StorageJSON.
const storageVersion = 1

// zaiStorage is the provider-owned credential record persisted by CPA. Tokens
// are kept by purpose; the provisioned API key is used for inference.
type zaiStorage struct {
	Version          int    `json:"version"`
	Type             string `json:"type"`
	Provider         string `json:"provider,omitempty"`
	OAuthAccessToken string `json:"oauth_access_token,omitempty"`
	ZcodeJWT         string `json:"zcode_jwt,omitempty"`
	BizAccessToken   string `json:"biz_access_token,omitempty"`
	APIKey           string `json:"api_key,omitempty"`
	Label            string `json:"label,omitempty"`
	Email            string `json:"email,omitempty"`
	UserID           string `json:"user_id,omitempty"`
	OrganizationID   string `json:"organization_id,omitempty"`
	ProjectID        string `json:"project_id,omitempty"`
	ObtainedAt       string `json:"obtained_at,omitempty"`
	ExpiresAt        string `json:"expires_at,omitempty"`
}

type flexStorage struct {
	Version          int    `json:"version"`
	Type             string `json:"type"`
	Provider         string `json:"provider"`
	OAuthAccessToken string `json:"oauth_access_token"`
	ZcodeJWT         string `json:"zcode_jwt"`
	BizAccessToken   string `json:"biz_access_token"`
	APIKey           string `json:"api_key"`
	AltAPIKey        string `json:"apiKey"`
	KebabAPIKey      string `json:"api-key"`
	Label            string `json:"label"`
	Email            string `json:"email"`
	UserID           string `json:"user_id"`
	OrganizationID   string `json:"organization_id"`
	ProjectID        string `json:"project_id"`
	ObtainedAt       string `json:"obtained_at"`
	ExpiresAt        string `json:"expires_at"`
}

// errNoCredentials reports a storage record without usable login tokens.
var errNoCredentials = fmt.Errorf("zai: stored credentials contain no login token")

func parseZaiStorage(raw []byte) (*zaiStorage, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("zai: stored credentials are empty")
	}
	var flex flexStorage
	if errUnmarshal := json.Unmarshal(raw, &flex); errUnmarshal != nil {
		return nil, fmt.Errorf("zai: decode stored credentials: %w", errUnmarshal)
	}

	storageType := strings.TrimSpace(flex.Type)
	if storageType == "" {
		storageType = strings.TrimSpace(flex.Provider)
	}
	if storageType == "" {
		storageType = providerID
	}
	if storageType != providerID {
		return nil, fmt.Errorf("zai: stored credentials have type %q", storageType)
	}

	apiKey := strings.TrimSpace(flex.APIKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(flex.AltAPIKey)
	}
	if apiKey == "" {
		apiKey = strings.TrimSpace(flex.KebabAPIKey)
	}

	version := flex.Version
	if version == 0 {
		version = storageVersion
	}

	storage := zaiStorage{
		Version:          version,
		Type:             providerID,
		OAuthAccessToken: strings.TrimSpace(flex.OAuthAccessToken),
		ZcodeJWT:         strings.TrimSpace(flex.ZcodeJWT),
		BizAccessToken:   strings.TrimSpace(flex.BizAccessToken),
		APIKey:           apiKey,
		Label:            strings.TrimSpace(flex.Label),
		Email:            strings.TrimSpace(flex.Email),
		UserID:           strings.TrimSpace(flex.UserID),
		OrganizationID:   strings.TrimSpace(flex.OrganizationID),
		ProjectID:        strings.TrimSpace(flex.ProjectID),
		ObtainedAt:       strings.TrimSpace(flex.ObtainedAt),
		ExpiresAt:        strings.TrimSpace(flex.ExpiresAt),
	}

	if len(storage.bearerCandidates()) == 0 {
		return nil, errNoCredentials
	}
	return &storage, nil
}

// bearerCandidates lists login-derived tokens in preference order: the short
// lived OAuth session token first, then the durable business token, the Zcode
// JWT, and finally the direct API key.
func (s *zaiStorage) bearerCandidates() []string {
	out := make([]string, 0, 4)
	for _, token := range []string{s.OAuthAccessToken, s.BizAccessToken, s.ZcodeJWT, s.APIKey} {
		token = strings.TrimSpace(token)
		if token != "" {
			out = append(out, token)
		}
	}
	return out
}

func (s *zaiStorage) accountLabel() string {
	if s.Label != "" {
		return s.Label
	}
	if s.Email != "" {
		return s.Email
	}
	if s.UserID != "" {
		return s.UserID
	}
	if key := strings.TrimSpace(s.APIKey); key != "" {
		if len(key) > 8 {
			return "key-" + key[len(key)-6:]
		}
		return "key"
	}
	return ""
}

// authID derives the stable CPA auth identifier for the account.
func (s *zaiStorage) authID() string {
	id := s.accountLabel()
	if id == "" {
		id = "account"
	}
	return providerID + "-" + sanitizeAuthIDSuffix(id)
}

func sanitizeAuthIDSuffix(id string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(id) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}
	out := builder.String()
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	return strings.Trim(out, "-")
}

// resolveStorageByIndex loads the persisted credential record for one CPA auth
// index through the host. Used when the host does not embed storage in the
// request payload (for example quota.fetch).
func resolveStorageByIndex(authIndex string) (*zaiStorage, error) {
	if strings.TrimSpace(authIndex) == "" {
		return nil, errNoCredentials
	}
	result, errGet := callHost("host.auth.get", map[string]string{"auth_index": authIndex})
	if errGet != nil {
		return nil, errGet
	}
	var record struct {
		JSON json.RawMessage `json:"json"`
	}
	if errUnmarshal := json.Unmarshal(result, &record); errUnmarshal != nil {
		return nil, fmt.Errorf("zai: decode auth record: %w", errUnmarshal)
	}
	return parseZaiStorage(record.JSON)
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// encodeQuery builds a query string with stable encoding for upstream calls.
func encodeQuery(params map[string]string) string {
	values := url.Values{}
	for key, value := range params {
		if value != "" {
			values.Set(key, value)
		}
	}
	return values.Encode()
}
