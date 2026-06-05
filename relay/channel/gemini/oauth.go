package gemini

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

// ============================================
// Gemini OAuth 常量
// ============================================

const (
	GoogleAuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
	GoogleTokenURL     = "https://oauth2.googleapis.com/token"

	// AI Studio 默认 scopes（使用 generative-language.retriever）
	DefaultAIStudioScopes = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/generative-language.retriever"

	// 内置 Gemini CLI OAuth 客户端凭据的环境变量名
	// 设置后可使用 Google 公开 Gemini CLI OAuth 客户端，不设则必须提供自定义 OAuth 凭据
	EnvBuiltinOAuthClientID     = "GEMINI_CLI_OAUTH_CLIENT_ID"
	EnvBuiltinOAuthClientSecret = "GEMINI_CLI_OAUTH_CLIENT_SECRET"

	OAuthSessionTTL = 30 * time.Minute

	// Token 提前刷新时间（过期前 5 分钟）
	TokenRefreshMargin = 5 * time.Minute

	// Code Assist API 端点
	CodeAssistBaseURL = "https://cloudcode-pa.googleapis.com"

	// Gemini CLI User-Agent 模拟 Gemini CLI 请求头，确保与内部端点的兼容性
	GeminiCLIUserAgent = "GeminiCLI/0.1.5 (Windows; AMD64)"
)

// GeminiOAuthInfo 存储在 channel.other_info 中的 OAuth 配置
type GeminiOAuthInfo struct {
	OAuthType      string `json:"oauth_type"` // "ai_studio" 或 "code_assist"
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	RefreshToken   string `json:"refresh_token"`
	AccessToken    string `json:"access_token"`
	TokenExpiresAt int64  `json:"token_expires_at"` // Unix 时间戳
	Scope          string `json:"scope"`
	ProjectID      string `json:"project_id,omitempty"` // Code Assist 项目的 GCP project_id
	TierID         string `json:"tier_id,omitempty"`    // Code Assist 订阅 tier ID
}

// IsCodeAssist 判断是否使用 Code Assist 端点
func (o *GeminiOAuthInfo) IsCodeAssist() bool {
	return o != nil && o.OAuthType == "code_assist" && o.ProjectID != ""
}

// ============================================
// Code Assist LoadCodeAssist / OnboardUser 类型
// ============================================

type CodeAssistMetadata struct {
	IDEType    string `json:"ideType"`
	Platform   string `json:"platform"`
	PluginType string `json:"pluginType"`
}

type LoadCodeAssistRequest struct {
	Metadata CodeAssistMetadata `json:"metadata"`
}

type TierInfo struct {
	ID string `json:"id"`
}

// UnmarshalJSON 兼容字符串和对象两种 tier 格式
func (t *TierInfo) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var id string
		if err := json.Unmarshal(data, &id); err != nil {
			return err
		}
		t.ID = id
		return nil
	}
	type alias TierInfo
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*t = TierInfo(decoded)
	return nil
}

type LoadCodeAssistResponse struct {
	CurrentTier             *TierInfo `json:"currentTier,omitempty"`
	PaidTier                *TierInfo `json:"paidTier,omitempty"`
	CloudAICompanionProject string    `json:"cloudaicompanionProject,omitempty"`
	AllowedTiers            []struct {
		ID        string `json:"id"`
		IsDefault bool   `json:"isDefault,omitempty"`
	} `json:"allowedTiers,omitempty"`
}

// GetTier 提取 tier ID，优先使用 paidTier
func (r *LoadCodeAssistResponse) GetTier() string {
	if r.PaidTier != nil && r.PaidTier.ID != "" {
		return r.PaidTier.ID
	}
	if r.CurrentTier != nil {
		return r.CurrentTier.ID
	}
	return ""
}

type OnboardUserRequest struct {
	TierID   string             `json:"tierId"`
	Metadata CodeAssistMetadata `json:"metadata"`
}

type OnboardUserResponse struct {
	Done     bool   `json:"done"`
	Name     string `json:"name,omitempty"`
	Response *struct {
		CloudAICompanionProject any `json:"cloudaicompanionProject,omitempty"`
	} `json:"response,omitempty"`
}

// OAuthSession 浏览器授权流程中的临时会话
type OAuthSession struct {
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	OAuthType    string `json:"oauth_type"`
	Scopes       string `json:"scopes"`
	CreatedAt    int64  `json:"created_at"`
}

// OAuthAuthURLResponse 授权 URL 响应
type OAuthAuthURLResponse struct {
	AuthURL    string `json:"auth_url"`
	SessionID  string `json:"session_id"`
	ExpiresAt  int64  `json:"expires_at"`
	RedirectURI string `json:"redirect_uri"`
}

// ============================================
// OAuth 会话存储（内存）
// ============================================

var (
	oauthSessionStore = &sessionStore{
		sessions: make(map[string]*OAuthSession),
	}
)

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*OAuthSession
}

func (s *sessionStore) Set(id string, session *OAuthSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = session
}

func (s *sessionStore) Get(id string) (*OAuthSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	if time.Now().Unix()-sess.CreatedAt > int64(OAuthSessionTTL.Seconds()) {
		delete(s.sessions, id)
		return nil, false
	}
	return sess, true
}

func (s *sessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// ============================================
// PKCE 工具函数
// ============================================

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func generateState() (string, error) {
	bytes, err := generateRandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64URLEncode(bytes), nil
}

func generateSessionID() (string, error) {
	bytes, err := generateRandomBytes(16)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}

func generateCodeVerifier() (string, error) {
	bytes, err := generateRandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64URLEncode(bytes), nil
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64URLEncode(hash[:])
}

// ============================================
// OAuth 授权 URL 生成
// ============================================

func BuildGeminiAuthURL(clientID, clientSecret, redirectURI, oauthType string) (*OAuthAuthURLResponse, error) {
	// 解析有效 OAuth 配置
	effectiveID := strings.TrimSpace(clientID)
	effectiveSecret := strings.TrimSpace(clientSecret)

	if effectiveID == "" || effectiveSecret == "" {
		// 尝试使用内置 Gemini CLI OAuth 客户端（从环境变量读取）
		effectiveID = os.Getenv(EnvBuiltinOAuthClientID)
		effectiveSecret = os.Getenv(EnvBuiltinOAuthClientSecret)
		if effectiveID == "" || effectiveSecret == "" {
			return nil, fmt.Errorf("未配置 OAuth 客户端凭据，请设置 %s 和 %s 环境变量，或通过 API 提供自定义 client_id/client_secret", EnvBuiltinOAuthClientID, EnvBuiltinOAuthClientSecret)
		}
		// 内置客户端不支持 ai_studio scopes，强制用 code_assist scopes
		if oauthType == "ai_studio" {
			oauthType = "code_assist"
		}
	}

	scopes := DefaultAIStudioScopes
	if oauthType == "code_assist" {
		scopes = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"
	}

	state, err := generateState()
	if err != nil {
		return nil, fmt.Errorf("生成 state 失败: %w", err)
	}

	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("生成 code_verifier 失败: %w", err)
	}
	codeChallenge := generateCodeChallenge(codeVerifier)

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("生成 session ID 失败: %w", err)
	}

	// 存储会话
	oauthSessionStore.Set(sessionID, &OAuthSession{
		State:        state,
		CodeVerifier: codeVerifier,
		RedirectURI:  redirectURI,
		ClientID:     effectiveID,
		ClientSecret: effectiveSecret,
		OAuthType:    oauthType,
		Scopes:       scopes,
		CreatedAt:    time.Now().Unix(),
	})

	// 构建 Google OAuth URL
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", effectiveID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scopes)
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	params.Set("access_type", "offline")
	params.Set("prompt", "consent")

	authURL := fmt.Sprintf("%s?%s", GoogleAuthorizeURL, params.Encode())

	expiresAt := time.Now().Add(OAuthSessionTTL).Unix()

	return &OAuthAuthURLResponse{
		AuthURL:     authURL,
		SessionID:   sessionID,
		ExpiresAt:   expiresAt,
		RedirectURI: redirectURI,
	}, nil
}

// ============================================
// OAuth Token 交换（authorization_code → access_token + refresh_token）
// ============================================

func ExchangeGeminiCode(sessionID, state, code string) (*GeminiOAuthInfo, error) {
	sess, ok := oauthSessionStore.Get(sessionID)
	if !ok {
		return nil, fmt.Errorf("OAuth 会话已过期或不存在，请重新发起授权")
	}

	if sess.State != state {
		return nil, fmt.Errorf("state 不匹配，可能存在 CSRF 攻击")
	}

	tokenResp, err := exchangeCodeForToken(sess.ClientID, sess.ClientSecret, code, sess.CodeVerifier, sess.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("token 交换失败: %w", err)
	}

	oauthSessionStore.Delete(sessionID)

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix()

	return &GeminiOAuthInfo{
		OAuthType:      sess.OAuthType,
		ClientID:       sess.ClientID,
		ClientSecret:   sess.ClientSecret,
		RefreshToken:   tokenResp.RefreshToken,
		AccessToken:    tokenResp.AccessToken,
		TokenExpiresAt: expiresAt,
		Scope:          tokenResp.Scope,
	}, nil
}

type googleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func exchangeCodeForToken(clientID, clientSecret, code, codeVerifier, redirectURI string) (*googleTokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("code_verifier", codeVerifier)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequest("POST", GoogleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp googleTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w, body: %s", err, string(body))
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("Google 返回错误: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("access_token 为空")
	}

	return &tokenResp, nil
}

// ============================================
// OAuth Token 刷新
// ============================================

func RefreshGeminiToken(oauthInfo *GeminiOAuthInfo) error {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", oauthInfo.RefreshToken)
	data.Set("client_id", oauthInfo.ClientID)
	data.Set("client_secret", oauthInfo.ClientSecret)

	req, err := http.NewRequest("POST", GoogleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("token 刷新请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var tokenResp googleTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("解析刷新响应失败: %w, body: %s", err, string(body))
	}

	if tokenResp.Error != "" {
		return fmt.Errorf("刷新 token 失败: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	if tokenResp.AccessToken == "" {
		return fmt.Errorf("刷新后 access_token 为空")
	}

	oauthInfo.AccessToken = tokenResp.AccessToken
	oauthInfo.TokenExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix()

	// 如果返回了新的 refresh_token，也更新
	if tokenResp.RefreshToken != "" {
		oauthInfo.RefreshToken = tokenResp.RefreshToken
	}

	common.SysLog(fmt.Sprintf("Gemini OAuth token 已刷新，%d 秒后过期", tokenResp.ExpiresIn))
	return nil
}

// ============================================
// 从 Channel 读取/写入 OAuth 信息
// ============================================

func GetOAuthInfoFromChannel(channel *model.Channel) *GeminiOAuthInfo {
	otherInfo := channel.GetOtherInfo()
	if otherInfo == nil {
		return nil
	}

	oauthData, ok := otherInfo["gemini_oauth"]
	if !ok {
		return nil
	}

	// otherInfo 中的值可能是 map[string]interface{}，需要重新 marshal/unmarshal
	jsonBytes, err := json.Marshal(oauthData)
	if err != nil {
		return nil
	}

	var oauthInfo GeminiOAuthInfo
	if err := json.Unmarshal(jsonBytes, &oauthInfo); err != nil {
		return nil
	}

	// 必须要有 refresh_token
	if oauthInfo.RefreshToken == "" {
		return nil
	}

	return &oauthInfo
}

func SaveOAuthInfoToChannel(channel *model.Channel, oauthInfo *GeminiOAuthInfo) error {
	otherInfo := channel.GetOtherInfo()
	if otherInfo == nil {
		otherInfo = make(map[string]interface{})
	}

	otherInfo["gemini_oauth"] = oauthInfo

	channel.SetOtherInfo(otherInfo)
	return channel.UpdateOtherInfo()
}

// GetOrRefreshAccessToken 获取有效的 access_token，必要时自动刷新
// 返回 access_token 和 error
func GetOrRefreshAccessToken(channel *model.Channel) (string, error) {
	oauthInfo := GetOAuthInfoFromChannel(channel)
	if oauthInfo == nil {
		return "", fmt.Errorf("channel %d 未配置 Gemini OAuth", channel.Id)
	}

	// 检查是否即将过期（提前 5 分钟刷新）
	needRefresh := time.Now().Unix()+int64(TokenRefreshMargin.Seconds()) >= oauthInfo.TokenExpiresAt

	if needRefresh {
		ctx := fmt.Sprintf("channel=%d", channel.Id)
		common.SysLog(fmt.Sprintf("Gemini OAuth token 即将过期，刷新中... %s", ctx))

		if err := RefreshGeminiToken(oauthInfo); err != nil {
			common.SysError(fmt.Sprintf("刷新 Gemini OAuth token 失败 %s: %v", ctx, err))
			// 如果刷新失败且旧 token 仍然有效，继续使用旧 token
			if time.Now().Unix() >= oauthInfo.TokenExpiresAt {
				return "", fmt.Errorf("token 已过期且刷新失败: %w", err)
			}
			common.SysLog(fmt.Sprintf("token 刷新失败但旧 token 未过期，继续使用旧 token %s", ctx))
			return oauthInfo.AccessToken, nil
		}

		// 更新到数据库
		if err := SaveOAuthInfoToChannel(channel, oauthInfo); err != nil {
			common.SysError(fmt.Sprintf("保存刷新后的 OAuth token 失败 %s: %v", ctx, err))
			// token 已刷新成功，但保存失败，仍可使用新 token（下次会再刷新）
		}
	}

	// Code Assist 模式自动获取 project_id（懒加载：首次 API 调用时触发）
	if oauthInfo.OAuthType == "code_assist" && oauthInfo.ProjectID == "" {
		ctx := fmt.Sprintf("channel=%d", channel.Id)
		common.SysLog(fmt.Sprintf("Code Assist project_id 为空，尝试自动获取... %s", ctx))
		projectID, tierID, err := FetchProjectID(oauthInfo.AccessToken)
		if err == nil && projectID != "" {
			oauthInfo.ProjectID = projectID
			oauthInfo.TierID = tierID
			if saveErr := SaveOAuthInfoToChannel(channel, oauthInfo); saveErr != nil {
				common.SysError(fmt.Sprintf("保存 Code Assist project_id 失败 %s: %v", ctx, saveErr))
			} else {
				common.SysLog(fmt.Sprintf("Code Assist project_id 已获取: %s, tier: %s %s", projectID, tierID, ctx))
			}
		} else {
			common.SysLog(fmt.Sprintf("Code Assist project_id 自动获取失败 %s: %v", ctx, err))
		}
	}

	return oauthInfo.AccessToken, nil
}

// ============================================
// Code Assist: LoadCodeAssist / OnboardUser / FetchProjectID
// ============================================

// defaultCodeAssistMetadata 返回默认的 Code Assist 元数据
func defaultCodeAssistMetadata() CodeAssistMetadata {
	return CodeAssistMetadata{
		IDEType:    "ANTIGRAVITY",
		Platform:   "PLATFORM_UNSPECIFIED",
		PluginType: "GEMINI",
	}
}

// callCodeAssistAPI 调用 Code Assist 内部 API 的通用方法
func callCodeAssistAPI(accessToken, path string, reqBody any, result any) error {
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("序列化请求体失败: %w", err)
	}

	req, err := http.NewRequest("POST", CodeAssistBaseURL+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", GeminiCLIUserAgent)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// 截断错误响应体用于日志
		sanitized := string(respBody)
		if len(sanitized) > 500 {
			sanitized = sanitized[:500] + "..."
		}
		return fmt.Errorf("Code Assist API 返回错误 (status=%d): %s", resp.StatusCode, sanitized)
	}

	if err := json.Unmarshal(respBody, result); err != nil {
		return fmt.Errorf("解析响应失败: %w, body: %s", err, string(respBody))
	}

	return nil
}

// LoadCodeAssist 获取 Code Assist 的用户 tier 和项目信息
func LoadCodeAssist(accessToken string) (*LoadCodeAssistResponse, error) {
	req := &LoadCodeAssistRequest{Metadata: defaultCodeAssistMetadata()}
	var result LoadCodeAssistResponse
	if err := callCodeAssistAPI(accessToken, "/v1internal:loadCodeAssist", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// OnboardUser 为新用户注册 Code Assist 并获取 project_id
func OnboardUser(accessToken, tierID string) (*OnboardUserResponse, error) {
	if tierID == "" {
		tierID = "LEGACY"
	}
	req := &OnboardUserRequest{
		TierID:   tierID,
		Metadata: defaultCodeAssistMetadata(),
	}
	var result OnboardUserResponse
	if err := callCodeAssistAPI(accessToken, "/v1internal:onboardUser", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// FetchProjectID 获取 Code Assist 所需的 GCP project_id
// 流程：LoadCodeAssist → 如果没返回 project_id 则 OnboardUser
func FetchProjectID(accessToken string) (projectID string, tierID string, err error) {
	// 第一步: LoadCodeAssist 获取 tier 和可能的 project_id
	loadResp, loadErr := LoadCodeAssist(accessToken)

	// 提取 tierID
	tierID = "LEGACY"
	if loadResp != nil {
		if tier := loadResp.GetTier(); tier != "" {
			tierID = tier
		}
	}

	// 如果直接返回了 project_id，完成
	if loadErr == nil && loadResp != nil && strings.TrimSpace(loadResp.CloudAICompanionProject) != "" {
		return strings.TrimSpace(loadResp.CloudAICompanionProject), tierID, nil
	}

	// 已注册用户但没有 project_id — 尝试 OnboardUser
	if loadResp != nil && loadResp.GetTier() != "" {
		common.SysLog(fmt.Sprintf("Code Assist 用户已注册(tier=%s)但没有 project_id，尝试 OnboardUser...", tierID))
	}

	// 第二步: OnboardUser（最多重试 5 次）
	const maxAttempts = 5
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, onboardErr := OnboardUser(accessToken, tierID)
		if onboardErr != nil {
			return "", tierID, fmt.Errorf("OnboardUser 失败: %w", onboardErr)
		}
		if resp.Done {
			if resp.Response != nil && resp.Response.CloudAICompanionProject != nil {
				switch v := resp.Response.CloudAICompanionProject.(type) {
				case string:
					return strings.TrimSpace(v), tierID, nil
				case map[string]any:
					if id, ok := v["id"].(string); ok {
						return strings.TrimSpace(id), tierID, nil
					}
				}
			}
			return "", tierID, fmt.Errorf("OnboardUser 完成但未返回 project_id")
		}
		time.Sleep(2 * time.Second)
	}

	return "", tierID, fmt.Errorf("OnboardUser 超时（%d 次尝试后仍未完成）", maxAttempts)
}

// WrappedGeminiRequest Code Assist 包装请求格式
type WrappedGeminiRequest struct {
	Model   string          `json:"model"`
	Project string          `json:"project"`
	Request json.RawMessage `json:"request"`
}