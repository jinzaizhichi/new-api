package gemini

import (
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
	if oauthType == "code_assist" || effectiveID == BuiltinOAuthClientID {
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

	return oauthInfo.AccessToken, nil
}