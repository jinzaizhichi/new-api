package controller

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relay/channel/gemini"

	"github.com/gin-gonic/gin"
)

// ============================================
// Gemini OAuth Admin API
// ============================================

type GeminiOAuthAuthURLRequest struct {
	ChannelID   int    `json:"channel_id" binding:"required"`
	RedirectURI string `json:"redirect_uri"`
	OAuthType   string `json:"oauth_type"` // "ai_studio" 或 "code_assist"，默认 "ai_studio"
}

// GenerateGeminiOAuthURL 生成 Gemini OAuth 授权 URL
// POST /api/channel/gemini/oauth/auth-url
func GenerateGeminiOAuthURL(c *gin.Context) {
	var req GeminiOAuthAuthURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	// 获取 channel
	channel, err := model.GetChannelById(req.ChannelID, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "渠道不存在: " + err.Error(),
		})
		return
	}

	// 如果未指定 redirect_uri，自动构造
	redirectURI := req.RedirectURI
	if redirectURI == "" {
		scheme := "https"
		if c.Request.TLS == nil {
			if xfProto := c.GetHeader("X-Forwarded-Proto"); xfProto != "" {
				scheme = xfProto
			}
		}
		redirectURI = scheme + "://" + c.Request.Host + "/auth/callback"
	}

	// 从渠道 other_info 读取自定义 OAuth 凭据（可选）
	otherInfo := channel.GetOtherInfo()
	var clientID, clientSecret string
	if oauthCfg, ok := otherInfo["gemini_oauth_config"].(map[string]interface{}); ok {
		if v, ok := oauthCfg["client_id"].(string); ok {
			clientID = v
		}
		if v, ok := oauthCfg["client_secret"].(string); ok {
			clientSecret = v
		}
	}

	oauthType := req.OAuthType
	if oauthType == "" {
		oauthType = "ai_studio"
	}

	result, err := gemini.BuildGeminiAuthURL(clientID, clientSecret, redirectURI, oauthType)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "生成授权 URL 失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}

type GeminiOAuthExchangeRequest struct {
	ChannelID int    `json:"channel_id" binding:"required"`
	SessionID string `json:"session_id" binding:"required"`
	State     string `json:"state" binding:"required"`
	Code      string `json:"code" binding:"required"`
}

// ExchangeGeminiOAuthCode 交换授权码并保存到渠道
// POST /api/channel/gemini/oauth/exchange
func ExchangeGeminiOAuthCode(c *gin.Context) {
	var req GeminiOAuthExchangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	// 交换 code 获取 token
	oauthInfo, err := gemini.ExchangeGeminiCode(req.SessionID, req.State, req.Code)
	if err != nil {
		common.SysError(fmt.Sprintf("Gemini OAuth code 交换失败: %v", err))
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "OAuth 授权失败: " + err.Error(),
		})
		return
	}

	// 获取渠道
	channel, err := model.GetChannelById(req.ChannelID, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "渠道不存在: " + err.Error(),
		})
		return
	}

	// 保存 OAuth 信息到渠道
	if err := gemini.SaveOAuthInfoToChannel(channel, oauthInfo); err != nil {
		common.SysError(fmt.Sprintf("保存 Gemini OAuth 信息失败: %v", err))
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "保存 OAuth 配置失败: " + err.Error(),
		})
		return
	}

	// 返回 token 信息（access_token 脱敏）
	expiresAt := time.Unix(oauthInfo.TokenExpiresAt, 0).Format(time.RFC3339)
	maskedToken := ""
	if len(oauthInfo.AccessToken) > 12 {
		maskedToken = oauthInfo.AccessToken[:6] + "..." + oauthInfo.AccessToken[len(oauthInfo.AccessToken)-6:]
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Gemini OAuth 配置成功",
		"data": gin.H{
			"access_token":    maskedToken,
			"token_expires_at": expiresAt,
			"oauth_type":      oauthInfo.OAuthType,
		},
	})
}

type GeminiOAuthStatusResponse struct {
	Configured       bool   `json:"configured"`
	OAuthType         string `json:"oauth_type,omitempty"`
	TokenExpiresAt   string `json:"token_expires_at,omitempty"`
	TokenIsExpired   bool   `json:"token_is_expired"`
	MinutesRemaining int64  `json:"minutes_remaining,omitempty"`
}

// GetGeminiOAuthStatus 查询渠道 OAuth 状态
// GET /api/channel/gemini/oauth/status
func GetGeminiOAuthStatus(c *gin.Context) {
	channelIDStr := c.Query("channel_id")
	if channelIDStr == "" {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "缺少 channel_id 参数",
		})
		return
	}

	channelID, err := strconv.Atoi(channelIDStr)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "channel_id 格式错误",
		})
		return
	}

	channel, err := model.GetChannelById(channelID, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "渠道不存在",
		})
		return
	}

	oauthInfo := gemini.GetOAuthInfoFromChannel(channel)
	if oauthInfo == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": GeminiOAuthStatusResponse{
				Configured: false,
			},
		})
		return
	}

	nowUnix := time.Now().Unix()
	tokenIsExpired := nowUnix >= oauthInfo.TokenExpiresAt
	minutesRemaining := (oauthInfo.TokenExpiresAt - nowUnix) / 60
	if minutesRemaining < 0 {
		minutesRemaining = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": GeminiOAuthStatusResponse{
			Configured:       true,
			OAuthType:         oauthInfo.OAuthType,
			TokenExpiresAt:   time.Unix(oauthInfo.TokenExpiresAt, 0).Format(time.RFC3339),
			TokenIsExpired:   tokenIsExpired,
			MinutesRemaining: minutesRemaining,
		},
	})
}

// ForceRefreshGeminiOAuth 强制刷新 OAuth token
// POST /api/channel/gemini/oauth/refresh
func ForceRefreshGeminiOAuth(c *gin.Context) {
	var req struct {
		ChannelID int `json:"channel_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	channel, err := model.GetChannelById(req.ChannelID, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "渠道不存在",
		})
		return
	}

	oauthInfo := gemini.GetOAuthInfoFromChannel(channel)
	if oauthInfo == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "该渠道未配置 Gemini OAuth",
		})
		return
	}

	if err := gemini.RefreshGeminiToken(oauthInfo); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "token 刷新失败: " + err.Error(),
		})
		return
	}

	if err := gemini.SaveOAuthInfoToChannel(channel, oauthInfo); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "保存 token 失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "token 已刷新",
		"data": gin.H{
			"token_expires_at": time.Unix(oauthInfo.TokenExpiresAt, 0).Format(time.RFC3339),
		},
	})
}

// SetGeminiOAuthConfig 设置渠道的 OAuth 客户端配置
// POST /api/channel/gemini/oauth/config
func SetGeminiOAuthConfig(c *gin.Context) {
	var req struct {
		ChannelID    int    `json:"channel_id" binding:"required"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	channel, err := model.GetChannelById(req.ChannelID, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "渠道不存在",
		})
		return
	}

	otherInfo := channel.GetOtherInfo()
	if otherInfo == nil {
		otherInfo = make(map[string]interface{})
	}

	otherInfo["gemini_oauth_config"] = map[string]interface{}{
		"client_id":     req.ClientID,
		"client_secret": req.ClientSecret,
	}

	channel.SetOtherInfo(otherInfo)
	if err := channel.UpdateOtherInfo(); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "OAuth 客户端配置已保存",
	})
}

