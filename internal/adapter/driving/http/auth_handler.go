package http

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

// AuthHandler serves sign-up, sign-in, token refresh, sign-out, and the
// signed-in user's account and audit history.
type AuthHandler struct {
	auth port.AuthService
}

func NewAuthHandler(auth port.AuthService) *AuthHandler {
	return &AuthHandler{auth: auth}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req registerRequest
	if !bindJSON(c, &req) {
		return
	}
	res, err := h.auth.Register(c.Request.Context(), port.RegisterCommand{
		Email: req.Email, Password: req.Password, DisplayName: req.DisplayName, Client: clientInfo(c),
	})
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, toAuthResponse(res))
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if !bindJSON(c, &req) {
		return
	}
	res, err := h.auth.Login(c.Request.Context(), port.LoginCommand{
		Email: req.Email, Password: req.Password, Client: clientInfo(c),
	})
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, toAuthResponse(res))
}

func (h *AuthHandler) Google(c *gin.Context) {
	var req googleRequest
	if !bindJSON(c, &req) {
		return
	}
	res, err := h.auth.LoginWithGoogle(c.Request.Context(), port.GoogleLoginCommand{
		IDToken: req.IDToken, Client: clientInfo(c),
	})
	if err != nil {
		respondError(c, err)
		return
	}
	status := http.StatusOK
	if res.Created {
		status = http.StatusCreated
	}
	c.JSON(status, toAuthResponse(res))
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req refreshRequest
	if !bindJSON(c, &req) {
		return
	}
	tokens, err := h.auth.Refresh(c.Request.Context(), req.RefreshToken, clientInfo(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, toTokensResponse(tokens))
}

func (h *AuthHandler) Logout(c *gin.Context) {
	p, _ := principalFrom(c)
	if err := h.auth.Logout(c.Request.Context(), p, clientInfo(c)); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) LogoutAll(c *gin.Context) {
	p, _ := principalFrom(c)
	if err := h.auth.LogoutAll(c.Request.Context(), p, clientInfo(c)); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) Me(c *gin.Context) {
	user, err := h.auth.Me(c.Request.Context(), authorID(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, toUserResponse(user))
}

func (h *AuthHandler) UpdateMe(c *gin.Context) {
	var req updateMeRequest
	if !bindJSON(c, &req) {
		return
	}
	user, err := h.auth.UpdateProfile(c.Request.Context(), authorID(c), req.DisplayName)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, toUserResponse(user))
}

func (h *AuthHandler) DeleteMe(c *gin.Context) {
	var req deleteAccountRequest
	if !bindJSON(c, &req) {
		return
	}
	p, _ := principalFrom(c)
	err := h.auth.DeleteAccount(c.Request.Context(), port.DeleteAccountCommand{
		Principal: p, Password: req.Password, GoogleIDToken: req.GoogleIDToken, Client: clientInfo(c),
	})
	if err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) Sessions(c *gin.Context) {
	p, _ := principalFrom(c)
	sessions, err := h.auth.Sessions(c.Request.Context(), p.UserID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": toSessionResponses(sessions, p.SessionID)})
}

func (h *AuthHandler) AuditEvents(c *gin.Context) {
	events, err := h.auth.AuditTrail(c.Request.Context(), authorID(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": toAuditResponses(events)})
}

// bindJSON decodes the body or answers 400. A too-large body (rejected by
// limitBody) surfaces here as a decode error too.
func bindJSON(c *gin.Context, dst any) bool {
	if err := c.ShouldBindJSON(dst); err != nil {
		respondError(c, domain.ValidationError{Field: "body", Reason: "is missing a required field or is not valid JSON"})
		return false
	}
	return true
}
