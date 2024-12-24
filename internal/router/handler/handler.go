// Copyright 2024 Melon Project Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package handler

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/meloncoffee/melon_agent/config"
	"github.com/meloncoffee/melon_agent/internal/auth"
	"github.com/meloncoffee/melon_agent/internal/logger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/thoas/stats"
)

var (
	adminMu sync.Mutex
)

// MetricsHandler prometheus 메트릭 제공 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
func MetricsHandler(c *gin.Context) {
	promhttp.Handler().ServeHTTP(c.Writer, c.Request)
}

// HealthHandler 헬스 체크 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
func HealthHandler(c *gin.Context) {
	c.AbortWithStatus(http.StatusOK)
}

// SysStatsHandler 서버 상태 정보 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
//   - servStats: 요청 및 응답 통계 정보 구조체
func SysStatsHandler(c *gin.Context, servStats *stats.Stats) {
	c.JSON(http.StatusOK, servStats.Data())
}

// VersionHandler 버전 정보 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
func VersionHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"source":  "https://github.com/meloncoffee/melon_agent",
		"version": config.Version,
	})
}

// RootHandler 루트 경로 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
func RootHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"text": "Welcome to melon_agent.",
	})
}

// LoginHandler 로그인 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
//   - jwtSecretKey: JWT 토큰 서명 Secret Key
func LoginHandler(c *gin.Context, jwtSecretKey string) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// 요청 바디에서 JSON 바인딩
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// ID/PW 검증
	// TODO: 수정
	if req.Username != "user" || req.Password != "12345" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// JWT 토큰 생성
	token, err := auth.GenJWTToken(req.Username, jwtSecretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// JWT 토큰 반환
	c.JSON(http.StatusOK, gin.H{"token": token})
}

// RegisterAdminHandler 관리자 계정 등록 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
func RegisterAdminHandler(c *gin.Context, admin *auth.Account) {
	adminMu.Lock()
	defer adminMu.Unlock()

	var reqAdmin auth.Account

	// Content-Type 검증
	if c.GetHeader("Content-Type") != "application/json" {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "Unsupported Content-Type"})
		return
	}

	// 이미 admin ID/PW가 존재한다면, 새로 등록하지 않음
	if admin.ID != "" && admin.PW != "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin account already registered exists"})
		return
	}

	// 요청 바디에서 JSON 바인딩
	if err := c.ShouldBindJSON(&reqAdmin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// ID/PW가 정상적으로 파싱되었는지 확인
	if reqAdmin.ID == "" || reqAdmin.PW == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid admin id/pw"})
		return
	}

	// Admin 계정 정보 저장
	admin.ID = reqAdmin.ID
	admin.PW = reqAdmin.PW

	go func(id, pw string) {
		// 관리자 계정 정보를 암호화하여 파일에 저장
		err := auth.EncryptAdminAccountToFile(config.AdminAccountPath, id, pw)
		if err != nil {
			logger.Log.LogError("%v", err)
		}
	}(admin.ID, admin.PW)

	c.JSON(http.StatusOK, gin.H{"success": "Admin account registration was successful"})
}
