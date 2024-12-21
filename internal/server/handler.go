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

package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/meloncoffee/melon_agent/config"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metricsHandler prometheus 메트릭 제공 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
func metricsHandler(c *gin.Context) {
	promhttp.Handler().ServeHTTP(c.Writer, c.Request)
}

// healthHandler 헬스 체크 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
func healthHandler(c *gin.Context) {
	c.AbortWithStatus(http.StatusOK)
}

// sysStatsHandler 서버 상태 정보 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
func sysStatsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, servStats.Data())
}

// versionHandler 버전 정보 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
func versionHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"source":  "https://github.com/meloncoffee/melon_agent",
		"version": config.Version,
	})
}

// rootHandler 루트 경로 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
func rootHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"text": "Welcome to melon_agent.",
	})
}

// genJWTToken JWT 토큰 생성
//
// Parameters:
//   - username: JWT 토큰 생성 ID
//
// Returns:
//   - string: JWT 토큰
//   - error: 성공(nil), 실패(error)
func genJWTToken(username string) (string, error) {
	// JWT Claims 생성
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}

	// JWT 토큰 생성
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if token == nil {
		return "", fmt.Errorf("failed to generate JWT token")
	}
	return token.SignedString(jwtSecretKey)
}

// loginHandler 로그인 핸들러
//
// Parameters:
//   - c: HTTP 요청 및 응답과 관련된 정보를 포함하는 객체
func loginHandler(c *gin.Context) {
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
	token, err := genJWTToken(req.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// JWT 토큰 반환
	c.JSON(http.StatusOK, gin.H{"token": token})
}
