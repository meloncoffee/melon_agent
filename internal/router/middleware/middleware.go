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

package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/meloncoffee/melon_agent/config"
	"github.com/meloncoffee/melon_agent/internal/logger"
	"github.com/thoas/stats"
)

// GinLoggerMiddleware gin 요청/응답 정보 로깅 미들웨어
//
// Returns:
//   - gin.HandlerFunc: gin 미들웨어
func GinLoggerMiddleware() gin.HandlerFunc {
	// 로깅에서 제외할 경로 설정
	excludePath := map[string]struct{}{
		config.Conf.API.MetricURI: {},
		config.Conf.API.HealthURI: {},
	}

	return func(c *gin.Context) {
		// 요청 시작 시간 획득
		start := time.Now()
		// 요청 경로 획득
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		if raw != "" {
			path = path + "?" + raw
		}

		// 요청 처리
		c.Next()

		// 제외할 경로는 로깅하지 않음
		if _, ok := excludePath[path]; ok {
			return
		}

		// 요청 종료 시간 및 latency 계산
		end := time.Now()
		latency := end.Sub(start)

		// 로그 메시지 설정
		var logMsg string
		if len(c.Errors) > 0 {
			logMsg = c.Errors.String()
		} else {
			logMsg = "Request"
		}
		// 상태 코드 획득
		statusCode := c.Writer.Status()
		// 요청 메서드 획득
		method := c.Request.Method
		// 요청 클라이언트 IP 획득
		clientIP := c.ClientIP()
		// 사용자 에이전트 획득
		userAgent := c.Request.UserAgent()
		// 응답 바디 사이즈 획득
		resBodySize := c.Writer.Size()

		// 로그 출력 (상태 코드에 따른 로그 레벨 설정)
		if statusCode >= 500 {
			logger.Log.LogError("[%d] %s %s (IP: %s, Latency: %v, UA: %s, ResSize: %d) %s",
				statusCode, method, path, clientIP, latency, userAgent, resBodySize, logMsg)
		} else if statusCode >= 400 {
			logger.Log.LogWarn("[%d] %s %s (IP: %s, Latency: %v, UA: %s, ResSize: %d) %s",
				statusCode, method, path, clientIP, latency, userAgent, resBodySize, logMsg)
		} else {
			logger.Log.LogInfo("[%d] %s %s (IP: %s, Latency: %v, UA: %s, ResSize: %d) %s",
				statusCode, method, path, clientIP, latency, userAgent, resBodySize, logMsg)
		}
	}
}

// VersionMiddleware 버전 정보 미들웨어
//
// Returns:
//   - gin.HandlerFunc: gin 미들웨어
func VersionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-MELON_AGENT-VERSION", config.Version)
		c.Next()
	}
}

// StatMiddleware 요청 통계를 수집하고 기록하는 미들웨어
//
// Returns:
//   - gin.HandlerFunc: gin 미들웨어
//   - servStats: 요청 및 응답 통계 정보 구조체
func StatMiddleware(servStats *stats.Stats) gin.HandlerFunc {
	return func(c *gin.Context) {
		beginning, recorder := servStats.Begin(c.Writer)
		c.Next()
		servStats.End(beginning, stats.WithRecorder(recorder))
	}
}

// SetDefHeaderTypeMiddleware 요청 헤더에 생략된 타입이 있는 경우 기본 값으로 세팅하는 미들웨어
//
// Returns:
//   - gin.HandlerFunc: gin 미들웨어
func SetDefHeaderTypeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Content-Type 헤더 확인
		if c.GetHeader("Content-Type") == "" {
			// Content-Type이 없으면 기본값으로 설정
			c.Request.Header.Set("Content-Type", "application/json")
		}

		c.Next()
	}
}

// JwtMiddleware JWT 미들웨어
//
// Parameters:
//   - jwtSecretKey: JWT 토큰 서명 Secret Key
//
// Returns:
//   - gin.HandlerFunc: gin 미들웨어
func JwtMiddleware(jwtSecretKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Authorization 헤더에서 토큰 가져오기
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// "Bearer " 부분 제거
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		// 토큰 파싱 및 검증
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// HS256 알고리즘 검증
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return jwtSecretKey, nil
		})

		// 토큰 검증 실패
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Claims에서 ID 추출
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("id", claims["id"])
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Next() // 다음 핸들러로 이동
	}
}
