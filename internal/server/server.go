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
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/meloncoffee/melon_agent/config"
	"github.com/meloncoffee/melon_agent/internal/logger"
	"github.com/meloncoffee/melon_agent/internal/metric"
	"github.com/meloncoffee/melon_agent/pkg/certificate"
	"github.com/meloncoffee/melon_agent/pkg/utils/file"
	"github.com/meloncoffee/melon_agent/pkg/utils/process"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/thoas/stats"
)

var (
	doOnce sync.Once
	// 서버 응답 시간 및 상태 코드 카운트
	servStats *stats.Stats
	// JWT 토큰 서명 Secret Key
	jwtSecretKey string
)

type Server struct{}

// Run 메인 서버 가동
//
// Parameters:
//   - ctx: 서버 종료 컨텍스트
func (s *Server) Run(ctx context.Context) {
	var tlsConf tls.Config
	isTLS := false
	port := config.Conf.Server.Port

	if config.Conf.Server.TLSEnabled {
		// TLS 인증서 파일 존재 유무 체크
		if !file.IsFileExists(config.TLSCertPath) || !file.IsFileExists(config.TLSKeyPath) {
			// TLS 인증서 파일 저장 경로 생성
			dir := filepath.Dir(config.TLSCertPath)
			os.MkdirAll(dir, 0644)

			// TLS 인증서 파일 생성
			err := certificate.GenTLSCertificate(config.TLSCertPath, config.TLSKeyPath,
				"Melon", 3650)
			if err != nil {
				logger.Log.LogError("%v", err)
				process.SendSignal(config.RunConf.Pid, syscall.SIGUSR1)
				return
			}
		}

		// TLS 인증서 파일 로드
		cert, err := tls.LoadX509KeyPair(config.TLSCertPath, config.TLSKeyPath)
		if err != nil {
			logger.Log.LogError("Failed to load TLS certificate: %v", err)
			process.SendSignal(config.RunConf.Pid, syscall.SIGUSR1)
			return
		}

		// TLS 설정에 로드한 인증서 등록
		tlsConf.Certificates = []tls.Certificate{cert}

		// 애플리케이션 계층 프로토콜(HTTP/1.1, HTTP/2) 설정
		if tlsConf.NextProtos == nil {
			tlsConf.NextProtos = []string{"h2", "http/1.1"}
		}

		isTLS = true
	}

	if jwtSecretKey == "" {
		// JWT Secret Key 생성
		var err error
		jwtSecretKey, err = s.genJWTSecretKey(32)
		if err != nil {
			logger.Log.LogError("Failed to generate JWT secret key: %v", err)
			process.SendSignal(config.RunConf.Pid, syscall.SIGUSR1)
			return
		}
	}

	// HTTP 서버 설정
	server := &http.Server{
		Addr: ":" + strconv.Itoa(port),
		// gin 엔진 설정
		Handler: s.newGinRouterEngine(),
		// 요청 타임아웃 10초 설정
		ReadTimeout: 10 * time.Second,
		// 응답 타임아웃 10초 설정
		WriteTimeout: 10 * time.Second,
		// 요청 헤더 최대 크기를 1MB로 설정
		MaxHeaderBytes: 1 << 20,
	}

	if isTLS {
		// TLS 설정 등록
		server.TLSConfig = &tlsConf
		// HTTPS 서버 가동
		go func() {
			err := server.ListenAndServeTLS("", "")
			if err != nil && err != http.ErrServerClosed {
				logger.Log.LogError("Server error occurred: %v", err)
				process.SendSignal(config.RunConf.Pid, syscall.SIGUSR1)
			}
		}()
	} else {
		// HTTP 서버 가동
		go func() {
			err := server.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				logger.Log.LogError("Server error occurred: %v", err)
				process.SendSignal(config.RunConf.Pid, syscall.SIGUSR1)
			}
		}()
	}

	logger.Log.LogInfo("Server listening on port %d", port)

	// 서버 종료 신호 대기
	<-ctx.Done()

	// 종료 신호를 받았으면 graceful shutdown을 위해 5초 타임아웃 설정
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 서버 종료
	err := server.Shutdown(shutdownCtx)
	if err != nil {
		logger.Log.LogWarn("Server shutdown: %v", err)
		return
	}

	logger.Log.LogInfo("Server shutdown on port %d", port)
}

// newRouterEngine gin 엔진 생성
//
// Returns:
//   - *gin.Engine: gin 엔진
func (s *Server) newGinRouterEngine() *gin.Engine {
	// 런타임 중 한번만 호출됨
	doOnce.Do(func() {
		// 시스템 메트릭 정보 생성
		m := metric.NewMetrics()
		prometheus.MustRegister(m)
		// Stats 구조체 생성
		servStats = stats.New()
	})

	// gin 동작 모드 설정
	gin.SetMode(func() string {
		if config.RunConf.DebugMode {
			return gin.DebugMode
		}
		return gin.ReleaseMode
	}())

	// gin 라우터 생성
	r := gin.New()

	// 복구 미들웨어 등록
	r.Use(gin.Recovery())
	// 요청/응답 정보 로깅 미들웨어 등록
	r.Use(s.ginLoggerMiddleware())
	// 버전 정보 미들웨어 등록
	r.Use(s.versionMiddleware())
	// 요청 통계를 수집하고 기록하는 미들웨어 등록
	r.Use(s.statMiddleware())

	// 요청 핸들러 등록
	r.GET(config.Conf.API.MetricURI, metricsHandler)
	r.GET(config.Conf.API.HealthURI, healthHandler)
	r.GET(config.Conf.API.SysStatURI, sysStatsHandler)
	r.GET("/version", versionHandler)
	r.GET("/", rootHandler)
	r.POST(config.Conf.API.LoginURI, loginHandler)

	// `/protected` 그룹에 속하는 모든 라우터는 JWT 토큰 검증 수행
	protected := r.Group("/protected")
	// JWT 토큰 검증 미들웨어 등록
	protected.Use(s.jwtMiddleware())

	return r
}

// ginLoggerMiddleware gin 요청/응답 정보 로깅 미들웨어
//
// Returns:
//   - gin.HandlerFunc: gin 미들웨어
func (s *Server) ginLoggerMiddleware() gin.HandlerFunc {
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

// versionMiddleware 버전 정보 미들웨어
//
// Returns:
//   - gin.HandlerFunc: gin 미들웨어
func (s *Server) versionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-MELON_AGENT-VERSION", config.Version)
		c.Next()
	}
}

// statMiddleware 요청 통계를 수집하고 기록하는 미들웨어
//
// Returns:
//   - gin.HandlerFunc: gin 미들웨어
func (s *Server) statMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		beginning, recorder := servStats.Begin(c.Writer)
		c.Next()
		servStats.End(beginning, stats.WithRecorder(recorder))
	}
}

// genJWTSecretKey 랜덤 JWT Secret Key 생성 함수
//
// Parameters:
//   - size: Key Size
//
// Returns:
//   - string: JWT Secret Key
//   - error: 성공(nil), 실패(error)
func (s *Server) genJWTSecretKey(size int) (string, error) {
	// 지정된 크기의 랜덤 바이트 배열 생성
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}

	// Base64로 인코딩하여 문자열 반환
	return base64.StdEncoding.EncodeToString(key), nil
}

// jwtMiddleware JWT 미들웨어
//
// Returns:
//   - gin.HandlerFunc: gin 미들웨어
func (s *Server) jwtMiddleware() gin.HandlerFunc {
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

		// Claims에서 유저 정보 추출
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("username", claims["username"])
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Next() // 다음 핸들러로 이동
	}
}
