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
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/meloncoffee/melon_agent/config"
	"github.com/meloncoffee/melon_agent/internal/auth"
	"github.com/meloncoffee/melon_agent/internal/logger"
	"github.com/meloncoffee/melon_agent/internal/router"
	"github.com/meloncoffee/melon_agent/pkg/certificate"
	"github.com/meloncoffee/melon_agent/pkg/utils/file"
	"github.com/meloncoffee/melon_agent/pkg/utils/process"
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

	if router.JwtSecretKey == "" {
		// JWT Secret Key 생성
		var err error
		router.JwtSecretKey, err = auth.GenJWTSecretKey(32)
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
		Handler: router.NewGinRouterEngine(),
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
