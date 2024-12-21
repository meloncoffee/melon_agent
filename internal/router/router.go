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

package router

import (
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/meloncoffee/melon_agent/config"
	"github.com/meloncoffee/melon_agent/internal/metric"
	"github.com/meloncoffee/melon_agent/internal/router/handler"
	"github.com/meloncoffee/melon_agent/internal/router/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/thoas/stats"
)

var (
	JwtSecretKey string

	servStats *stats.Stats
	doOnce    sync.Once
)

// NewGinRouterEngine gin 엔진 생성
//
// Returns:
//   - *gin.Engine: gin 엔진
func NewGinRouterEngine() *gin.Engine {
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
	r.Use(middleware.GinLoggerMiddleware())
	// 버전 정보 미들웨어 등록
	r.Use(middleware.VersionMiddleware())
	// 요청 통계를 수집하고 기록하는 미들웨어 등록
	r.Use(middleware.StatMiddleware(servStats))

	// 요청 핸들러 등록
	r.GET(config.Conf.API.MetricURI, handler.MetricsHandler)
	r.GET(config.Conf.API.HealthURI, handler.HealthHandler)
	r.GET(config.Conf.API.SysStatURI, func(ctx *gin.Context) {
		handler.SysStatsHandler(ctx, servStats)
	})
	r.GET("/version", handler.VersionHandler)
	r.GET("/", handler.RootHandler)
	r.POST(config.Conf.API.LoginURI, func(ctx *gin.Context) {
		handler.LoginHandler(ctx, JwtSecretKey)
	})
	r.POST(config.Conf.API.RegisterAdminURI, handler.RegisterAdminHandler)

	// `/protected` 그룹에 속하는 모든 라우터는 JWT 토큰 검증 수행
	protected := r.Group("/protected")
	// JWT 토큰 검증 미들웨어 등록
	protected.Use(middleware.JwtMiddleware(JwtSecretKey))

	return r
}
