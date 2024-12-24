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

package config

import (
	"fmt"
	"os"

	"github.com/meloncoffee/melon_agent/pkg/utils/network"
	"gopkg.in/yaml.v3"
)

// 빌드 시 값 설정됨
var (
	Version   = "unknown"
	BuildTime = "unknown"
)

const (
	ModuleName   = "melon_agent"
	PidFilePath  = "var/.melon_agent.pid"
	LogFilePath  = "log/melon_agent.log"
	ConfFilePath = "conf/melon_agent.yaml"
)

const (
	TLSCertPath      = "cert/melon_agent.crt"
	TLSKeyPath       = "cert/melon_agent.key"
	AdminAccountPath = "auth/.admin"
)

// Config 설정 정보 구조체
type Config struct {
	// 서버 설정
	Server struct {
		// 서버 리스닝 포트 (DEF:8888)
		Port int `yaml:"port"`
		// TLS 사용 설정 (DEF:true)
		TLSEnabled bool `yaml:"tlsEnabled"`
	} `yaml:"server"`

	// API 설정
	API struct {
		// 서버 메트릭 요청 URI (DEF:/metrics)
		MetricURI string `yaml:"metricURI"`
		// 서버 상태 요청 URI (DEF:/health)
		HealthURI string `yaml:"healthURI"`
		// 서버 응답 시간 및 상태 코드 요청 URI (DEF:/sys/stat)
		SysStatURI string `yaml:"sysStatURI"`
		// JWT 토큰 요청 URI (DEF:/login)
		LoginURI string `yaml:"loginURI"`
		// 관리자 계정 정보 등록 요청 URI (DEF:/register/admin)
		RegisterAdminURI string `yaml:"registerAdminURI"`
	} `yaml:"api"`

	// 로그 설정
	Log struct {
		// 최대 로그 파일 사이즈 (DEF:100MB, MIN:1MB, MAX:1000MB)
		MaxLogFileSize int `yaml:"maxLogFileSize"`
		// 최대 로그 파일 백업 개수 (DEF:10, MIN:1, MAX:100)
		MaxLogFileBackup int `yaml:"maxLogFileBackup"`
		// 로그 파일 유지 기간 (DEF:90, MIN:1, MAX:365)
		MaxLogFileAge int `yaml:"maxLogFileAge"`
		// 백업 로그 파일 압축 여부 (DEF:true)
		CompBakLogFile bool `yaml:"compBakLogFile"`
	} `yaml:"log"`
}

// RunConfig 런타임 설정 정보 구조체
type RunConfig struct {
	DebugMode bool
	Pid       int
	NetIface  []network.NetInterface
}

var RunConf RunConfig
var Conf Config

// 패키지 임포트 시 초기화
func init() {
	Conf.Server.Port = 8888
	Conf.Server.TLSEnabled = true

	Conf.API.MetricURI = "/metrics"
	Conf.API.HealthURI = "/health"
	Conf.API.SysStatURI = "/sys/stat"
	Conf.API.LoginURI = "/login"
	Conf.API.RegisterAdminURI = "/register/admin"

	Conf.Log.MaxLogFileSize = 100
	Conf.Log.MaxLogFileBackup = 10
	Conf.Log.MaxLogFileAge = 90
	Conf.Log.CompBakLogFile = true
}

// LoadConfig yaml 설정 파일 로드
//
// Parameters:
//   - filePath: 설정 파일 경로
//
// Returns:
//   - error: 성공(nil), 실패(error)
func (c *Config) LoadConfig(filePath string) error {
	// YAML 설정 파일 열기
	file, err := os.Open(ConfFilePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// YAML 디코더 생성
	decoder := yaml.NewDecoder(file)

	// YAML 파싱 및 디코딩
	err = decoder.Decode(&Conf)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	// 설정 값 유효성 검사
	if Conf.Server.Port < 1 || Conf.Server.Port > 65535 {
		Conf.Server.Port = 8888
	}
	if Conf.API.MetricURI == "" || Conf.API.MetricURI[0] != '/' {
		Conf.API.MetricURI = "/metrics"
	}
	if Conf.API.HealthURI == "" || Conf.API.HealthURI[0] != '/' {
		Conf.API.HealthURI = "/health"
	}
	if Conf.API.SysStatURI == "" || Conf.API.SysStatURI[0] != '/' {
		Conf.API.SysStatURI = "/sys/stat"
	}
	if Conf.API.LoginURI == "" || Conf.API.LoginURI[0] != '/' {
		Conf.API.LoginURI = "/login"
	}
	if Conf.API.RegisterAdminURI == "" || Conf.API.RegisterAdminURI[0] != '/' {
		Conf.API.RegisterAdminURI = "/register/admin"
	}
	if Conf.Log.MaxLogFileSize < 1 || Conf.Log.MaxLogFileSize > 1000 {
		Conf.Log.MaxLogFileSize = 100
	}
	if Conf.Log.MaxLogFileBackup < 1 || Conf.Log.MaxLogFileBackup > 100 {
		Conf.Log.MaxLogFileBackup = 10
	}
	if Conf.Log.MaxLogFileAge < 1 || Conf.Log.MaxLogFileAge > 365 {
		Conf.Log.MaxLogFileAge = 90
	}

	return nil
}
