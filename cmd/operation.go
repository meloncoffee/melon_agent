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

package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/meloncoffee/melon_agent/config"
	"github.com/meloncoffee/melon_agent/internal/logger"
	"github.com/meloncoffee/melon_agent/internal/resourcecollector"
	"github.com/meloncoffee/melon_agent/internal/server"
	"github.com/meloncoffee/melon_agent/pkg/utils/file"
	"github.com/meloncoffee/melon_agent/pkg/utils/goroutine"
	"github.com/meloncoffee/melon_agent/pkg/utils/network"
	"github.com/meloncoffee/melon_agent/pkg/utils/process"
	"github.com/spf13/cobra"
)

var oper operation

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "",
	RunE:  WrapCmdFuncForCobra(oper.start),
}
var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "",
	RunE:  WrapCmdFuncForCobra(oper.start),
}
var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "",
	RunE:  WrapCmdFuncForCobra(oper.stop),
}

type operation struct{}

// start melon_agent 모듈 가동
//
// Parameters:
//   - cmd: cobra 명령어 정보 구조체
//
// Returns:
//   - error: 정상 종료(nil), 비정상 종료(error)
func (o *operation) start(cmd *cobra.Command) error {
	// 작업 경로를 실행 파일이 위치한 경로로 변경
	err := o.changeWorkPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return err
	}

	// 이미 프로세스가 동작 중인지 확인
	var pid int
	if o.isRunning(&pid, config.PidFilePath) {
		fmt.Fprintf(os.Stdout, "[INFO] melon_agent is already running. (pid:%d)\n", pid)
		return nil
	}

	// 데몬 프로세스 생성
	err = process.DaemonizeProcess()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return err
	}

	// 현재 프로세스 PID 저장
	config.RunConf.Pid = os.Getpid()

	// 현재 프로세스 PID를 파일에 기록
	err = file.WriteDataToTextFile(config.PidFilePath, config.RunConf.Pid, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return err
	}

	// 디버그 모드 체크 (디버그 모드일 경우 stdout, stderr 출력)
	if cmd.Use == "debug" {
		config.RunConf.DebugMode = true
	} else {
		os.Stdout = nil
		os.Stderr = nil
	}

	// 시그널 설정
	sigChan := o.setupSignal()
	defer signal.Stop(sigChan)

	// 고루틴 관리 구조체 생성
	gm := goroutine.NewGoroutineManager()
	// 패닉 핸들러 설정
	gm.PanicHandler = o.panicHandler

	o.initialization(gm)
	defer o.finalization(gm)

	logger.Log.LogInfo("Start %s (pid:%d, mode:%s)", config.ModuleName, config.RunConf.Pid,
		func() string {
			if config.RunConf.DebugMode {
				return "debug"
			}
			return "normal"
		}())

	// 작업에 등록된 모든 고루틴 가동
	gm.StartAll()

	// 종료 시그널 대기 (SIGINT, SIGTERM, SIGUSR1)
	sig := <-sigChan
	logger.Log.LogInfo("Received %s (signum:%d)", sig.String(), sig)

	return nil
}

// stop melon_agent 모듈 정지
//
// Parameters:
//   - cmd: cobra 명령어 정보 구조체
//
// Returns:
//   - error: 정상 종료(nil), 비정상 종료(error)
func (o *operation) stop(cmd *cobra.Command) error {
	// 작업 경로를 현재 프로세스가 위치한 경로로 변경
	err := o.changeWorkPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		return err
	}

	// 프로세스가 동작 중인지 확인
	var pid int
	if !o.isRunning(&pid, config.PidFilePath) {
		return nil
	}

	// 서버에 정지 시그널 전송 (SIGTERM)
	if err := process.SendSignal(pid, syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "[WARNING] %v\n", err)
		return err
	}

	return nil
}

// initialization 모듈 초기화
//
// Parameters:
//   - gm: 고루틴 동작 관리 구조체
func (o *operation) initialization(gm *goroutine.GoroutineManager) {
	var errors []error

	// 설정 파일 로드
	config.Conf.LoadConfig(config.ConfFilePath)
	// 로거 초기화
	logger.Log.InitializeLogger()
	// 네트워크 인터페이스 정보 획득
	config.RunConf.NetIface, errors = network.GetNetworkInterfaces()
	for _, err := range errors {
		logger.Log.LogWarn("%v", err)
	}
	if config.RunConf.DebugMode {
		for _, iface := range config.RunConf.NetIface {
			logger.Log.LogDebug("Network Interface: %v", network.MakeNetIfaceInfoString(&iface))
		}
	}

	// 작업 목록에 고루틴 등록
	var server server.Server
	gm.AddTask("server", server.Run)
	var resourceCollector resourcecollector.ResourceCollector
	gm.AddTask("resourceCollector", resourceCollector.Run)
}

// finalization 모듈 종료 시 자원 정리
//
// Parameters:
//   - gm: 고루틴 동작 관리 구조체
func (o *operation) finalization(gm *goroutine.GoroutineManager) {
	// 작업에 등록된 모든 고루틴 종료
	gm.StopAll(10 * time.Second)

	// 로그 자원 정리
	logger.Log.FinalizeLogger()
}

// changeWorkPath 프로세스 작업 경로를 실행 파일이 위치한 경로로 변경
//
// returns:
//   - error : 성공(nil), 실패(error)
func (o *operation) changeWorkPath() error {
	// 현재 프로세스의 절대 경로 획득
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to absolute path: %v", err)
	}

	dirPath := filepath.Dir(exePath)

	// 작업 경로 변경
	err = os.Chdir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to change dir: %v", err)
	}

	return nil
}

// isRunning 파일에서 PID를 추출하고 해당 PID를 가진 프로세스가 동작 중인지 확인
//
// Parameters:
//   - pid: PID를 저장할 변수
//   - pidFilePath: PID 파일 경로
//
// Returns:
//   - bool: 동작(true), 미동작(false)
func (o *operation) isRunning(pid *int, pidFilePath string) bool {
	if pid == nil {
		return false
	}

	file, err := os.Open(pidFilePath)
	if err != nil {
		return false
	}
	defer file.Close()

	pidStr, err := io.ReadAll(file)
	if err != nil {
		return false
	}

	*pid, err = strconv.Atoi(string(pidStr))
	if err != nil {
		return false
	}

	return process.IsProcessRun(*pid)
}

// setupSignal 시그널 설정
//
// Returns:
//   - chan os.Signal: signal channel
func (o *operation) setupSignal() chan os.Signal {
	sigChan := make(chan os.Signal, 1)
	// 수신할 시그널 설정 (SIGINT, SIGTERM, SIGUSR1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	// 무시할 시그널 설정
	signal.Ignore(syscall.SIGABRT, syscall.SIGALRM, syscall.SIGFPE, syscall.SIGHUP,
		syscall.SIGILL, syscall.SIGPROF, syscall.SIGQUIT, syscall.SIGTSTP,
		syscall.SIGVTALRM)

	return sigChan
}

// panicHandler 패닉 핸들러
//
// Parameters:
//   - panicErr: 패닉 에러
func (o *operation) panicHandler(panicErr interface{}) {
	logger.Log.LogError("Panic occurred: %v", panicErr)
	process.SendSignal(config.RunConf.Pid, syscall.SIGUSR1)
}
