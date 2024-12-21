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

package process

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// IsProcessRun 프로세스가 동작 중인지 확인
//
// Parameters:
//   - pid: PID
//
// Returns:
//   - bool: 동작(true), 미동작(false)
func IsProcessRun(pid int) bool {
	// PID에 해당하는 프로세스를 찾음
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// 시그널 0번을 전송하여 실제 동작 중인지 확인
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

// DaemonizeProcess 데몬 프로세스 생성
//
// Returns:
//   - error: 성공(nil), 실패(error)
func DaemonizeProcess() error {
	// PID가 1인 경우 이미 데몬 프로세스임
	if os.Getppid() != 1 {
		// 현재 프로세스의 절대 경로 획득
		exePath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get absolute path: %v", err)
		}

		// 자식 프로세스 생성
		cmd := exec.Command(exePath, os.Args[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}
		cmd.Stdin = nil
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		// 데몬 프로세스 가동
		err = cmd.Start()
		if err != nil {
			return fmt.Errorf("failed to start daemon process: %v", err)
		}

		// 부모 프로세스 종료
		os.Exit(0)
	}

	return nil
}

// SendSignal 프로세스에 시그널 전송
//
// Parameters:
//   - pid: PID
//   - sig: signal
//
// Returns:
//   - error: 성공(nil), 실패(error)
func SendSignal(pid int, sig syscall.Signal) error {
	// PID로 부터 프로세스 정보 획득
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %v", err)
	}

	// 시그널 전송
	err = proc.Signal(sig)
	if err != nil {
		return fmt.Errorf("failed to send signal: %v", err)
	}

	return nil
}
