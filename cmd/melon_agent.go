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
	"os"

	"github.com/meloncoffee/melon_agent/config"
	"github.com/spf13/cobra"
	"go.uber.org/automaxprocs/maxprocs"
)

var melonAgentCmd = &cobra.Command{
	Use:     "melon_agent",
	Short:   "",
	Long:    "",
	Version: config.Version + "\nBuild Date: " + config.BuildTime,
}

func init() {
	melonAgentCmd.AddCommand(startCmd, debugCmd, stopCmd)
}

// Execute CLI 처리
func Execute() {
	// 최적화된 GOMAXPROCS 값 설정
	undo, err := maxprocs.Set()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARNING] Failed to set GOMAXPROCS: %v\n", err)
	}
	defer undo()

	err = melonAgentCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// WrapCmdFuncForCobra cobra의 `RunE` 메서드와 호환되는 함수 래핑
//
// 이 함수는 `func(cmd *cobra.Command) error` 형태의 함수를 받아서,
// cobra의 `RunE` 메서드에서 요구하는 `func(cmd *cobra.Command, _ []string) error` 형태로 변환.
//
// Parameters:
//   - f: `func(cmd *cobra.Command) error` 형태의 함수로, cobra 명령어의 실행 로직을 포함
//
// Returns:
//   - func: `func(cmd *cobra.Command, _ []string) error` 형태의 함수로 변환된 결과
func WrapCmdFuncForCobra(f func(cmd *cobra.Command) error) func(cmd *cobra.Command, _ []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		// cobra에서 출력하는 에러 메시지 무시
		cmd.SilenceErrors = true
		return f(cmd)
	}
}
