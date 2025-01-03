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

package taskmanager

import (
	"context"
	"sync"
	"time"

	"github.com/meloncoffee/melon_agent/internal/logger"
	"github.com/meloncoffee/melon_agent/pkg/utils/goroutine"
)

type OperType int

const (
	ServerReload OperType = iota
	ResCollectorReload
	ConfReload
)

type TaskType int

const (
	TaskManagerType TaskType = iota
	ServerType
	ResourceCollectorType
)

// String TaskType을 문자열로 반환
//
// Returns:
//   - string: 문자열로 변환된 TaskType
func (t TaskType) String() string {
	switch t {
	case TaskManagerType:
		return string(TaskManagerStr)
	case ServerType:
		return string(ServerStr)
	case ResourceCollectorType:
		return string(ResourceCollectorStr)
	}

	return ""
}

type TaskStrType string

const (
	TaskManagerStr       TaskStrType = "taskManager"
	ServerStr            TaskStrType = "server"
	ResourceCollectorStr TaskStrType = "resourceCollector"
)

// Int TaskStrType을 정수로 반환
//
// Returns:
//   - int: 정수로 변환된 TaskStrType
func (t TaskStrType) Int() int {
	switch t {
	case TaskManagerStr:
		return int(TaskManagerType)
	case ServerStr:
		return int(ServerType)
	case ResourceCollectorStr:
		return int(ResourceCollectorType)
	}

	return -1
}

var TaskManagerChan chan OperType

func init() {
	TaskManagerChan = make(chan OperType, 10)
}

type TaskManager struct {
	wg sync.WaitGroup
}

// Run 고루틴 작업 관리자
//
// Parameters:
//   - ctx: 종료 컨텍스트
//   - gm: 고루틴 작업 정보 구조체
func (t *TaskManager) Run(ctx context.Context, gm *goroutine.GoroutineManager) {
	var timeout time.Duration

	if nil == gm {
		logger.Log.LogPanic("Invalid parameter (`gm *goroutine.GoroutineManager` is nil)")
		return
	}

	// 작업 채널로 전송된 TaskType 처리 고루틴 생성
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.taskChannelManager(gm)
	}()

	for goroutine.WaitTimeout == goroutine.WaitCancelWithTimeout(ctx, timeout) {
		timeout = 3 * time.Second
	}

	close(TaskManagerChan)
	t.wg.Wait()
}

// taskChannelManager 작업 채널로 들어오는 OperType 처리
//
// Parameters:
//   - gm: 고루틴 작업 정보 구조체
func (t *TaskManager) taskChannelManager(gm *goroutine.GoroutineManager) {
	for task := range TaskManagerChan {
		switch task {
		// 서버 고루틴 재가동
		case ServerReload:
			time.Sleep(1 * time.Second)
			gm.Stop(string(ServerStr), -1)
			err := gm.Start(string(ServerStr))
			if err != nil {
				logger.Log.LogError("%v", err)
			}
		// 리소스 수집 고루틴 재가동
		case ResCollectorReload:
			time.Sleep(1 * time.Second)
			gm.Stop(string(ResourceCollectorStr), -1)
			err := gm.Start(string(ResourceCollectorStr))
			if err != nil {
				logger.Log.LogError("%v", err)
			}
		}
	}
}
