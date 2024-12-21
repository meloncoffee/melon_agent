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

package goroutine

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// PanicHandleFunc 패닉 핸들러 함수 타입 정의
type PanicHandleFunc func(interface{})

// GoroutineManager 전체 고루틴 관리 정보 구조체
type GoroutineManager struct {
	PanicHandler PanicHandleFunc
	mu           sync.Mutex
	parentWG     sync.WaitGroup
	parentCtx    context.Context
	parentCancel context.CancelFunc
	tasks        map[string]*taskWrapper
}

// taskWrapper 개별 고루틴 관리 정보 구조체
type taskWrapper struct {
	childWG     sync.WaitGroup
	childCtx    context.Context
	childCancel context.CancelFunc
	task        func(ctx context.Context)
}

// NewGoroutineManager 고루틴 관리 구조체 생성
//
// Returns:
//   - *GoroutineManager
func NewGoroutineManager() *GoroutineManager {
	// 전체 고루틴 종료를 위한 부모 컨텍스트 생성
	ctx, cancel := context.WithCancel(context.Background())
	return &GoroutineManager{
		parentCtx:    ctx,
		parentCancel: cancel,
		tasks:        make(map[string]*taskWrapper),
	}
}

// AddTask 고루틴을 작업에 등록
//
// Parameters:
//   - name: 작업명 (key)
//   - task: function (value)
func (gm *GoroutineManager) AddTask(name string, task func(ctx context.Context)) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// 개별 고루틴 종료를 위한 자식 컨텍스트 생성
	ctx, cancel := context.WithCancel(gm.parentCtx)
	// 맵에 작업 등록
	gm.tasks[name] = &taskWrapper{
		childCtx:    ctx,
		childCancel: cancel,
		task:        task,
	}
}

// RemoveTask 고루틴 종료 및 작업 제거
//
// Parameters:
//   - name: 작업명
//   - timeout: WaitGroup 타임아웃
//
// Returns:
//   - error: 성공(nil), 타임아웃 발생(error)
func (gm *GoroutineManager) RemoveTask(name string, timeout time.Duration) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if t, exists := gm.tasks[name]; exists {
		t.childCancel()
		if WaitGroupWithTimeout(&t.childWG, timeout) != WaitSuccess {
			return fmt.Errorf("goroutine was not terminated within the specified timeout"+
				"(goroutine: %s, timeout: %.2fsec)", name, timeout.Seconds())
		}
		delete(gm.tasks, name)
	}

	return nil
}

// StartAll 작업에 등록된 모든 고루틴 가동
func (gm *GoroutineManager) StartAll() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	for _, t := range gm.tasks {
		gm.parentWG.Add(1)
		t.childWG.Add(1)
		tmpTask := t
		go func(tw *taskWrapper) {
			defer func() {
				if err := recover(); err != nil {
					if gm.PanicHandler != nil {
						gm.PanicHandler(err)
					}
				}
				tw.childWG.Done()
				gm.parentWG.Done()
			}()

			// 작업 가동
			tw.task(tw.childCtx)
		}(tmpTask)
	}
}

// StopAll 작업에 등록된 모든 고루틴 가동 정지
//
// Parameters:
//   - timeout: WaitGroup 타임아웃
//
// Returns:
//   - error: 성공(nil), 타임아웃 발생(error)
func (gm *GoroutineManager) StopAll(timeout time.Duration) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	gm.parentCancel()
	if WaitGroupWithTimeout(&gm.parentWG, timeout) != WaitSuccess {
		return fmt.Errorf("goroutines were not terminated within the specified timeout"+
			"(timeout: %.2fsec)", timeout.Seconds())
	}
	return nil
}

// Start 작업에 등록된 개별 고루틴 가동
//
// Parameters:
//   - name: 작업명
//
// Returns:
//   - error: 성공(nil), 실패(error)
func (gm *GoroutineManager) Start(name string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// 작업에 등록되어 있는지 확인
	t, exists := gm.tasks[name]
	if !exists {
		return fmt.Errorf("task does not exist (%s)", name)
	}

	gm.parentWG.Add(1)
	t.childWG.Add(1)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				if gm.PanicHandler != nil {
					gm.PanicHandler(err)
				}
			}
			t.childWG.Done()
			gm.parentWG.Done()
		}()

		// 작업 가동
		t.task(t.childCtx)
	}()

	return nil
}

// Stop 작업에 등록된 개별 고루틴 가동 정지
//
// Parameters:
//   - name: 작업명
//   - timeout: WaitGroup 타임아웃
//
// Returns:
//   - error: 성공(nil), 타임아웃 발생(error)
func (gm *GoroutineManager) Stop(name string, timeout time.Duration) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if t, exists := gm.tasks[name]; exists {
		t.childCancel()
		if WaitGroupWithTimeout(&t.childWG, timeout) != WaitSuccess {
			return fmt.Errorf("goroutine was not terminated within the specified timeout"+
				"(goroutine: %s, timeout: %.2fsec)", name, timeout.Seconds())
		}
	}
	return nil
}

// DefaultPanicHandler 기본 패닉 핸들러 함수
//
// Parameters:
//   - panicErr: 패닉 에러
func DefaultPanicHandler(panicErr interface{}) {
	fmt.Fprintf(os.Stderr, "panic occurred: %v\n", panicErr)
}
