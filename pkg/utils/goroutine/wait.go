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
	"sync"
	"time"
)

type WaitError int

const (
	WaitSuccess WaitError = iota
	WaitTimeout
	WaitInvalidParam
)

// WaitCancelWithTimeout 컨텍스트 종료 타임아웃 대기
//
// Parameters:
//   - ctx: context
//   - timeout: 타임아웃
//
// Returns:
//   - WaitError: 종료 신호 수신(WaitSuccess), 타임아웃 발생(WaitTimeout)
func WaitCancelWithTimeout(ctx context.Context, timeout time.Duration) WaitError {
	// 타임아웃이 0보다 작을 경우 무한 대기
	if timeout < 0 {
		<-ctx.Done()
		return WaitSuccess
	}

	select {
	case <-ctx.Done():
		// 종료 신호 수신
		return WaitSuccess
	case <-time.After(timeout):
		// 타임아웃 발생
		return WaitTimeout
	}
}

// WaitGroupWithTimeout 고루틴 종료 타임아웃 대기
//
// Parameters:
//   - wg: WaitGroup
//   - timeout: 타임아웃
//
// Returns:
//   - WaitError: 고루틴 정상 종료(WaitSuccess), 실패(WaitError)
func WaitGroupWithTimeout(wg *sync.WaitGroup, timeout time.Duration) WaitError {
	if wg == nil {
		return WaitInvalidParam
	}

	// 타임아웃이 0보다 작을 경우 무한 대기
	if timeout < 0 {
		wg.Wait()
		return WaitSuccess
	}

	done := make(chan struct{})

	// 고루틴 작업 종료 대기
	go func() {
		defer close(done)
		wg.Wait()
	}()

	select {
	case <-done:
		// 고루틴 정상 종료
		return WaitSuccess
	case <-time.After(timeout):
		// 타임아웃 발생
		return WaitTimeout
	}
}
