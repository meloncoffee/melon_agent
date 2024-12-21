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

package channel

import "fmt"

// SendChannel 패닉에 안전한 채널 전송 함수
//
// Parameters:
//   - ch: 채널
//   - data: 채널에 전송할 데이터
//
// Returns:
//   - err: 성공(nil), 실패(패닉 에러)
func SendChannel[T any](ch chan T, data T) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occurred: %v", r)
		}
	}()

	ch <- data
	return nil
}
