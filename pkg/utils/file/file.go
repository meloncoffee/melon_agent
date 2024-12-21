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

package file

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteDataToTextFile 제네릭한 파일 쓰기 함수
// Parameters:
//   - filePath: 파일 경로
//   - data: 제네릭 타입 데이터
//   - isMakeDir: 디렉터리가 존재하지 않을 경우 생성 옵션
//
// Returns:
//   - error: 성공(nil), 실패(error)
func WriteDataToTextFile[T any](filePath string, data T, isMakeDir bool) error {
	if isMakeDir {
		// 디렉터리가 존재하지 않을 경우 생성
		dir := filepath.Dir(filePath)
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to make directory: %v", err)
		}
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	_, err = fmt.Fprintf(file, "%v", data)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	return nil
}

// IsFileExists 파일 존재 여부 확인
//
// Parameters:
//   - filePath: 파일 경로
//
// Returns:
//   - bool: 파일 존재(true), 파일 미존재(false)
func IsFileExists(filePath string) bool {
	stat, err := os.Stat(filePath)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return !stat.IsDir()
}
