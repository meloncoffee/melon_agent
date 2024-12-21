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

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// EncryptAES256GCM AES256-GCM 암호화 함수
//
// Parameters:
//   - key: 암호화 키 (32바이트 크기의 AES256 키)
//   - plaintext: 평문 데이터 (암호화할 데이터)
//
// Returns:
//   - []byte: 암호화된 데이터 (nonce + 암호문)
//   - error: 성공 시 nil, 실패 시 error
func EncryptAES256GCM(key, plaintext []byte) ([]byte, error) {
	// AES 블록 암호 생성
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// GCM 모드 래퍼 생성
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Nonce 생성 (암호화 시 고유한 값, 크기는 GCM 모드가 지정)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// GCM 암호화를 수행하고 결과 반환
	// Seal 함수는 (nonce + 암호문)을 반환
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptAES256GCM AES256-GCM 복호화 함수
//
// Parameters:
//   - key: 복호화 키 (32바이트 크기의 AES256 키)
//   - ciphertext: 암호문 데이터 (nonce + 암호문 형식)
//
// Returns:
//   - []byte: 복호화된 평문 데이터
//   - error: 성공 시 nil, 실패 시 error
func DecryptAES256GCM(key, ciphertext []byte) ([]byte, error) {
	// AES 블록 암호 생성
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// GCM 모드 래퍼 생성
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 암호문 길이 확인 (Nonce를 포함한 데이터인지 확인)
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Nonce와 암호문 분리
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	// GCM 복호화 수행
	// Open 함수는 복호화된 평문을 반환
	// 데이터 무결성을 확인하며, 위조된 경우 에러 반환
	return gcm.Open(nil, nonce, ciphertext, nil)
}
