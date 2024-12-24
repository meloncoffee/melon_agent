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

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	mrand "math/rand"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/meloncoffee/melon_agent/pkg/utils/crypto"
	"github.com/meloncoffee/melon_agent/pkg/utils/file"
)

type Account struct {
	ID string `json:"id"`
	PW string `json:"pw"`
}

// GenJWTSecretKey 랜덤 JWT Secret Key 생성 함수
//
// Parameters:
//   - size: Key Size
//
// Returns:
//   - string: JWT Secret Key
//   - error: 성공(nil), 실패(error)
func GenJWTSecretKey(size int) (string, error) {
	// 지정된 크기의 랜덤 바이트 배열 생성
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}

	// Base64로 인코딩하여 문자열 반환
	return base64.StdEncoding.EncodeToString(key), nil
}

// GenJWTToken JWT 토큰 생성
//
// Parameters:
//   - username: JWT 토큰 생성 ID
//   - jwtSecretKey: JWT 토큰 서명 Secret Key
//
// Returns:
//   - string: JWT 토큰
//   - error: 성공(nil), 실패(error)
func GenJWTToken(username, jwtSecretKey string) (string, error) {
	// JWT Claims 생성
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}

	// JWT 토큰 생성
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if token == nil {
		return "", fmt.Errorf("failed to generate JWT token")
	}
	return token.SignedString(jwtSecretKey)
}

// EncryptAdminAccount 관리자 계정 암호화 후 파일 저장
//
// Parameters:
//   - filePath: 암호화 관리자 계정 저장 파일 경로
//   - id: Admin ID
//   - pw: Admin PW
//
// Returns:
//   - error: 성공(nil), 실패(error)
func EncryptAdminAccountToFile(filePath, id, pw string) error {
	idLen := len([]byte(id))
	pwLen := len([]byte(pw))

	// idLen과 pwLen을 2바이트로 변환
	idLenBytes := []byte{byte(idLen >> 8), byte(idLen & 0xFF)}
	pwLenBytes := []byte{byte(pwLen >> 8), byte(pwLen & 0xFF)}

	// 전체 데이터 크기 계산
	totalLen := 2 + 2 + idLen + pwLen
	plaintext := make([]byte, totalLen)

	// 데이터를 순서대로 슬라이스에 복사
	copy(plaintext[0:2], idLenBytes)
	copy(plaintext[2:4], pwLenBytes)
	copy(plaintext[4:4+idLen], []byte(id))
	copy(plaintext[4+idLen:], []byte(pw))

	// 로컬 랜덤 생성기 초기화
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))

	// 0~511 사이의 랜덤 정수 생성
	randNum := r.Intn(512)

	// Key 값의 해시를 암호화 키로 사용
	hash := sha256.Sum256(KeyTables[randNum][:])
	hashSlice := hash[:]

	// AES256-GCM 암호화
	ciphertext, err := crypto.EncryptAES256GCM(hashSlice, plaintext)
	if err != nil {
		return err
	}

	// randNum을 2바이트로 변환
	randNumBytes := []byte{byte(randNum >> 8), byte(randNum & 0xFF)}

	// 최종 암호화 데이터 생성
	encryptedData := make([]byte, 2+len(ciphertext))
	copy(encryptedData[0:2], randNumBytes)
	copy(encryptedData[2:], ciphertext)

	// 파일 경로 전체 생성
	err = file.MakeDirAll(filePath, os.ModePerm)
	if err != nil {
		return err
	}

	// 암호화된 데이터를 파일에 저장
	err = os.WriteFile(filePath, encryptedData, 0600)
	if err != nil {
		return err
	}

	return nil
}

// DecryptAdminAccountFromFile 파일에서 암호화된 관리자 계정 복호화
//
// Parameters:
//   - filePath: 파일 경로
//
// Returns:
//   - string: Admin ID
//   - string: Admin PW
//   - error: 성공(nil), 실패(error)
func DecryptAdminAccountFromFile(filePath string) (string, string, error) {
	// 파일에서 암호화된 데이터 읽기
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}

	encryptedDataLen := len(encryptedData)

	// 파일 크기 검증 (최소 2바이트의 랜덤 숫자 + 암호문 길이)
	if encryptedDataLen < 2 {
		return "", "", fmt.Errorf("invalid encrypted data (len:%d)", encryptedDataLen)
	}

	// 랜덤 숫자 추출 (상위 2바이트)
	randNum := int(encryptedData[0])<<8 | int(encryptedData[1])

	// 랜덤 숫자 범위 검증
	if randNum < 0 || randNum >= 512 {
		return "", "", fmt.Errorf("invalid random number(%d) in encrypted data", randNum)
	}

	// Key 값의 해시를 복호화 키로 사용
	hash := sha256.Sum256(KeyTables[randNum][:])
	hashSlice := hash[:]

	// AES256-GCM으로 데이터 복호화
	ciphertext := encryptedData[2:]
	plaintext, err := crypto.DecryptAES256GCM(hashSlice, ciphertext)
	if err != nil {
		return "", "", err
	}

	plaintextLen := len(plaintext)

	// 복호화된 데이터에서 ID 길이 및 PW 길이 추출
	if plaintextLen < 4 {
		return "", "", fmt.Errorf("invalid decrypted data (len:%d)", plaintextLen)
	}
	idLen := int(plaintext[0])<<8 | int(plaintext[1])
	pwLen := int(plaintext[2])<<8 | int(plaintext[3])

	// ID와 PW의 길이 검증
	if plaintextLen != (4 + idLen + pwLen) {
		return "", "", fmt.Errorf("decrypted data length mismatch (%d != %d)",
			plaintextLen, (4 + idLen + pwLen))
	}

	// ID와 PW 추출
	id := string(plaintext[4 : 4+idLen])
	pw := string(plaintext[4+idLen:])

	return id, pw, nil
}
