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
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

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
