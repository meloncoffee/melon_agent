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

package network

import (
	"fmt"
	"net"
)

type NetInterface struct {
	Name         string           // 인터페이스명
	MTU          int              // 전송 가능한 최대 패킷 크기(바이트 단위)
	HardwareAddr net.HardwareAddr // MAC 주소
	Flags        net.Flags        // 인터페이스의 상태를 나타내는 플래그
	IP           []net.IPNet      // 인터페이스에 할당된 IP 주소와 서브넷 정보 리스트
}

// GetNetworkInterfaces 시스템 네트워크 인터페이스 정보 획득 함수
//
// Returns:
//   - []NetInterface: 네트워크 인터페이스 정보 구조체 슬라이스
//   - error: 성공(nil), 실패(error)
func GetNetworkInterfaces() ([]NetInterface, []error) {
	var netIfaceList []NetInterface = nil
	var retErr []error = nil

	// 네트워크 인터페이스 리스트 가져오기
	interfaces, err := net.Interfaces()
	if err != nil {
		retErr = append(retErr,
			fmt.Errorf("failed to get network interfaces: %v", err))
		return nil, retErr
	}

	for _, iface := range interfaces {
		// 네트워크 인터페이스 기본 정보 저장
		netIface := NetInterface{
			Name:         iface.Name,
			MTU:          iface.MTU,
			HardwareAddr: iface.HardwareAddr,
			Flags:        iface.Flags,
		}

		// 인터페이스에서 IP 정보 획득
		addrs, err := iface.Addrs()
		if err != nil {
			retErr = append(retErr,
				fmt.Errorf("failed to get addresses for interface %s: %v", iface.Name, err))
			continue
		}

		for _, addr := range addrs {
			// IP 주소와 서브넷 마스크를 포함하는 구조체로 타입 단언
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			// IP 정보 추가
			netIface.IP = append(netIface.IP, *ipNet)
		}

		// 네트워크 인터페이스 정보를 구조체 슬라이스에 추가
		netIfaceList = append(netIfaceList, netIface)
	}

	return netIfaceList, retErr
}

// MakeNetIfaceInfoString 네트워크 인터페이스 정보 문자열 생성
//
// Parameters:
//   - netIface: 네트워크 인터페이스 정보 구조체 포인터
//
// Returns:
//   - string: 네트워크 인터페이스 정보 문자열
func MakeNetIfaceInfoString(netIface *NetInterface) string {
	if netIface == nil {
		return ""
	}

	// 네트워크 인터페이스 정보 문자열 생성
	ifaceInfoStr := fmt.Sprintf("Name: %s, MTU: %d, HardwareAddr: %s, Flags: %s,",
		netIface.Name, netIface.MTU, netIface.HardwareAddr.String(), netIface.Flags.String())
	ifaceInfoStr += " IP:"
	for _, ipNet := range netIface.IP {
		ones, _ := ipNet.Mask.Size()
		ifaceInfoStr += fmt.Sprintf(" %s/%d", ipNet.IP.String(), ones)
	}

	return ifaceInfoStr
}
