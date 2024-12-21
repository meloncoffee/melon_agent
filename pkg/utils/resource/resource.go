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

package resource

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// CPUStat CPU 상태 정보 구조체
type CPUStat struct {
	User   uint64 // 사용자 모드에서 실행된 프로세스가 사용한 시간 (일반 우선순위)
	Nice   uint64 // 낮은 우선순위(NICE)로 실행된 프로세스가 사용한 시간
	System uint64 // 시스템 모드(커널)에서 실행된 작업이 사용한 시간
	Idle   uint64 // CPU가 유휴 상태로 대기한 시간
	IOWait uint64 // 디스크, 네트워크 등의 I/O 작업을 기다리며 대기한 시간
}

// MemStat 메모리 상태 정보 구조체
type MemStat struct {
	MemTotal     uint64 // 총 메모리 (kbyte)
	MemFree      uint64 // 사용 가능한 여유 메모리 (kbyte)
	MemAvailable uint64 // 애플리케이션이 사용할 수 있는 메모리 (kbyte)
	Buffers      uint64 // I/O 버퍼 메모리 (kbyte)
	Cached       uint64 // 페이지 캐시에 사용된 메모리 (kbyte)
	SwapTotal    uint64 // 총 스왑 메모리 (kbyte)
	SwapFree     uint64 // 사용 가능한 스왑 메모리 (kbyte)
}

// DiskStat 디스크 상태 정보 구조체
type DiskStat struct {
	Total uint64 // 총 디스크 크기 (byte)
	Free  uint64 // 사용 가능한 공간 (byte)
	Used  uint64 // 사용된 공간 (byte)
}

// NetworkTraffic 네트워크 트래픽 상태 정보 구조체
type NetworkTraffic struct {
	Interface   string  // 인터페이스명
	RxBytes     uint64  // 수신 바이트 (Inbound)
	TxBytes     uint64  // 송신 바이트 (Outbound)
	InboundBps  float64 // 인바운드 트래픽량 (bps)
	OutboundBps float64 // 아웃바운드 트래픽량 (bps)
}

// GetCPUStat CPU 상태 정보 획득
//
// Returns:
//   - CPUStat: CPU 상태 정보 구조체
//   - error: 성공(nil), 실패(error)
func GetCPUStat() (CPUStat, error) {
	// CPU 상태 정보 파일 읽기
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return CPUStat{}, err
	}

	// 라인 별로 분리
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// 공백을 기준으로 각 필드 파싱
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[0] == "cpu" {
			// 각 필드 값 획득
			user, _ := strconv.ParseUint(fields[1], 10, 64)
			nice, _ := strconv.ParseUint(fields[2], 10, 64)
			system, _ := strconv.ParseUint(fields[3], 10, 64)
			idle, _ := strconv.ParseUint(fields[4], 10, 64)
			iowait, _ := strconv.ParseUint(fields[5], 10, 64)

			// CPU 상태 정보 반환
			return CPUStat{
				User:   user,
				Nice:   nice,
				System: system,
				Idle:   idle,
				IOWait: iowait,
			}, nil
		}
	}

	return CPUStat{}, fmt.Errorf("CPU stats not found")
}

// CalculateCPURate CPU 사용률 계산
//
// Parameters:
//   - prev: 이전 CPU 상태 정보
//   - current: 현재 CPU 상태 정보
//
// Returns:
//   - float64: CPU 사용률
func CalculateCPURate(prev, current CPUStat) float64 {
	prevTotal := prev.User + prev.Nice + prev.System + prev.Idle + prev.IOWait
	currentTotal := current.User + current.Nice + current.System + current.Idle + current.IOWait

	totalDiff := currentTotal - prevTotal
	idleDiff := current.Idle - prev.Idle

	if totalDiff == 0 {
		return 0.0
	}

	return (float64(totalDiff-idleDiff) / float64(totalDiff)) * 100
}

// GetMemStat 메모리 상태 정보 획득
//
// Returns:
//   - MemStat: 메모리 상태 정보 구조체
//   - error: 성공(nil), 실패(error)
func GetMemStat() (MemStat, error) {
	// 메모리 상태 정보 파일 읽기
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return MemStat{}, err
	}

	memStat := MemStat{}
	// 라인 별로 분리
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// 공백을 기준으로 각 필드 파싱
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// ':' 문자 제거
		key := strings.TrimSuffix(fields[0], ":")
		// KB 단위 값 파싱
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		// 필드를 구조체에 매핑
		switch key {
		case "MemTotal":
			memStat.MemTotal = value
		case "MemFree":
			memStat.MemFree = value
		case "MemAvailable":
			memStat.MemAvailable = value
		case "Buffers":
			memStat.Buffers = value
		case "Cached":
			memStat.Cached = value
		case "SwapTotal":
			memStat.SwapTotal = value
		case "SwapFree":
			memStat.SwapFree = value
		}
	}

	return memStat, nil
}

// CalculateMemRate 메모리 사용률 계산
//
// Parameters:
//   - memStat: 메모리 상태 정보 구조체
//
// Returns:
//   - float64: 메모리 사용률
func CalculateMemRate(memStat MemStat) float64 {
	if memStat.MemTotal == 0 {
		return 0.0
	}
	used := memStat.MemTotal - memStat.MemAvailable
	return (float64(used) / float64(memStat.MemTotal)) * 100
}

// GetDiskStat 지정된 경로의 디스크 상태 정보 획득
//
// Parameters:
//   - path: 디스크 상태 정보를 획득 기준 경로
//
// Returns:
//   - DiskStat: 디스크 상태 정보 구조체
//   - error: 성공(nil), 실패(error)
func GetDiskStat(path string) (DiskStat, error) {
	var stat syscall.Statfs_t

	// 파일 시스템 통계 정보 획득
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return DiskStat{}, err
	}

	// 총 디스크 크기 계산
	total := stat.Blocks * uint64(stat.Bsize)
	// 사용 가능한 공간 계산
	free := stat.Bavail * uint64(stat.Bsize)
	// 사용된 공간 계산
	used := total - free

	// 디스크 상태 정보 반환
	return DiskStat{
		Total: total,
		Free:  free,
		Used:  used,
	}, nil
}

// CalculateDiskRate 디스크 사용률 계산
//
// Parameters:
//   - diskStat: 디스크 상태 정보 구조체
//
// Returns:
//   - float64: 디스크 사용률
func CalculateDiskRate(diskStat DiskStat) float64 {
	if diskStat.Total == 0 {
		return 0.0
	}
	return (float64(diskStat.Used) / float64(diskStat.Total)) * 100
}

// GetAllNetworkTraffic 모든 인터페이스에 대한 Rx, Tx 정보 획득
//
// Returns:
//   - []NetworkTraffic: 네트워크 트래픽 리스트
//   - error: 성공(nil), 실패(error)
func GetAllNetworkTraffic() ([]NetworkTraffic, error) {
	// 네트워크 트래픽 상태 정보 파일 읽기
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var trafficList []NetworkTraffic

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// 인터페이스명 추출
		interfaceName := strings.TrimSuffix(fields[0], ":")
		// lo 인터페이스는 무시
		if interfaceName == "lo" {
			continue
		}
		// 수신 바이트 획득
		rxBytes, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		// 송신 바이트 획득
		txBytes, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}

		// 리스트에 추가
		trafficList = append(trafficList, NetworkTraffic{
			Interface: interfaceName,
			RxBytes:   rxBytes,
			TxBytes:   txBytes,
		})
	}

	return trafficList, nil
}

// CalculateNetworkTraffic 인터페이스 별 네트워크 트래픽량 계산 (bps)
//
// Parameters:
//   - prev: 이전 네트워크 트래픽 상태 정보 리스트
//   - current: 현재 네트워크 트래픽 상태 정보 리스트
//   - intervalSec: bps 측정 간격 시간 (초)
//
// Returns:
//   - []NetworkTraffic: 네트워크 트래픽량 리스트
//   - error: 성공(nil), 실패(error)
func CalculateNetworkTraffic(prev, current []NetworkTraffic, intervalSec float64) ([]NetworkTraffic, error) {
	var trafficList []NetworkTraffic

	if intervalSec == 0.0 {
		return nil, fmt.Errorf("interval seconds is zero")
	}

	for _, t1 := range prev {
		for _, t2 := range current {
			if t1.Interface != t2.Interface {
				continue
			}
			inboundBytes := t2.RxBytes - t1.RxBytes
			outboundBytes := t2.TxBytes - t1.TxBytes

			// bps 계산 (bytes -> Bits로 변환)
			inboundBps := float64(inboundBytes*8) / intervalSec
			outboundBps := float64(outboundBytes*8) / intervalSec

			trafficList = append(trafficList, NetworkTraffic{
				Interface:   t2.Interface,
				InboundBps:  inboundBps,
				OutboundBps: outboundBps,
			})
		}
	}

	if len(trafficList) == 0 {
		return nil, fmt.Errorf("failed to get network traffic")
	}

	return trafficList, nil
}
