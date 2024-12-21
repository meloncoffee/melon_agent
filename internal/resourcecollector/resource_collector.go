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

package resourcecollector

import (
	"context"
	"sync"
	"time"

	"github.com/meloncoffee/melon_agent/internal/logger"
	"github.com/meloncoffee/melon_agent/pkg/utils/goroutine"
	"github.com/meloncoffee/melon_agent/pkg/utils/resource"
)

var ResMutex sync.RWMutex
var resInfo [2]ResourceInfo
var currUseIdx int

type ResourceInfo struct {
	CPUUsageRate  float64
	MemUsageRate  float64
	DiskUsageRate float64
	NetTraffic    []resource.NetworkTraffic
}

type ResourceCollector struct {
	wg sync.WaitGroup
}

// GetCurrResInfo 현재 사용 가능한 리소스 정보 구조체 포인터 반환
//
// Returns:
//   - *ResourceInfo: 리소스 정보 구조체
func GetCurrResInfo() *ResourceInfo {
	return &resInfo[currUseIdx]
}

// Run 서버 리소스 정보 수집
//
// Parameters:
//   - ctx: 종료 컨텍스트
func (r *ResourceCollector) Run(ctx context.Context) {
	var timeout time.Duration

	for goroutine.WaitTimeout == goroutine.WaitCancelWithTimeout(ctx, timeout) {
		timeout = 3 * time.Second

		// 사용 중이지 않은 인덱스 획득
		notUseIdx := currUseIdx ^ 1
		resInfo[notUseIdx] = ResourceInfo{}

		// CPU 사용률 획득
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			var err error
			resInfo[notUseIdx].CPUUsageRate, err = r.getCPUUsage()
			if err != nil {
				logger.Log.LogWarn("%v", err)
			}
		}()
		// 메모리 사용률 획득
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			var err error
			resInfo[notUseIdx].MemUsageRate, err = r.getMemUsage()
			if err != nil {
				logger.Log.LogWarn("%v", err)
			}
		}()
		// 디스크 사용률 획득
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			var err error
			resInfo[notUseIdx].DiskUsageRate, err = r.getDiskUsage()
			if err != nil {
				logger.Log.LogWarn("%v", err)
			}
		}()
		// 네트워크 트래픽 사용량 획득
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			var err error
			resInfo[notUseIdx].NetTraffic, err = r.getNetworkTraffic()
			if err != nil {
				logger.Log.LogWarn("%v", err)
			}
		}()

		// 리소스 정보 수집 고루틴들 작업 종료 대기
		r.wg.Wait()

		// 리소스 수집이 완료 됐다면, 인덱스를 바꿔줌
		ResMutex.Lock()
		currUseIdx ^= 1
		ResMutex.Unlock()
	}
}

// getCPUUsage CPU 사용률 획득
//
// Returns:
//   - float64: CPU 사용률
//   - error: 성공(nil), 실패(error)
func (r *ResourceCollector) getCPUUsage() (float64, error) {
	// 이전 CPU 상태 정보 획득
	prevCpuStat, err := resource.GetCPUStat()
	if err != nil {
		return 0.0, err
	}

	// 1초 대기
	time.Sleep(1 * time.Second)

	// 현재 CPU 상태 정보 획득
	currCpuStat, err := resource.GetCPUStat()
	if err != nil {
		return 0.0, err
	}

	// CPU 사용률 계산
	cpuUsageRate := resource.CalculateCPURate(prevCpuStat, currCpuStat)

	return cpuUsageRate, nil
}

// getMemUsage 메모리 사용률 획득
//
// Returns:
//   - float64: 메모리 사용률
//   - error: 성공(nil), 실패(error)
func (r *ResourceCollector) getMemUsage() (float64, error) {
	// 메모리 상태 정보 획득
	memStat, err := resource.GetMemStat()
	if err != nil {
		return 0.0, err
	}

	// 메모리 사용률 계산
	memUsageRate := resource.CalculateMemRate(memStat)

	return memUsageRate, nil
}

// getDiskUsage 디스크 사용률 획득
//
// Returns:
//   - float64: 디스크 사용률
//   - error: 성공(nil), 실패(error)
func (r *ResourceCollector) getDiskUsage() (float64, error) {
	// 디스크 상태 정보 획득
	diskStat, err := resource.GetDiskStat("/")
	if err != nil {
		return 0.0, err
	}

	// 디스크 사용률 계산
	diskUsageRate := resource.CalculateDiskRate(diskStat)

	return diskUsageRate, nil
}

// getNetworkTraffic 네트워크 트래픽 사용량 획득
//
// Returns:
//   - []resource.NetworkTraffic: 네트워크 트래픽 정보 구조체 슬라이스
//   - error: 성공(nil), 실패(error)
func (r *ResourceCollector) getNetworkTraffic() ([]resource.NetworkTraffic, error) {
	// 이전 네트워크 트래픽 사용량 획득
	prevNetTraffic, err := resource.GetAllNetworkTraffic()
	if err != nil {
		return nil, err
	}

	// 1초 대기
	time.Sleep(1 * time.Second)

	// 이전 네트워크 트래픽 사용량 획득
	currNetTraffic, err := resource.GetAllNetworkTraffic()
	if err != nil {
		return nil, err
	}

	// 네트워크 트래픽 사용량 계산
	netTrafficUsage, err := resource.CalculateNetworkTraffic(prevNetTraffic, currNetTraffic, float64(1))
	if err != nil {
		return nil, err
	}

	return netTrafficUsage, nil
}
