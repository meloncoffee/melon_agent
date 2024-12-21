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

package metric

import (
	"github.com/meloncoffee/melon_agent/internal/resourcecollector"
	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "melon_agent_"

// Metrics Prometheus와 연동하기 위한 구조체
type Metrics struct {
	CPUUsageRate  *prometheus.Desc
	MemUsageRate  *prometheus.Desc
	DiskUsageRate *prometheus.Desc
	NetworkInBps  *prometheus.Desc
	NetworkOutBps *prometheus.Desc
}

// NewMetrics Metrics 구조체 초기화 및 생성
//
// Returns:
//   - Metrics: 초기화된 Metrics 구조체
func NewMetrics() Metrics {
	m := Metrics{
		CPUUsageRate: prometheus.NewDesc(
			namespace+"cpu_usage_rate",
			"Current CPU usage in percentage",
			nil, nil,
		),
		MemUsageRate: prometheus.NewDesc(
			namespace+"memory_usage_rate",
			"Current memory usage in percentage",
			nil, nil,
		),
		DiskUsageRate: prometheus.NewDesc(
			namespace+"disk_usage_rate",
			"Current disk usage in percentage",
			nil, nil,
		),
		NetworkInBps: prometheus.NewDesc(
			namespace+"network_inbound_bps",
			"Current network inbound traffic in bps for all interfaces",
			[]string{"interface"},
			nil,
		),
		NetworkOutBps: prometheus.NewDesc(
			namespace+"network_outbound_bps",
			"Current network outbound traffic in bps for all interfaces",
			[]string{"interface"},
			nil,
		),
	}

	return m
}

// Describe Prometheus Collector 인터페이스의 필수 메서드로,
// 수집기(collector)가 제공할 수 있는 메트릭을 사전에 정의
//
// Parameters:
//   - ch: Prometheus가 메트릭의 정의를 수집할 때 사용하는 채널
func (m Metrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.CPUUsageRate
	ch <- m.MemUsageRate
	ch <- m.DiskUsageRate
	ch <- m.NetworkInBps
	ch <- m.NetworkOutBps
}

// Collect Prometheus Collector 인터페이스의 필수 메서드로,
// 리소스를 수집하여 메트릭으로 변환
//
// Parameters:
//   - ch: Prometheus가 메트릭 데이터를 수집할 때 사용하는 채널
func (m Metrics) Collect(ch chan<- prometheus.Metric) {
	resourcecollector.ResMutex.RLock()
	defer resourcecollector.ResMutex.RUnlock()

	// 현재 사용 가능한 리소스 정보 구조체 포인터 획득
	resInfo := resourcecollector.GetCurrResInfo()

	// CPU 사용률 메트릭 수집
	ch <- prometheus.MustNewConstMetric(
		m.CPUUsageRate,
		prometheus.GaugeValue,
		resInfo.CPUUsageRate,
	)
	// Memory 사용률 메트릭 수집
	ch <- prometheus.MustNewConstMetric(
		m.MemUsageRate,
		prometheus.GaugeValue,
		resInfo.MemUsageRate,
	)
	// Disk 사용률 메트릭 수집
	ch <- prometheus.MustNewConstMetric(
		m.DiskUsageRate,
		prometheus.GaugeValue,
		resInfo.DiskUsageRate,
	)

	if len(resInfo.NetTraffic) > 0 {
		// 네트워크 트래픽 메트릭 수집 (인터페이스별)
		for _, traffic := range resInfo.NetTraffic {
			// 네트워크 Inbound 트래픽 메트릭 수집
			ch <- prometheus.MustNewConstMetric(
				m.NetworkInBps,
				prometheus.GaugeValue,
				traffic.InboundBps,
				traffic.Interface, // 라벨 값으로 인터페이스 이름 전달
			)

			// 네트워크 Outbound 트래픽 메트릭 수집
			ch <- prometheus.MustNewConstMetric(
				m.NetworkOutBps,
				prometheus.GaugeValue,
				traffic.OutboundBps,
				traffic.Interface, // 라벨 값으로 인터페이스 이름 전달
			)
		}
	} else {
		ch <- prometheus.MustNewConstMetric(
			m.NetworkInBps,
			prometheus.GaugeValue,
			float64(0.0),
			"unknown",
		)
		ch <- prometheus.MustNewConstMetric(
			m.NetworkOutBps,
			prometheus.GaugeValue,
			float64(0.0),
			"unknown",
		)
	}
}
