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

package logger

import (
	"fmt"
	"os"
	"strings"

	"github.com/meloncoffee/melon_agent/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger 인터페이스
type Logger interface {
	InitializeLogger()
	FinalizeLogger()
	LogInfo(format string, args ...interface{})
	LogWarn(format string, args ...interface{})
	LogError(format string, args ...interface{})
	LogDebug(format string, args ...interface{})
	LogPanic(format string, args ...interface{})
	LogFatal(format string, args ...interface{})
}

// SyncLogger 로그 관리 정보 구조체
type SyncLogger struct {
	fileLogger *lumberjack.Logger
	zapLogger  *zap.Logger
}

var Log Logger = &SyncLogger{}

// InitializeLogger 로거 초기화
func (s *SyncLogger) InitializeLogger() {
	var cores []zapcore.Core

	// Lumberjack 생성 (자동으로 로그 파일 관리)
	s.fileLogger = s.newLumberJackLogger(config.LogFilePath)

	// 인코더 설정
	encoderConfig := zapcore.EncoderConfig{
		MessageKey:       "msg",
		LevelKey:         "level",
		TimeKey:          "time",
		CallerKey:        "caller",
		FunctionKey:      zapcore.OmitKey,
		StacktraceKey:    "stacktrace",
		LineEnding:       zapcore.DefaultLineEnding,
		EncodeLevel:      s.capitalLevelEncoder,
		EncodeTime:       zapcore.TimeEncoderOfLayout("[2006-01-02 15:04:05]"),
		EncodeDuration:   zapcore.SecondsDurationEncoder,
		EncodeCaller:     s.wrapShortCallerEncoder,
		ConsoleSeparator: " ",
	}

	// 콘솔 인코더 생성
	consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)

	// 파일 로그 출력을 위한 코어 설정
	fileWriter := zapcore.AddSync(s.fileLogger)
	// 파일 로그 코어 추가
	cores = append(cores, zapcore.NewCore(consoleEncoder, fileWriter, zapcore.DebugLevel))

	// 디버그 모드일 경우 로그를 콘솔로도 출력
	if config.RunConf.DebugMode {
		stdoutLevel := zap.LevelEnablerFunc(func(level zapcore.Level) bool {
			return level < zapcore.ErrorLevel
		})
		stderrLevel := zap.LevelEnablerFunc(func(level zapcore.Level) bool {
			return level >= zapcore.ErrorLevel
		})
		consoleOut := zapcore.AddSync(os.Stdout)
		consoleErr := zapcore.AddSync(os.Stderr)
		cores = append(cores, zapcore.NewCore(consoleEncoder, consoleOut, stdoutLevel))
		cores = append(cores, zapcore.NewCore(consoleEncoder, consoleErr, stderrLevel))
	}

	// 코어 생성
	core := zapcore.NewTee(cores...)

	// 코어로 부터 로거 생성
	s.zapLogger = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1),
		zap.AddStacktrace(zapcore.PanicLevel))
}

// FinalizeLogger 프로그램 종료 시 로그 자원 정리
func (s *SyncLogger) FinalizeLogger() {
	// 버퍼에 남아있는 로그를 전부 파일에 기록
	s.zapLogger.Sync()
	// 열려 있는 로그 파일을 닫아줌
	s.fileLogger.Close()
}

// newLumberJackLogger Lumberjack 생성
//
// Parameters:
//   - logFilePath: 로그 파일 경로
//
// Returns:
//   - *lumberjack.Logger
func (s *SyncLogger) newLumberJackLogger(logFilePath string) *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    config.Conf.Log.MaxLogFileSize,
		MaxBackups: config.Conf.Log.MaxLogFileBackup,
		MaxAge:     config.Conf.Log.MaxLogFileAge,
		Compress:   config.Conf.Log.CompBakLogFile,
	}
}

// capitalLevelEncoder zapcore의 CapitalLevelEncoder() 메서드 커스터마이징 함수
// Parameters:
//   - l: zapcore 로그 레벨
//   - enc: zapcore 배열 인터페이스
func (s *SyncLogger) capitalLevelEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString("[" + l.CapitalString() + "]")
}

// wrapShortCallerEncoder zapcore의 ShortCallerEncoder() 메서드 커스터마이징 함수
//
// Parameters:
//   - caller: 로깅 호출 함수 콜러
//   - enc: zapcore 배열 인터페이스
func (s *SyncLogger) wrapShortCallerEncoder(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
	fileIdx := -1
	funcIdx := -1

	if !caller.Defined {
		enc.AppendString("[undefined]")
		return
	}

	// 파일명 추출
	if fileIdx = strings.LastIndex(caller.File, "/"); fileIdx == -1 {
		enc.AppendString(fmt.Sprintf("[%s-%s()]", caller.FullPath(), caller.Function))
		return
	}

	// 함수명 추출
	if funcIdx = strings.LastIndex(caller.Function, "."); funcIdx == -1 {
		enc.AppendString(fmt.Sprintf("[%s-%s()]", caller.FullPath(), caller.Function))
		return
	}

	// Caller 메시지 생성
	enc.AppendString(fmt.Sprintf("[%s:%d-%s()]", caller.File[fileIdx+1:], caller.Line,
		caller.Function[funcIdx+1:]))
}

// LogInfo 로그 기록 (로그 레벨:INFO)
//
// Parameters:
//   - format: 로그 메시지
//   - args: 가변 인자
func (s *SyncLogger) LogInfo(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	s.zapLogger.Info(message)
}

// LogWarn 로그 기록 (로그 레벨:WARN)
//
// Parameters:
//   - format: 로그 메시지
//   - args: 가변 인자
func (s *SyncLogger) LogWarn(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	s.zapLogger.Warn(message)
}

// LogError 로그 기록 (로그 레벨:ERROR)
//
// Parameters:
//   - format: 로그 메시지
//   - args: 가변 인자
func (s *SyncLogger) LogError(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	s.zapLogger.Error(message)
}

// LogDebug 로그 기록 (로그 레벨:DEBUG)
//
// Parameters:
//   - format: 로그 메시지
//   - args: 가변 인자
func (s *SyncLogger) LogDebug(format string, args ...interface{}) {
	if config.RunConf.DebugMode {
		message := fmt.Sprintf(format, args...)
		s.zapLogger.Debug(message)
	}
}

// LogPanic 로그 기록 (로그 레벨:PANIC)
// 주의: panic 발생
//
// Parameters:
//   - format: 로그 메시지
//   - args: 가변 인자
func (s *SyncLogger) LogPanic(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	s.zapLogger.Panic(message)
}

// LogFatal 로그 기록 (로그 레벨:FATAL)
// 주의: os.Exit(1) 실행
//
// Parameters:
//   - format: 로그 메시지
//   - args: 가변 인자
func (s *SyncLogger) LogFatal(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	s.zapLogger.Fatal(message)
}
