package main

import (
	"fmt"
	"time"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorGray   = "\033[37m"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarning
	LevelError
)

func parseLogLevel(s string) LogLevel {
	switch s {
	case "debug":
		return LevelDebug
	case "warning":
		return LevelWarning
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

type Logger struct {
	Level      LogLevel
	Components map[string]bool
	UseColor   bool
	UseJSON    bool
}

func (l *Logger) log(level LogLevel, component string, message string) {
	if level < l.Level {
		return
	}
	if component != "" && !l.Components[component] {
		return
	}

	timestamp := time.Now().Format(time.RFC3339)
	levelStr := ""
	color := ""

	switch level {
	case LevelDebug:
		levelStr = "DEBUG"
		color = ColorGray
	case LevelInfo:
		levelStr = "INFO"
		color = ColorGreen
	case LevelWarning:
		levelStr = "WARNING"
		color = ColorYellow
	case LevelError:
		levelStr = "ERROR"
		color = ColorRed
	}

	if l.UseJSON {
		fmt.Printf(`{"time":"%s","level":"%s","component":"%s","message":"%s"}`+"\n", timestamp, levelStr, component, message)
		return
	}

	if l.UseColor {
		fmt.Printf("%s%s [%s] (%s) %s%s\n", color, timestamp, levelStr, component, message, ColorReset)
	} else {
		fmt.Printf("%s [%s] (%s) %s\n", timestamp, levelStr, component, message)
	}
}

func (l *Logger) Debug(component, format string, v ...interface{}) {
	l.log(LevelDebug, component, fmt.Sprintf(format, v...))
}

func (l *Logger) Info(component, format string, v ...interface{}) {
	l.log(LevelInfo, component, fmt.Sprintf(format, v...))
}

func (l *Logger) Warning(component, format string, v ...interface{}) {
	l.log(LevelWarning, component, fmt.Sprintf(format, v...))
}

func (l *Logger) Error(component, format string, v ...interface{}) {
	l.log(LevelError, component, fmt.Sprintf(format, v...))
}
