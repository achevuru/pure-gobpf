package logger

import (
    "os"
    "fmt"

    logrus "github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Logger
}

const LOG_FILE = "/var/log/aws-routed-eni/ebpf-sdk.log"
var log *Logger

func Get() *Logger {
	if log == nil {
		log = New()
		log.Info("Initialized new logger as an existing instance was not found")
	}
	return log
}

func New() *Logger {
	f, err := os.OpenFile(LOG_FILE, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Failed to create logfile" + LOG_FILE)
		panic(err)
	}

	var baseLogger = logrus.New()
	var standardLogger = &Logger{baseLogger}
	standardLogger.Formatter = &logrus.JSONFormatter{}

	standardLogger.SetOutput(f)
	standardLogger.Info("Constructed new logger instance")
	return standardLogger
}
