package core

// LogFunc is a function type for logging
type LogFunc func(format string, v ...any)

const (
	LOG_DEBUG = 0
	LOG_ERROR = 1
	LOG_WARN  = 2
	LOG_INFO  = 3
)

var (
	// defaultLogger is the global logger that can be set by the application
	logger LogFunc = nil
	level          = LOG_INFO
)

// SetLogger sets the global logger for the core package
// If logger is nil, logging will be disabled
func SetLogger(l LogFunc) {
	logger = l
}

func SetLogLevel(lv int) {
	level = lv
}

// logf logs a message using the global logger if set
func logf(format string, v ...any) {
	if logger != nil {
		logger(format, v...)
	}
}

// logDebug logs a debug message (only if logger is set)
func logDebug(format string, v ...any) {
	if level != LOG_DEBUG {
		return
	}
	logf("[DEBUG] "+format, v...)
}

// logInfo logs an info message
func logInfo(format string, v ...any) {
	if level < LOG_INFO {
		return
	}
	logf("[INFO] "+format, v...)
}

// logWarn logs a warning message
func logWarn(format string, v ...any) {
	if level < LOG_WARN {
		return
	}
	logf("[WARN] "+format, v...)
}

// logError logs an error message
func logError(format string, v ...any) {
	if level < LOG_ERROR {
		return
	}
	logf("[ERROR] "+format, v...)
}
