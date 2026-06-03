package vpn

import "log/slog"

type ovpnLogger struct {
	logger *slog.Logger
}

func newOvpnLogger(logger *slog.Logger) *ovpnLogger {
	return &ovpnLogger{logger: logger}
}

func (l *ovpnLogger) Debugf(format string, args ...any) {
	l.logger.Debug("openvpn", "message", sprintf(format, args...))
}
func (l *ovpnLogger) Infof(format string, args ...any) {
	l.logger.Info("openvpn", "message", sprintf(format, args...))
}
func (l *ovpnLogger) Warnf(format string, args ...any) {
	l.logger.Warn("openvpn", "message", sprintf(format, args...))
}
func (l *ovpnLogger) Errorf(format string, args ...any) {
	l.logger.Error("openvpn", "message", sprintf(format, args...))
}

func sprintf(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	return fmtSprintf(format, args...)
}
