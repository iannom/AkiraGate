package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"aimilivpn/userspace-gateway/internal/manager"
)

func main() {
	defaultConfig := filepath.Join(defaultDataDir(), "config.json")
	configPath := flag.String("config", getenv("AIMILI_CONFIG", defaultConfig), "AimiliVPN Go server configuration path")
	webRoot := flag.String("web-root", getenv("AIMILI_WEB_ROOT", filepath.Join("frontend", "dist")), "AimiliVPN frontend static files directory")
	flag.Parse()

	logBuffer := manager.NewLogBuffer(500)
	logger := slog.New(manager.NewTeeHandler(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		logBuffer.Handler(),
	))
	config, err := manager.LoadConfig(*configPath)
	if err != nil {
		logger.Error("读取配置失败", "error", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	server := manager.NewServer(*configPath, config, logger, logBuffer)
	if err := server.SetWebRoot(*webRoot); err != nil {
		logger.Error("读取前端静态目录失败", "path", *webRoot, "error", err)
		os.Exit(2)
	}
	if err := server.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("管理服务退出", "error", err)
		os.Exit(1)
	}
}

func defaultDataDir() string {
	if value := os.Getenv("AIMILI_DATA_DIR"); value != "" {
		return value
	}
	return "aimili_data"
}

func getenv(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}
