package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"akiragate/userspace-gateway/internal/manager"
)

func main() {
	defaultConfig := filepath.Join(defaultDataDir(), "config.json")
	configPath := flag.String("config", getenv("AKIRAGATE_CONFIG", defaultConfig), "AkiraGate Go server configuration path")
	webRoot := flag.String("web-root", getenv("AKIRAGATE_WEB_ROOT", filepath.Join("frontend", "dist")), "AkiraGate frontend static files directory")
	hashPasswordMode := flag.Bool("hash-password", false, "Read an admin password from stdin and print a bcrypt hash")
	flag.Parse()

	if *hashPasswordMode {
		hashPasswordFromStdin()
		return
	}

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

func hashPasswordFromStdin() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取密码失败: %v\n", err)
		os.Exit(2)
	}
	password := strings.TrimRight(string(data), "\r\n")
	hash, err := manager.HashPassword(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "生成密码哈希失败: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(hash)
}

func defaultDataDir() string {
	if value := os.Getenv("AKIRAGATE_DATA_DIR"); value != "" {
		return value
	}
	return "akiragate_data"
}

func getenv(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}
