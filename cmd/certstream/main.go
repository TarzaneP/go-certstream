package main

import (
	"context"
	"github.com/charmbracelet/log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LeakIX/go-certstream"
)

func init() {
	//reasonable defaults for defaultHttpClient
	http.DefaultClient.Timeout = 30 * time.Second
}

func main() {
	cs, err := certstream.NewCertstream(getOptions()...)
	if err != nil {
		panic(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cs.Run(ctx); err != nil {
		log.Warn(err)
	}
	log.Info("certstream terminated")
}

func getOptions() (options []certstream.Option) {
	if listenAddr, found := os.LookupEnv("WEBSOCKET_LISTEN"); found {
		options = append(options, certstream.WithWebSocketListen(listenAddr))
	}
	if customLogList, found := os.LookupEnv("CUSTOM_LOG_LIST"); found {
		options = append(options, certstream.WithCustomLogList(customLogList))
	}
	return
}
