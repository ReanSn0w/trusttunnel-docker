package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-pkgz/lgr"
	flags "github.com/jessevdk/go-flags"

	"github.com/reansnow/trusttunnel-controller/internal/app"
)

var (
	version = "dev"
	commit  = "unknown"
)

type options struct {
	DataDir        string        `long:"data-dir" env:"TT_DATA_DIR" default:"/var/lib/trusttunnel" description:"Persistent data directory"`
	EndpointBinary string        `long:"endpoint-binary" env:"TT_ENDPOINT_BINARY" default:"/usr/local/bin/trusttunnel_endpoint" description:"Official endpoint binary"`
	UIListen       string        `long:"ui-listen" env:"TT_UI_LISTEN" default:"127.0.0.1:8080" description:"Admin UI listener"`
	MetricsURL     string        `long:"metrics-url" env:"TT_METRICS_URL" default:"http://127.0.0.1:9090/metrics" description:"Internal endpoint metrics URL"`
	ProbeListen    string        `long:"probe-listen" env:"TT_PROBE_LISTEN" default:"127.0.0.1:8081" description:"Health/readiness listener"`
	StartTimeout   time.Duration `long:"start-timeout" env:"TT_START_TIMEOUT" default:"15s" description:"Endpoint start timeout"`
	StopTimeout    time.Duration `long:"stop-timeout" env:"TT_STOP_TIMEOUT" default:"10s" description:"Endpoint graceful stop timeout"`
	LogFormat      string        `long:"log-format" env:"TT_LOG_FORMAT" choice:"json" choice:"text" default:"json" description:"Log encoding"`
	LogLevel       string        `long:"log-level" env:"TT_LOG_LEVEL" default:"info" description:"Log severity"`
	ShowVersion    bool          `long:"version" description:"Print version and exit"`
}

func run(args []string) error {
	var opts options
	parser := flags.NewParser(&opts, flags.Default)
	if _, err := parser.ParseArgs(args); err != nil {
		var flagErr *flags.Error
		if errors.As(err, &flagErr) && flagErr.Type == flags.ErrHelp {
			return nil
		}
		return err
	}
	if opts.ShowVersion {
		fmt.Printf("trusttunnel-controller %s (%s)\n", version, commit)
		return nil
	}

	logOpts := []lgr.Option{lgr.LevelBraces}
	if opts.LogFormat == "json" {
		logOpts = append(logOpts, lgr.Format(`{"time":"{{.DT.Format "2006-01-02T15:04:05.000Z07:00"}}","level":"{{.Level}}","message":{{printf "%q" .Message}}}`))
	}
	log := lgr.New(logOpts...)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	cfg := app.Config{
		DataDir: opts.DataDir, EndpointBinary: opts.EndpointBinary,
		UIListen: opts.UIListen, MetricsURL: opts.MetricsURL,
		ProbeListen: opts.ProbeListen, StartTimeout: opts.StartTimeout,
		StopTimeout: opts.StopTimeout, Version: version, Commit: commit,
	}
	return app.Run(ctx, cfg, log)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "controller:", err)
		os.Exit(1)
	}
}
