package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/manzanit0/medbot/cmd/bot/data"
	"github.com/manzanit0/medbot/withings"
	"github.com/manzanit0/weathry/pkg/env"
	"github.com/manzanit0/weathry/pkg/middleware"
	"github.com/manzanit0/weathry/pkg/tgram"
	"golang.org/x/exp/slog"
	"golang.org/x/oauth2"
)

func init() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
}

func main() {
	// tgramClient, err := newTelegramClient()
	// if err != nil {
	// 	panic(err)
	// }

	errorTgramClient, err := env.NewErroryTgramClient()
	if err != nil {
		panic(err)
	}

	myTelegramChatID, err := env.MyTelegramChatID()
	if err != nil {
		panic(err)
	}

	withingsClient, err := withings.New(os.Getenv("WITHINGS_CLIENT_ID"), os.Getenv("WITHINGS_CLIENT_SECRET"), fmt.Sprintf("https://%s/auth/callback", os.Getenv("HOST")))
	if err != nil {
		panic(err)
	}

	r := gin.New()
	r.Use(middleware.Recovery(errorTgramClient, myTelegramChatID))
	r.Use(middleware.Logging())

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	r.GET("/auth/login", func(c *gin.Context) {
		url := withingsClient.Conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
		c.Redirect(302, url)
	})

	r.GET("/auth/callback", func(c *gin.Context) {
		grantCode := c.Query("code")
		if grantCode == "" {
			slog.Info("missing grant code")
			c.JSON(400, gin.H{
				"error": err.Error(),
			})
			return
		}

		cl := &http.Client{Transport: &withings.OAuthTransport{}}
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, cl)
		token, err := withingsClient.Conf.Exchange(ctx, grantCode)
		if err != nil {
			slog.Error("failed exchange oauth stuff", "error", err.Error())
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
		}

		withingsClient.Token = token
		withingsClient.Client = withings.GetClient(withingsClient.Conf, withingsClient.Token)

		err = data.SaveToken(token)
		if err != nil {
			slog.Error("failed save access token", "error", err.Error())
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
		}

		c.JSON(200, gin.H{
			"message": "session saved!",
		})
	})

	r.GET("/test", func(c *gin.Context) {
		token, err := data.GetToken()
		if err != nil {
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
		}

		withingsClient.Client = withings.GetClient(withingsClient.Conf, token)

		t0 := time.Now()
		adayago := t0.Add(-48 * time.Hour)
		slp, err := withingsClient.GetSleep(adayago, t0, withings.HrSleep, withings.RrSleep, withings.SnoringSleep)
		if err != nil {
			slog.Error("failed to get sleep data", "error", err.Error())
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
			return
		}

		var series []string
		for _, v := range slp.Body.Series {
			sleepState := ""
			switch withings.SleepState(v.State) {
			case withings.Awake:
				sleepState = "🙂 Awake"
			case withings.LightSleep:
				sleepState = "🥱 LightSleep"
			case withings.DeepSleep:
				sleepState = "😴 DeepSleep"
			case withings.REM:
				sleepState = "REM"
			default:
				sleepState = "Unknown"
			}

			startTimeUnix := time.Unix(v.Startdate, 0)
			endTimeUnix := time.Unix(v.Enddate, 0)

			madridTimezone := time.FixedZone("Europe/Madrid", 2*60*60)
			start := (startTimeUnix.In(madridTimezone)).Format("2006-01-02 15:04")
			end := (endTimeUnix.In(madridTimezone)).Format("2006-01-02 15:04")
			series = append(series, fmt.Sprintf("%s to %s: %s", start, end, sleepState))
		}
		c.JSON(200, gin.H{
			"sleep_series": series,
		})
	})

	r.POST("/telegram/webhook", telegramWebhookController())

	// background job to ping users on weather changes
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var port string
	if port = os.Getenv("PORT"); port == "" {
		port = "8080"
	}

	srv := &http.Server{Addr: fmt.Sprintf(":%s", port), Handler: r}
	go func() {
		slog.Info(fmt.Sprintf("serving HTTP on :%s", port))

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server shutdown abruptly", "error", err.Error())
		} else {
			slog.Info("server shutdown gracefully")
		}

		stop()
	}()

	// Listen for OS interrupt
	<-ctx.Done()
	stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err.Error())
	}

	slog.Info("server exited")
}

// @see https://core.telegram.org/bots/api#markdownv2-style
func webhookResponse(p *tgram.WebhookRequest, text string) gin.H {
	return gin.H{
		"method":     "sendMessage",
		"chat_id":    p.GetFromID(),
		"text":       text,
		"parse_mode": "MarkdownV2",
	}
}

func telegramWebhookController() func(c *gin.Context) {
	return func(c *gin.Context) {
		var p *tgram.WebhookRequest

		if i, ok := c.Get(middleware.CtxKeyPayload); ok {
			p = i.(*tgram.WebhookRequest)
		} else {
			c.JSON(400, gin.H{"error": "bad request"})
			return
		}

		c.JSON(200, webhookResponse(p, "hello, world!"))
	}
}

// func newTelegramClient() (tgram.Client, error) {
// 	var telegramBotToken string
// 	if telegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN"); telegramBotToken == "" {
// 		return nil, fmt.Errorf("missing TELEGRAM_BOT_TOKEN environment variable. Please check your environment.")
// 	}
//
// 	httpClient := whttp.NewLoggingClient()
// 	return tgram.NewClient(httpClient, telegramBotToken), nil
// }
