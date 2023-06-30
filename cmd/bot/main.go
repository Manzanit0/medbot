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

	client, err := withings.New(os.Getenv("WITHINGS_CLIENT_ID"), os.Getenv("WITHINGS_CLIENT_SECRET"), fmt.Sprintf("https://%s", os.Getenv("HOST")))
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
		url := client.Conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
		// u, err := url.Parse("https://account.withings.com/oauth2_user/authorize2")
		// if err != nil {
		// 	slog.Error("failed to parse URL, WTF?", "error", err.Error())
		// 	c.JSON(500, gin.H{
		// 		"error": err.Error(),
		// 	})
		// }

		// q := url.Values{}
		// q.Set("access_type", "offline")
		// q.Set("client_id", os.Getenv("WITHINGS_CLIENT_ID"))
		// q.Set("redirect_uri", fmt.Sprintf("https://%s/auth/callback", os.Getenv("HOST")))
		// q.Set("response_type", "code")
		// q.Set("scope", "user.activity,user.metrics,user.info")
		// q.Set("state", "foo")
		// u.RawQuery = fmt.Sprintf("?%s", q.Encode())

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
		token, err := client.Conf.Exchange(ctx, grantCode)
		if err != nil {
			slog.Error("failed exchange oauth stuff", "error", err.Error())
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
		}

		client.Token = token
		client.Client = withings.GetClient(client.Conf, client.Token)

		err = data.SaveToken(token)
		if err != nil {
			slog.Error("failed save access token", "error", err.Error())
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
		}

		c.JSON(200, gin.H{
			"message": "session saved",
		})
	})

	r.GET("/test", func(c *gin.Context) {
		token, err := data.GetToken()
		if err != nil {
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
		}

		client.Client = withings.GetClient(client.Conf, token)

		t0 := time.Now()
		adayago := t0.Add(-48 * time.Hour)
		slp, err := client.GetSleep(adayago, t0, withings.HrSleep, withings.RrSleep, withings.SnoringSleep)
		if err != nil {
			slog.Error("failed to get sleep data", "error", err.Error())
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
			return
		}

		var message string

		for _, v := range slp.Body.Series {
			st := ""
			switch v.State {
			case int(withings.Awake):
				st = "Awake"
			case int(withings.LightSleep):
				st = "LightSleep"
			case int(withings.DeepSleep):
				st = "DeepSleep"
			case int(withings.REM):
				st = "REM"
			default:
				st = "Unknown"
			}

			startTimeUnix := time.Unix(v.Startdate, 0)
			endTimeUnix := time.Unix(v.Enddate, 0)

			madridTimezone := time.FixedZone("Europe/Madrid", 2*60*60)
			stime := (startTimeUnix.In(madridTimezone)).Format("2006-01-02 15:04:05")
			etime := (endTimeUnix.In(madridTimezone)).Format("2006-01-02 15:04:05")
			message += fmt.Sprintf("%s to %s: %s, Hr:%d, Rr:%d, Snoring:%d\n", stime, etime, st, v.Hr, v.Rr, v.Snoring)
		}
		c.JSON(200, gin.H{
			"message": message,
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
