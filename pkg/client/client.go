package client

import (
	"github.com/judy2k/nexmo/internal/auth"
	"net/http"
	"time"
)

type SMSMessage interface {
}

type TextSMSMessage struct {
	From string `url:"from"`
	To   string `url:"to"`
	Text string `url:"text"`
}

type Client interface {
	SendSMS(SMSMessage)
}

type client struct {
	httpClient *http.Client
}

func (c *client) SendSMS(message SMSMessage) {
	c.httpClient.Post()
}

func NewClient(credentials ...auth.Credentials) Client {
	return &client{
		httpClient: &http.Client{
			Timeout: time.Second * 3	,
		},
	}
}
