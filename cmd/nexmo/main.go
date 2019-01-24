package main

import (
	"fmt"
	"github.com/judy2k/nexmo/pkg/client"
)

func main() {
	c := client.NewClient()
	fmt.Printf("Client: %v\n", c)
	//c.SendSMS(client.SMSMessage{
	//
	//})
}

