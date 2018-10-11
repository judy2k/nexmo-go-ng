package requestbuilder

import "net/url"

type RequestBuilder struct {
	Method string
	Url string
	Params url.Values
}