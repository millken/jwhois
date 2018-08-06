package jwhois

import "regexp"

var tmp = make([]*regexp.Regexp, 0)
var regexp1 = regexp.MustCompile(`.*[Ww][Hh][Oo][Ii][Ss] Server: (.*)`)
var regexp2 = regexp.MustCompile(`.*at ([Ww][Hh][Oo][Ii][Ss]\.[A-Za-z]*\.[Nn][Ee][Tt])`)
var regexp3 = regexp.MustCompile(`r?whois:\/\/([^:]*):?([0-9]*)?\/?$`)

var RedirectServer = map[string][]*regexp.Regexp{
	"whois.verisign-grs.com":   append(tmp, regexp1),
	"ccwhois.verisign-grs.com": append(tmp, regexp1),
	"tvwhois.verisign-grs.com": append(tmp, regexp1),
	"whois.apnic.net":          append(tmp, regexp2),
	"whois.arin.net":           append(tmp, regexp2, regexp3),
}
