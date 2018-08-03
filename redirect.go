package jwhois

import "regexp"

var regexp1 = regexp.MustCompile(`.*[Ww][Hh][Oo][Ii][Ss] Server: (.*)`)
var RedirectServer = map[string]*regexp.Regexp{
	"whois.verisign-grs.com":   regexp1,
	"ccwhois.verisign-grs.com": regexp1,
	"tvwhois.verisign-grs.com": regexp1,
}
