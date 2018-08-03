package jwhois

import "regexp"

var arin_regexp1 = regexp.MustCompile(`^!?INTERNET(|[6])(BLK)?(-[A-Z0-9]+)+$`)

var ARIN = map[*regexp.Regexp]string{
	arin_regexp1: "whois.arin.net",
}

var ARINQueryFormat = map[*regexp.Regexp]string{
	arin_regexp1: "z %s",
}
