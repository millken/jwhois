package jwhois

import "regexp"

var as_regexp1 = regexp.MustCompile(`^[0-9]+$`)
var as_regexp2 = regexp.MustCompile(`^ASN-.+`)
var as_regexp3 = regexp.MustCompile(`AS[0-9]+$`)

var AS = map[*regexp.Regexp]string{
	as_regexp1: "whois.arin.net",
	as_regexp2: "whois.arin.net",
	as_regexp3: "whois.radb.net",
}
