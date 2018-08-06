package jwhois

import (
	"strings"
	"testing"
)

func TestWhoisDomain(t *testing.T) {
	data, err := Whois("baidu.com")
	if err != nil {
		t.Error("whois failed with error:", err)
		return
	}
	strings.Contains(string(data), "BAIDU.COM")
}

func TestWhoisAS(t *testing.T) {
	data, err := Whois("AS24406")
	if err != nil {
		t.Error("whois failed with error:", err)
		return
	}
	strings.Contains(string(data), "AS24406")
}

func TestWhoisARIN(t *testing.T) {
	_, err := Whois("INTERNET-BLK-A2HOS-2")
	if err != nil {
		t.Error("whois failed with error:", err)
		return
	}
}

func TestWhoisIP(t *testing.T) {
	_, err := Whois("223.35.2.2")
	if err != nil {
		t.Error("whois failed with error:", err)
		return
	}
}

func TestWhoisIPV6(t *testing.T) {
	_, err := Whois("2404:6800:4005:806::200e")
	if err != nil {
		t.Error("whois failed with error:", err)
		return
	}
}
