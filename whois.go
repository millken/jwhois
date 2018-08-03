package jwhois

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"regexp"
	"strings"
	"time"
)

var ErrLimitExceeded = errors.New("Whois Limit Exceeded")

var (
	reLimitExceeded = regexp.MustCompile(`(?i:LIMIT EXCEEDED|queries exceeded)`)
	reParam         = regexp.MustCompile(`[\r\n]\s*([a-zA-Z0-9\- /\\_]+):\s*(.*)`)
)

func Whois(data string) (body []byte, err error) {
	ri, err := getRecordInfo(data)
	if err != nil {
		return nil, err
	}
	body, err = WhoisByServer(fmt.Sprintf(ri.QueryFormat, data), ri.WhoisServer)
	if err != nil {
		return nil, err
	}

	//check redirect whois
	if re, ok := RedirectServer[ri.WhoisServer]; ok {
		ref := re.FindSubmatch(body)
		if len(ref) > 1 {
			return WhoisByServer(data, strings.TrimSpace(string(ref[1])))
		}
	}
	return body, err
}
func WhoisByServer(data, server string) (body []byte, err error) {
	conn, err := net.Dial("tcp", server+":43")
	if err != nil {
		return
	}
	defer conn.Close()

	// write request
	if err = conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	if _, err = conn.Write([]byte(data + "\r\n")); err != nil {
		return
	}

	// read response
	if err = conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}

	if body, err = ioutil.ReadAll(conn); err != nil {
		return
	}
	return
}
