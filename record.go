package jwhois

import (
	"errors"
	"net"
	"regexp"
	"strings"
)

type Record_Type int32

const (
	Record_UNKNOWN Record_Type = 0
	Record_SLD     Record_Type = 1
	Record_TLD     Record_Type = 2
	Record_AS      Record_Type = 3
	Record_IPV4    Record_Type = 4
	Record_IPV6    Record_Type = 5

	DNSName string = `^([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})*[\._]?$`
)

var (
	rxDNSName = regexp.MustCompile(DNSName)
)

var ErrIdentifyRecord = errors.New("Cannot identify the record")

//https://github.com/asaskevich/govalidator/blob/9a090521c4893a35ca9a228628abf8ba93f63108/validator.go
// IsIPv4 check if the string is an IP version 4.
func IsIPv4(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ".")
}

// IsIPv6 check if the string is an IP version 6.
func IsIPv6(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ":")
}

// IsCIDR check if the string is an valid CIDR notiation (IPV4 & IPV6)
func IsCIDR(str string) bool {
	_, _, err := net.ParseCIDR(str)
	return err == nil
}

type RecordInfo struct {
	Data        string
	RecordType  Record_Type
	WhoisServer string
	QueryFormat string
}

func getRecordInfo(data string) (*RecordInfo, error) {
	ri := &RecordInfo{
		Data:        data,
		QueryFormat: "%s",
	}
	//tld
	ss := strings.SplitN(data, ".", -1)
	zone := ss[len(ss)-1]
	if server, ok := TLDs[zone]; ok {
		ri.RecordType = Record_TLD
		ri.WhoisServer = server
		return ri, nil
	}

	//cidr4
	if IsIPv4(data) {
		ss := strings.SplitN(data, ".", 2)
		ri.RecordType = Record_IPV4
		ri.WhoisServer = CIDR[ss[0]]
		return ri, nil
	}

	//cidr6
	if IsIPv6(data) {
		for k, v := range CIDR6 {
			_, ipnet, err := net.ParseCIDR(k)
			if err != nil {
				return nil, err
			}
			if ipnet.Contains(net.ParseIP(data)) {
				ri.RecordType = Record_IPV6
				ri.WhoisServer = v
				return ri, nil
			}
		}
	}

	//as
	for k, v := range AS {
		if k.MatchString(data) {
			ri.RecordType = Record_TLD
			ri.WhoisServer = v
			return ri, nil
		}
	}

	//arin
	for k, v := range ARIN {
		if k.MatchString(data) {
			ri.RecordType = Record_TLD
			ri.WhoisServer = v
			ri.QueryFormat = ARINQueryFormat[k]
			return ri, nil
		}
	}

	return nil, ErrIdentifyRecord
}
