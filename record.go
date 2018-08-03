package jwhois

import (
	"errors"
	"strings"
)

type Record_Type int32

const (
	Record_UNKNOWN Record_Type = 0
	Record_SLD     Record_Type = 1
	Record_TLD     Record_Type = 2
	Record_AS      Record_Type = 3
)

var ErrIdentifyRecord = errors.New("Cannot identify the record")

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
