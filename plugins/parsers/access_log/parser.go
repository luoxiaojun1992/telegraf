package access_log

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/influxdata/telegraf"
)

type AccessLogParser struct {
	MetricName  string
	DataType    string
	DefaultTags map[string]string
}

func (v *AccessLogParser) Parse(buf []byte) ([]telegraf.Metric, error) {
	log := strings.TrimSpace(string(buf))

	// unless it's a string, separate out any fields in the buffer,
	// ignore anything but the last.
	if len(log) == 0 {
		return []telegraf.Metric{}, nil
	}

	// Parse Ip Address
	ip_regexp := regexp.MustCompile("\\s+(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)\\.(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)\\.(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)\\.(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)\\s+")
	hosts := ip_regexp.FindAllString(log, 2)

	// Parse Hostname
	hostname_regexp := regexp.MustCompile("\\s+([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}\\s+")
	hostname := strings.TrimSpace(hostname_regexp.FindString(log))

	// Parse Request Method
	method_regexp := regexp.MustCompile("\\s+(GET|HEAD|POST|PUT|DELETE|TRACE|OPTIONS|CONNECT)\\s+")
	method := strings.TrimSpace(method_regexp.FindString(log))

	// Parse Status Code
	status_code_regexp := regexp.MustCompile("\\s+[1-5]{1}[0-9]{2}\\s+")
	status_code_arr := status_code_regexp.FindAllString(log, 3)
	status_code := ""
	if len(status_code_arr) > 1 {
		status_code = strings.TrimSpace(status_code_arr[1])
	} else {
		status_code = strings.TrimSpace(status_code_arr[0])
	}
	status_code_number, err_status_code := strconv.Atoi(status_code)
	if err_status_code != nil {
		return nil, err_status_code
	}

	// Parse Request URI
	uri_regexp := regexp.MustCompile("\\s+(?:\\/([^?#]*))")
	uri := strings.Split(strings.TrimSpace(uri_regexp.FindString(log)), " ")[0]

	fields := map[string]interface{}{
		"client_ip":   strings.TrimSpace(hosts[0]),
		"host_ip":     strings.TrimSpace(hosts[1]),
		"hostname":    hostname,
		"method":      method,
		"status_code": status_code_number,
		"path":        uri,
	}

	metric, err := telegraf.NewMetric(v.MetricName, v.DefaultTags,
		fields, time.Now().UTC())
	if err != nil {
		return nil, err
	}

	return []telegraf.Metric{metric}, nil
}

func (v *AccessLogParser) ParseLine(line string) (telegraf.Metric, error) {
	metrics, err := v.Parse([]byte(line))

	if err != nil {
		return nil, err
	}

	if len(metrics) < 1 {
		return nil, fmt.Errorf("Can not parse the line: %s, for data format: value", line)
	}

	return metrics[0], nil
}

func (v *AccessLogParser) SetDefaultTags(tags map[string]string) {
	v.DefaultTags = tags
}
