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

	metric, err := telegraf.NewMetric(v.MetricName, v.DefaultTags,
		parseAccessLog(log), time.Now().UTC())
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

func parseAccessLog(log string) map[string]interface{} {
	// Parse Ip Address
	ip_regexp := regexp.MustCompile("\\s+(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)\\.(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)\\.(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)\\.(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)\\s+")
	hosts := ip_regexp.FindAllString(log, 2)
	client_ip := ""
	host_ip := ""
	if len(hosts) > 1 {
		client_ip = strings.TrimSpace(hosts[0])
		host_ip = strings.TrimSpace(hosts[1])
	}

	// Parse Hostname
	hostname_regexp := regexp.MustCompile("\\s+([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}\\s+")
	hostname := strings.TrimSpace(hostname_regexp.FindString(log))

	// Parse Request Method
	method_regexp := regexp.MustCompile("\\s+(GET|HEAD|POST|PUT|DELETE|TRACE|OPTIONS|CONNECT)\\s+")
	method := strings.TrimSpace(method_regexp.FindString(log))

	// Parse Status Code
	status_code_regexp := regexp.MustCompile("\\s+\\d+\\s+")
	status_code_arr := status_code_regexp.FindAllString(log, 3)
	status_code := ""
	upstream_time := ""
	if len(status_code_arr) > 0 {
		if len(status_code_arr) > 1 {
			upstream_time = strings.TrimSpace(status_code_arr[0])
			status_code = strings.TrimSpace(status_code_arr[1])
		} else {
			status_code = strings.TrimSpace(status_code_arr[0])
		}
	}
	status_code_number, _ := strconv.Atoi(status_code)
	upstream_time_number, _ := strconv.Atoi(upstream_time)
	success_status := 0
	fail_status := 0
	if status_code_number >= 400 {
		fail_status++
	} else {
		success_status++
	}
	slow_request := 0
	if upstream_time_number > 2000 {
		slow_request = 1
	}

	// Parse Request URI
	uri_regexp := regexp.MustCompile("\\s+(?:\\/([^?#]*))")
	uri_arr := strings.Split(strings.TrimSpace(uri_regexp.FindString(log)), " ")
	uri := ""
	if len(uri_arr) > 0 {
		uri = uri_arr[0]
	}

	return map[string]interface{}{
		"client_ip":   client_ip,
		"host_ip":     host_ip,
		"hostname":    hostname,
		"method":      method,
		"status_code": status_code_number,
		"success_status": success_status,
		"fail_status": fail_status,
		"upstream_time": upstream_time_number,
		"path":        uri,
		"slow_request": slow_request,
	}
}
