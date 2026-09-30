package tftp

import (
	"regexp"
	"strconv"
	"time"
)

var decimalOnly = regexp.MustCompile(`^\d{1,15}$`)

// parseNumericOption reads an option value. Option values are plain decimal
// numbers (RFC 2347); anything else is not a value this server can honour, so
// the option is declined rather than half parsed. "512abc" is not 512.
func parseNumericOption(value string, present bool) (int64, bool) {
	if !present || !decimalOnly.MatchString(value) {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// negotiated is the outcome of the RFC 2347 option negotiation.
type negotiated struct {
	blockSize  int
	windowSize int
	timeout    time.Duration
	// acked lists the options to confirm in an OACK, in a stable order.
	acked []option
	// announcedSize is the tsize a write request declared, -1 when absent.
	announcedSize int64
}

// negotiate answers the options of a request.
//
// blksize and windowsize may be answered with a smaller value than the client
// asked for (RFC 2348 section 1, RFC 7440 section 3), so an oversized request
// is capped instead of being turned down. timeout has to be echoed exactly
// (RFC 2349), so a value the server will not use is declined.
func negotiate(req request, cfg limits, forRead bool, fileSize int64) negotiated {
	result := negotiated{
		blockSize:     defaultBlockSize,
		windowSize:    1,
		timeout:       cfg.timeout,
		announcedSize: -1,
	}

	maxBlockSize := min(cfg.maxBlockSize, maxProtocolBlockSize)
	if value, ok := req.option("blksize"); ok {
		if requested, valid := parseNumericOption(value, true); valid && requested >= minBlockSize {
			result.blockSize = int(min(requested, int64(maxBlockSize)))
			result.acked = append(result.acked, option{"blksize", strconv.Itoa(result.blockSize)})
		}
	}

	if forRead {
		// RFC 7440 calls the option windowsize, some clients send wndsize
		key := ""
		if _, ok := req.option("windowsize"); ok {
			key = "windowsize"
		} else if _, ok := req.option("wndsize"); ok {
			key = "wndsize"
		}
		if key != "" {
			value, _ := req.option(key)
			if requested, valid := parseNumericOption(value, true); valid && requested >= 1 {
				result.windowSize = int(min(requested, int64(cfg.maxWindowSize)))
				result.acked = append(result.acked, option{key, strconv.Itoa(result.windowSize)})
			}
		}
	}

	if value, ok := req.option("timeout"); ok {
		limit := int64(cfg.maxTimeout / time.Second)
		if limit > 255 {
			limit = 255
		}
		if requested, valid := parseNumericOption(value, true); valid && requested >= 1 && requested <= limit {
			result.timeout = time.Duration(requested) * time.Second
			result.acked = append(result.acked, option{"timeout", strconv.FormatInt(requested, 10)})
		}
	}

	if value, ok := req.option("tsize"); ok {
		if forRead {
			// the transferred size is only known upfront for an untranslated
			// file, netascii changes the number of octets on the wire
			if fileSize >= 0 && req.mode != modeNetascii {
				result.acked = append(result.acked, option{"tsize", strconv.FormatInt(fileSize, 10)})
			}
		} else if announced, valid := parseNumericOption(value, true); valid {
			// only a value this server understood is confirmed back
			result.announcedSize = announced
			result.acked = append(result.acked, option{"tsize", strconv.FormatInt(announced, 10)})
		}
	}

	return result
}

// limits are the negotiation bounds taken from the configuration.
type limits struct {
	timeout       time.Duration
	maxTimeout    time.Duration
	retries       int
	maxBlockSize  int
	maxWindowSize int
}
