package tftp

import (
	"encoding/binary"
	"strings"
)

type opcode uint16

const (
	opRRQ   opcode = 1
	opWRQ   opcode = 2
	opDATA  opcode = 3
	opACK   opcode = 4
	opERROR opcode = 5
	opOACK  opcode = 6
)

type errorCode uint16

const (
	errNotDefined       errorCode = 0
	errFileNotFound     errorCode = 1
	errAccessViolation  errorCode = 2
	errDiskFull         errorCode = 3
	errIllegalOperation errorCode = 4
	errUnknownTID       errorCode = 5
	errFileExists       errorCode = 6
	//lint:ignore U1000 kept for completeness of the RFC 1350 error codes
	errNoSuchUser errorCode = 7
)

const (
	defaultBlockSize     = 512
	minBlockSize         = 8
	maxProtocolBlockSize = 65464
	maxFilenameLength    = 255
)

// option is one negotiated RFC 2347 option. They are kept in a slice rather
// than a map so that an OACK always lists them in the same order.
type option struct {
	key   string
	value string
}

// request is a parsed read or write request.
type request struct {
	filename string
	mode     string
	options  []option
}

// option returns the value of key and whether it was present.
func (r request) option(key string) (string, bool) {
	for _, opt := range r.options {
		if opt.key == key {
			return opt.value, true
		}
	}
	return "", false
}

// optionMap is what handlers see, for logging and policy.
func (r request) optionMap() map[string]string {
	if len(r.options) == 0 {
		return nil
	}
	out := make(map[string]string, len(r.options))
	for _, opt := range r.options {
		out[opt.key] = opt.value
	}
	return out
}

// parseRequest decodes an RRQ or WRQ. It returns false for a packet that is
// not a well formed request.
//
// The file name is UTF-8; decoding it as ASCII, as an earlier implementation
// did, silently rewrites every byte above 0x7F. The mode and the options are
// decoded as Latin-1, which cannot fail, since they are compared against known
// ASCII keywords.
func parseRequest(msg []byte) (request, bool) {
	var req request
	body := msg[2:]

	end := indexZero(body)
	if end < 0 {
		return req, false
	}
	req.filename = string(body[:end])
	body = body[end+1:]

	end = indexZero(body)
	if end < 0 {
		return req, false
	}
	req.mode = strings.ToLower(latin1(body[:end]))
	body = body[end+1:]

	// RFC 2347 options, key\0value\0 pairs after the mode
	for len(body) > 0 {
		end = indexZero(body)
		if end < 0 {
			break
		}
		key := strings.ToLower(latin1(body[:end]))
		body = body[end+1:]

		end = indexZero(body)
		if end < 0 {
			break
		}
		value := latin1(body[:end])
		body = body[end+1:]

		req.options = append(req.options, option{key: key, value: value})
	}
	return req, true
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// latin1 decodes bytes one to one into runes, the way the original did.
func latin1(b []byte) string {
	ascii := true
	for _, c := range b {
		if c > 0x7F {
			ascii = false
			break
		}
	}
	if ascii {
		return string(b)
	}
	runes := make([]rune, len(b))
	for i, c := range b {
		runes[i] = rune(c)
	}
	return string(runes)
}

func encodeDATA(block uint16, data []byte) []byte {
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(buf, uint16(opDATA))
	binary.BigEndian.PutUint16(buf[2:], block)
	copy(buf[4:], data)
	return buf
}

func encodeACK(block uint16) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf, uint16(opACK))
	binary.BigEndian.PutUint16(buf[2:], block)
	return buf
}

func encodeOACK(options []option) []byte {
	size := 2
	for _, opt := range options {
		size += len(opt.key) + len(opt.value) + 2
	}
	buf := make([]byte, 0, size)
	buf = binary.BigEndian.AppendUint16(buf, uint16(opOACK))
	for _, opt := range options {
		buf = append(buf, opt.key...)
		buf = append(buf, 0)
		buf = append(buf, opt.value...)
		buf = append(buf, 0)
	}
	return buf
}

func encodeError(code errorCode, message string) []byte {
	buf := make([]byte, 0, 5+len(message))
	buf = binary.BigEndian.AppendUint16(buf, uint16(opERROR))
	buf = binary.BigEndian.AppendUint16(buf, uint16(code))
	buf = append(buf, message...)
	buf = append(buf, 0)
	return buf
}

// sanitize strips control characters, so that a file name from the wire cannot
// garble the log.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7F && r <= 0x9F) {
			return -1
		}
		return r
	}, s)
}
