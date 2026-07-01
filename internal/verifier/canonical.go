package verifier

import (
	"errors"
	"strings"
)

var errInvalidURI = errors.New("invalid uri")

type canonicalQueryParam struct {
	name  string
	value string
}

type sigV4Query struct {
	algorithm          string
	algorithmCount     int
	credential         string
	credentialCount    int
	date               string
	dateCount          int
	expires            string
	expiresCount       int
	signedHeaders      string
	signedHeadersCount int
	signature          string
	signatureCount     int
}

func splitOriginalURI(rawURI string) (string, string, error) {
	if rawURI == "" || rawURI[0] != '/' {
		return "", "", errInvalidURI
	}
	if strings.ContainsAny(rawURI, "\r\n\t ") || strings.Contains(rawURI, "#") {
		return "", "", errInvalidURI
	}
	path := rawURI
	query := ""
	if idx := strings.IndexByte(rawURI, '?'); idx >= 0 {
		path = rawURI[:idx]
		query = rawURI[idx+1:]
	}
	if err := validateRawPath(path); err != nil {
		return "", "", err
	}
	return path, query, nil
}

func validateRawPath(path string) error {
	if path == "" || path[0] != '/' {
		return errInvalidURI
	}
	if strings.Contains(path, "//") {
		return errInvalidURI
	}
	for i := 0; i < len(path); i++ {
		b := path[i]
		if b <= 0x20 || b == 0x7f {
			return errInvalidURI
		}
		if b != '%' {
			continue
		}
		if i+2 >= len(path) || !isHex(path[i+1]) || !isHex(path[i+2]) {
			return errInvalidURI
		}
		hi := upperHex(path[i+1])
		lo := upperHex(path[i+2])
		if (hi == '2' && lo == 'F') || (hi == '5' && lo == 'C') {
			return errInvalidURI
		}
		i += 2
	}
	for start := 1; start <= len(path); {
		end := strings.IndexByte(path[start:], '/')
		if end < 0 {
			end = len(path)
		} else {
			end += start
		}
		segment := path[start:end]
		if segment == "" {
			start = end + 1
			continue
		}
		if !strings.Contains(segment, "%") {
			if segment == "." || segment == ".." {
				return errInvalidURI
			}
			start = end + 1
			continue
		}
		decoded, err := percentDecode(segment)
		if err != nil {
			return err
		}
		if string(decoded) == "." || string(decoded) == ".." {
			return errInvalidURI
		}
		start = end + 1
	}
	return nil
}

func canonicalURI(rawPath string) (string, error) {
	if err := validateRawPath(rawPath); err != nil {
		return "", err
	}
	return canonicalURIFromValidPath(rawPath), nil
}

func canonicalURIFromValidPath(rawPath string) string {
	if isCanonicalPath(rawPath) {
		return rawPath
	}
	var b strings.Builder
	b.Grow(len(rawPath) + 8)
	for i := 0; i < len(rawPath); i++ {
		c := rawPath[i]
		switch {
		case c == '/':
			b.WriteByte('/')
		case c == '%' && i+2 < len(rawPath) && isHex(rawPath[i+1]) && isHex(rawPath[i+2]):
			b.WriteByte('%')
			b.WriteByte(upperHex(rawPath[i+1]))
			b.WriteByte(upperHex(rawPath[i+2]))
			i += 2
		case isUnreserved(c):
			b.WriteByte(c)
		default:
			writeEscapedByte(&b, c)
		}
	}
	return b.String()
}

func isCanonicalPath(rawPath string) bool {
	for i := 0; i < len(rawPath); i++ {
		c := rawPath[i]
		if c == '/' || isUnreserved(c) {
			continue
		}
		if c == '%' && i+2 < len(rawPath) && isHex(rawPath[i+1]) && isHex(rawPath[i+2]) {
			if rawPath[i+1] != upperHex(rawPath[i+1]) || rawPath[i+2] != upperHex(rawPath[i+2]) {
				return false
			}
			i += 2
			continue
		}
		return false
	}
	return true
}

func canonicalQuery(rawQuery string) (string, sigV4Query, error) {
	var values sigV4Query
	if rawQuery == "" {
		return "", values, nil
	}
	if rawQuery[len(rawQuery)-1] == '&' {
		return "", values, errInvalidURI
	}
	paramCap := strings.Count(rawQuery, "&") + 1
	var smallParams [12]canonicalQueryParam
	params := smallParams[:0]
	if paramCap > len(smallParams) {
		params = make([]canonicalQueryParam, 0, paramCap)
	}
	for start := 0; start < len(rawQuery); {
		end := strings.IndexByte(rawQuery[start:], '&')
		if end < 0 {
			end = len(rawQuery)
		} else {
			end += start
		}
		if end == start {
			return "", values, errInvalidURI
		}
		part := rawQuery[start:end]
		nameRaw, valueRaw, _ := strings.Cut(part, "=")
		encodedName, name, err := canonicalizeQueryComponent(nameRaw, true)
		if err != nil {
			return "", values, err
		}
		if name == "" {
			return "", values, errInvalidURI
		}
		if name == "X-Amz-Signature" {
			_, value, err := canonicalizeQueryComponent(valueRaw, true)
			if err != nil {
				return "", values, err
			}
			values.set(name, value)
			start = end + 1
			continue
		}
		knownName := isKnownQueryName(name)
		encodedValue, value, err := canonicalizeQueryComponent(valueRaw, knownName)
		if err != nil {
			return "", values, err
		}
		if knownName {
			values.set(name, value)
		}
		params = append(params, canonicalQueryParam{
			name:  encodedName,
			value: encodedValue,
		})
		start = end + 1
	}
	sortCanonicalQueryParams(params)
	var b strings.Builder
	for i, p := range params {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.name)
		b.WriteByte('=')
		b.WriteString(p.value)
	}
	return b.String(), values, nil
}

func sortCanonicalQueryParams(params []canonicalQueryParam) {
	for i := 1; i < len(params); i++ {
		current := params[i]
		j := i - 1
		for ; j >= 0; j-- {
			if params[j].name < current.name || (params[j].name == current.name && params[j].value <= current.value) {
				break
			}
			params[j+1] = params[j]
		}
		params[j+1] = current
	}
}

func isKnownQueryName(name string) bool {
	switch name {
	case "X-Amz-Algorithm",
		"X-Amz-Credential",
		"X-Amz-Date",
		"X-Amz-Expires",
		"X-Amz-SignedHeaders",
		"X-Amz-Signature":
		return true
	default:
		return false
	}
}

func (q *sigV4Query) set(name, value string) {
	switch name {
	case "X-Amz-Algorithm":
		q.algorithm = value
		q.algorithmCount++
	case "X-Amz-Credential":
		q.credential = value
		q.credentialCount++
	case "X-Amz-Date":
		q.date = value
		q.dateCount++
	case "X-Amz-Expires":
		q.expires = value
		q.expiresCount++
	case "X-Amz-SignedHeaders":
		q.signedHeaders = value
		q.signedHeadersCount++
	case "X-Amz-Signature":
		q.signature = value
		q.signatureCount++
	}
}

func singleKnownQueryValue(value string, count int) (string, bool) {
	if count != 1 {
		return "", false
	}
	return value, true
}

func canonicalizeQueryComponent(raw string, wantDecoded bool) (string, string, error) {
	slow, err := queryComponentNeedsSlowPath(raw)
	if err != nil {
		return "", "", err
	}
	if !slow {
		if wantDecoded {
			return raw, raw, nil
		}
		return raw, "", nil
	}

	var encoded strings.Builder
	encoded.Grow(len(raw) + 8)
	var decoded strings.Builder
	if wantDecoded {
		decoded.Grow(len(raw))
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '%' {
			if i+2 >= len(raw) || !isHex(raw[i+1]) || !isHex(raw[i+2]) {
				return "", "", errInvalidURI
			}
			b := fromHex(raw[i+1])<<4 | fromHex(raw[i+2])
			if wantDecoded {
				decoded.WriteByte(b)
			}
			if isUnreserved(b) {
				encoded.WriteByte(b)
			} else {
				writeEscapedByte(&encoded, b)
			}
			i += 2
			continue
		}
		if wantDecoded {
			decoded.WriteByte(c)
		}
		if isUnreserved(c) {
			encoded.WriteByte(c)
		} else {
			writeEscapedByte(&encoded, c)
		}
	}
	if wantDecoded {
		return encoded.String(), decoded.String(), nil
	}
	return encoded.String(), "", nil
}

func queryComponentNeedsSlowPath(raw string) (bool, error) {
	slow := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '%' {
			if i+2 >= len(raw) || !isHex(raw[i+1]) || !isHex(raw[i+2]) {
				return false, errInvalidURI
			}
			slow = true
			i += 2
			continue
		}
		if !isUnreserved(c) {
			slow = true
		}
	}
	return slow, nil
}

func percentDecode(value string) ([]byte, error) {
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '%' {
			out = append(out, c)
			continue
		}
		if i+2 >= len(value) || !isHex(value[i+1]) || !isHex(value[i+2]) {
			return nil, errInvalidURI
		}
		out = append(out, fromHex(value[i+1])<<4|fromHex(value[i+2]))
		i += 2
	}
	return out, nil
}

func uriEncodeBytes(value []byte) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, c := range value {
		if isUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		writeEscapedByte(&b, c)
	}
	return b.String()
}

func writeEscapedByte(b *strings.Builder, c byte) {
	const hexdigits = "0123456789ABCDEF"
	b.WriteByte('%')
	b.WriteByte(hexdigits[c>>4])
	b.WriteByte(hexdigits[c&0x0f])
}

func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}

func fromHex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func upperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}
