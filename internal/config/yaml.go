package config

import (
	"fmt"
	"strconv"
	"strings"
)

func parseYAML(data []byte, raw *rawConfig) error {
	var section string
	var currentCred *rawCredential
	var listKey string
	var sectionList string

	lines := strings.Split(string(data), "\n")
	for idx, line := range lines {
		lineNo := idx + 1
		line = strings.TrimRight(line, " \t\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := leadingSpaces(line)
		if indent%2 != 0 {
			return fmt.Errorf("line %d: indentation must use multiples of two spaces", lineNo)
		}
		trimmed := strings.TrimSpace(stripTrailingComment(line))
		if trimmed == "" {
			continue
		}

		if indent == 0 {
			key, value, ok := splitYAMLKeyValue(trimmed)
			if !ok {
				return fmt.Errorf("line %d: expected key: value", lineNo)
			}
			section = key
			currentCred = nil
			listKey = ""
			sectionList = ""
			if value != "" {
				if err := setTopLevel(raw, key, value); err != nil {
					return fmt.Errorf("line %d: %w", lineNo, err)
				}
			}
			continue
		}

		switch section {
		case "server":
			key, value, ok := splitYAMLKeyValue(trimmed)
			if !ok {
				return fmt.Errorf("line %d: expected server key: value", lineNo)
			}
			if err := setServer(&raw.Server, key, value); err != nil {
				return fmt.Errorf("line %d: %w", lineNo, err)
			}
		case "verification":
			if strings.HasPrefix(trimmed, "- ") {
				if sectionList == "" {
					return fmt.Errorf("line %d: list item without list key", lineNo)
				}
				if sectionList == "supported_methods" {
					raw.Verification.SupportedMethods = append(raw.Verification.SupportedMethods, unquoteYAML(strings.TrimSpace(trimmed[2:])))
				}
				continue
			}
			key, value, ok := splitYAMLKeyValue(trimmed)
			if !ok {
				return fmt.Errorf("line %d: expected verification key: value", lineNo)
			}
			sectionList = ""
			if value == "" && key == "supported_methods" {
				sectionList = key
				continue
			}
			if err := setVerification(&raw.Verification, key, value); err != nil {
				return fmt.Errorf("line %d: %w", lineNo, err)
			}
		case "logging":
			key, value, ok := splitYAMLKeyValue(trimmed)
			if !ok {
				return fmt.Errorf("line %d: expected logging key: value", lineNo)
			}
			if err := setLogging(&raw.Logging, key, value); err != nil {
				return fmt.Errorf("line %d: %w", lineNo, err)
			}
		case "credentials":
			if indent == 2 && strings.HasPrefix(trimmed, "- ") {
				raw.Credentials = append(raw.Credentials, rawCredential{})
				currentCred = &raw.Credentials[len(raw.Credentials)-1]
				listKey = ""
				rest := strings.TrimSpace(trimmed[2:])
				if rest == "" {
					continue
				}
				key, value, ok := splitYAMLKeyValue(rest)
				if !ok {
					return fmt.Errorf("line %d: expected credential key: value", lineNo)
				}
				if err := setCredential(currentCred, key, value); err != nil {
					return fmt.Errorf("line %d: %w", lineNo, err)
				}
				continue
			}
			if currentCred == nil {
				return fmt.Errorf("line %d: credential field before list item", lineNo)
			}
			if strings.HasPrefix(trimmed, "- ") {
				if listKey == "" {
					return fmt.Errorf("line %d: credential list item without list key", lineNo)
				}
				appendCredentialList(currentCred, listKey, unquoteYAML(strings.TrimSpace(trimmed[2:])))
				continue
			}
			key, value, ok := splitYAMLKeyValue(trimmed)
			if !ok {
				return fmt.Errorf("line %d: expected credential key: value", lineNo)
			}
			listKey = ""
			if value == "" && isCredentialList(key) {
				listKey = key
				continue
			}
			if err := setCredential(currentCred, key, value); err != nil {
				return fmt.Errorf("line %d: %w", lineNo, err)
			}
		default:
			return fmt.Errorf("line %d: unsupported section %q", lineNo, section)
		}
	}
	return nil
}

func setTopLevel(raw *rawConfig, key, value string) error {
	switch key {
	case "allow_empty_credentials":
		b, err := strconv.ParseBool(unquoteYAML(value))
		if err != nil {
			return fmt.Errorf("%s must be boolean", key)
		}
		raw.AllowEmptyCredentials = &b
	default:
		return fmt.Errorf("unsupported top-level key %q", key)
	}
	return nil
}

func setServer(server *rawServer, key, value string) error {
	value = unquoteYAML(value)
	switch key {
	case "network":
		server.Network = value
	case "listen":
		server.Listen = value
	case "socket_mode":
		server.SocketMode = value
	case "read_header_timeout":
		server.ReadHeaderTimeout = value
	case "read_timeout":
		server.ReadTimeout = value
	case "write_timeout":
		server.WriteTimeout = value
	case "idle_timeout":
		server.IdleTimeout = value
	case "max_header_bytes":
		server.MaxHeaderBytes = value
	default:
		return fmt.Errorf("unsupported server key %q", key)
	}
	return nil
}

func setVerification(verification *rawVerification, key, value string) error {
	value = unquoteYAML(value)
	switch key {
	case "allowed_clock_skew":
		verification.AllowedClockSkew = value
	case "default_max_expires":
		verification.DefaultMaxExpires = value
	case "supported_service":
		verification.SupportedService = value
	default:
		return fmt.Errorf("unsupported verification key %q", key)
	}
	return nil
}

func setLogging(logging *rawLogging, key, value string) error {
	b, err := strconv.ParseBool(unquoteYAML(value))
	if err != nil {
		return fmt.Errorf("%s must be boolean", key)
	}
	switch key {
	case "log_all_requests":
		logging.LogAllRequests = &b
	case "log_denies":
		logging.LogDenies = &b
	default:
		return fmt.Errorf("unsupported logging key %q", key)
	}
	return nil
}

func setCredential(cred *rawCredential, key, value string) error {
	value = unquoteYAML(value)
	switch key {
	case "access_key":
		cred.AccessKey = value
	case "secret_key":
		cred.SecretKey = value
	case "secret_key_env":
		cred.SecretKeyEnv = value
	case "secret_key_file":
		cred.SecretKeyFile = value
	case "enabled":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%s must be boolean", key)
		}
		cred.Enabled = &b
	case "max_expires":
		cred.MaxExpires = value
	case "max_expires_seconds":
		cred.MaxExpiresSeconds = value
	default:
		if isCredentialList(key) {
			return nil
		}
		return fmt.Errorf("unsupported credential key %q", key)
	}
	return nil
}

func appendCredentialList(cred *rawCredential, key, value string) {
	switch key {
	case "allowed_hosts":
		cred.AllowedHosts = append(cred.AllowedHosts, value)
	case "allowed_methods":
		cred.AllowedMethods = append(cred.AllowedMethods, value)
	case "allowed_prefixes":
		cred.AllowedPrefixes = append(cred.AllowedPrefixes, value)
	}
}

func isCredentialList(key string) bool {
	switch key {
	case "allowed_hosts", "allowed_methods", "allowed_prefixes":
		return true
	default:
		return false
	}
}

func splitYAMLKeyValue(line string) (string, string, bool) {
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	value := strings.TrimSpace(line[idx+1:])
	return key, value, key != ""
}

func leadingSpaces(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n
}

func stripTrailingComment(line string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
					return strings.TrimRight(line[:i], " \t")
				}
			}
		}
	}
	return line
}

func unquoteYAML(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}
