package cli

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
)

// SplitLine supports quoted filenames without treating Windows path separators
// as escapes. There is no variable, wildcard, command, or shell expansion.
func SplitLine(line string) ([]string, error) {
	var words []string
	var word strings.Builder
	var quote rune
	started := false
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == 0 {
			return nil, errors.New("NUL is not allowed in commands")
		}
		if r == '\\' && quote != '\'' && i+1 < len(runes) {
			next := runes[i+1]
			if next == '"' || quote == 0 && (next == '\'' || unicode.IsSpace(next)) {
				word.WriteRune(next)
				started = true
				i++
				continue
			}
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			started = true
			continue
		}
		if unicode.IsSpace(r) {
			if started {
				words = append(words, word.String())
				word.Reset()
				started = false
			}
			continue
		}
		word.WriteRune(r)
		started = true
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if started {
		words = append(words, word.String())
	}
	return words, nil
}

func parseMode(value string) (uint32, error) {
	n, err := strconv.ParseUint(value, 8, 12)
	if err != nil {
		return 0, errors.New("mode must be octal, from 0000 to 7777")
	}
	return uint32(n), nil
}

func parseGroups(value string) ([]uint32, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 16 {
		return nil, errors.New("at most 16 supplementary groups are allowed")
	}
	groups := make([]uint32, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, errors.New("groups must be comma-separated unsigned integers")
		}
		groups[i] = uint32(n)
	}
	return groups, nil
}
