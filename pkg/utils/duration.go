package utils

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseDuration parses a duration string and converts it into a time.Duration.
// Supported suffixes (case-sensitive) are:
//
//	s -> second
//	m -> minute
//	h -> hour
//	D -> day (24 hours)
//	W -> week (7 days)
//	M -> month (30 days)
//	Y -> year (365 days)
func ParseDuration(input string) (time.Duration, error) {
	input = strings.TrimSpace(input)
	if len(input) < 2 {
		return 0, errors.New("invalid duration format")
	}

	// Get the last character as the unit.
	unit := input[len(input)-1:]
	// The rest of the string is the numeric value.
	valueStr := input[:len(input)-1]

	// Parse the numeric portion.
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric value in duration %q: %w", input, err)
	}

	var multiplier time.Duration

	switch unit {
	case "s": // seconds
		multiplier = time.Second
	case "m": // minutes
		multiplier = time.Minute
	case "h": // hours
		multiplier = time.Hour
	case "D": // days
		multiplier = 24 * time.Hour
	case "W": // weeks
		multiplier = 7 * 24 * time.Hour
	case "M": // months (30 days)
		multiplier = 30 * 24 * time.Hour
	case "Y": // years (365 days)
		multiplier = 365 * 24 * time.Hour
	default:
		return 0, errors.New("unsupported duration unit (supported units: s, m, h, D, W, M, Y)")
	}

	// Calculate the duration.
	duration := time.Duration(value) * multiplier
	return duration, nil
}
