package kube

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

var binarySuffixes = map[string]float64{
	"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "Pi": 1 << 50, "Ei": 1 << 60,
}

var decimalSuffixes = map[string]float64{
	"n": 1e-9, "u": 1e-6, "m": 1e-3, "": 1, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
}

// ParseQuantity reads a Kubernetes resource quantity ("500m", "2", "1Gi", "1.5e3") as a float in base units:
// cores for cpu, bytes for memory. It accepts the suffixes the API server accepts.
func ParseQuantity(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty quantity")
	}
	for suf, mult := range binarySuffixes {
		if strings.HasSuffix(s, suf) {
			return number(s[:len(s)-len(suf)], mult, s)
		}
	}
	if i := strings.IndexAny(s, "eE"); i > 0 && i < len(s)-1 {
		// Decimal exponent such as 1e3; "E" alone is the exa suffix and is handled below.
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f, nil
		}
	}
	if mult, ok := decimalSuffixes[s[len(s)-1:]]; ok {
		return number(s[:len(s)-1], mult, s)
	}
	return number(s, 1, s)
}

func number(digits string, mult float64, orig string) (float64, error) {
	f, err := strconv.ParseFloat(digits, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("invalid quantity %q", orig)
	}
	return f * mult, nil
}

// FormatQuantity prints a quantity of a resource the way people write it: cpu in cores or millicores, memory and
// storage in binary units.
func FormatQuantity(resource string, v float64) string {
	switch {
	case resource == "cpu":
		if v < 1 && v > 0 {
			return strconv.FormatFloat(v*1000, 'f', -1, 64) + "m"
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case resource == "memory" || resource == "storage" || strings.HasPrefix(resource, "ephemeral-storage"):
		for _, u := range []string{"Ei", "Pi", "Ti", "Gi", "Mi", "Ki"} {
			if v >= binarySuffixes[u] {
				return strconv.FormatFloat(math.Round(v/binarySuffixes[u]*10)/10, 'f', -1, 64) + u
			}
		}
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}
