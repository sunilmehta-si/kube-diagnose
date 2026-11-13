package kube

import (
	"sort"
	"strings"
)

// Matches reports whether labels satisfy the selector, with the API's semantics: every matchLabels pair and every
// expression must hold, and an empty selector matches everything.
func (s LabelSelector) Matches(labels map[string]string) bool {
	for k, v := range s.MatchLabels {
		if got, ok := labels[k]; !ok || got != v {
			return false
		}
	}
	for _, e := range s.MatchExpressions {
		val, has := labels[e.Key]
		switch e.Operator {
		case "In":
			if !has || !contains(e.Values, val) {
				return false
			}
		case "NotIn":
			if has && contains(e.Values, val) {
				return false
			}
		case "Exists":
			if !has {
				return false
			}
		case "DoesNotExist":
			if has {
				return false
			}
		default:
			return false // an operator the API would reject matches nothing
		}
	}
	return true
}

// MatchesMap reports whether labels carry every key/value pair, as a Service or nodeSelector selects.
func MatchesMap(selector, labels map[string]string) bool {
	for k, v := range selector {
		if got, ok := labels[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// FormatMap prints a label map as k=v pairs in key order.
func FormatMap(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + m[k]
	}
	return strings.Join(parts, ",")
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
