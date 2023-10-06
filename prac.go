package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// represents a log entry with attributes.
type LogEntry struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Country string `json:"country"`
	State   string `json:"state"`
	Device  string `json:"device"`
	Browser string `json:"browser"`
}

// represents a condition to be evaluated.
type Rule struct {
	Attribute string `json:"attribute"` // attribute name (e.g., "ip")
	Operator  string `json:"operator"`  // comparison operator (e.g., "==", "!=")
	Logical   string `json:"logical"`   // logical operator ("AND" or "OR") to combine rules
	Value     string `json:"value"`     // expected value for the attribute
}

// represents the computed attributes.
type ComputedAttributes struct {
	VPN            bool
	RiskScore      int
	TrustedDevice  bool
	TrustedNetwork bool
	AuthFail       bool
}

// evaluates a single rule against a log entry and returns true if the condition is met.
func EvaluateRule(entry LogEntry, rule Rule) bool {
	switch rule.Attribute {
	case "ip":
		return evaluateStringAttribute(entry.IP, rule.Operator, rule.Value)
	case "city":
		return evaluateStringAttribute(entry.City, rule.Operator, rule.Value)
	case "country":
		return evaluateStringAttribute(entry.Country, rule.Operator, rule.Value)
	case "state":
		return evaluateStringAttribute(entry.State, rule.Operator, rule.Value)
	case "device":
		return evaluateStringAttribute(entry.Device, rule.Operator, rule.Value)
	case "browser":
		return evaluateStringAttribute(entry.Browser, rule.Operator, rule.Value)
	default:
		// any unknown attribute, we cann return false.
		return false
	}
}

// evaluateStringAttribute evaluates a single string attribute rule.
func evaluateStringAttribute(attributeValue, operator, expectedValue string) bool {
	// fmt.Println("hello", attributeValue, operator, expectedValue)
	switch operator {
	case "==":
		return attributeValue == expectedValue
	case "!=":
		return attributeValue != expectedValue
	default:
		// Invalid operator, return false(we can chnge acording to need)
		return false
	}
}

// concurrently processes a stream of log entries using Goroutines.
func ProcessLogs(logs []LogEntry, rules []Rule) []ComputedAttributes {

	var wg sync.WaitGroup
	results := make([]ComputedAttributes, len(logs))

	for i, entry := range logs {
		// fmt.Println(rules)
		wg.Add(1)
		go func(index int, logEntry LogEntry) {
			defer wg.Done()
			results[index] = ComputeAttributes(logEntry, rules)
		}(i, entry)
	}

	wg.Wait()
	return results
}

// computes the specified attributes based on the log entry and rules.
func ComputeAttributes(entry LogEntry, rules []Rule) ComputedAttributes {
	// fmt.Println(rules)
	attributes := ComputedAttributes{}

	// initializing logical operator flag
	useLogicalAnd := true
	useLogicalOr := false

	for _, rule := range rules {
		// handling logical operators
		if strings.ToUpper(rule.Logical) == "AND" {
			useLogicalAnd = true
			useLogicalOr = false

		} else if strings.ToUpper(rule.Logical) == "OR" {
			// fmt.Println("hello")
			useLogicalAnd = false
			useLogicalOr = true

		}

		// evaluating the rule based on the logical operator
		ruleResult := EvaluateRule(entry, rule)
		// fmt.Println("pop")

		// applying the result to the attributes based on the logical operator
		if useLogicalAnd {
			attributes.VPN = attributes.VPN && ruleResult
			attributes.RiskScore += 10 // increasing risk score for certain cities
			attributes.TrustedDevice = attributes.TrustedDevice && ruleResult
			attributes.TrustedNetwork = attributes.TrustedNetwork && ruleResult
			attributes.AuthFail = attributes.AuthFail && ruleResult
		} else if useLogicalOr {
			attributes.VPN = attributes.VPN || ruleResult
			attributes.RiskScore += 10 // increasing risk score for certain cities
			attributes.TrustedDevice = attributes.TrustedDevice || ruleResult
			attributes.TrustedNetwork = attributes.TrustedNetwork || ruleResult
			attributes.AuthFail = attributes.AuthFail || ruleResult
		}
	}

	return attributes
}
func main() {
	// log entries as JSON
	logJSONs := []string{
		`{"ip": "192.168.100.18", "city": "Meerut", "country": "India", "state": "UP", "device": "Desktop", "browser": "Chrome"}`,
		`{"ip": "192.168.100.13", "city": "Mumbai", "country": "India", "state": "Maharashtra", "device": "Desktop", "browser": "Safari"}`,
		`{"ip": "192.168.100.14", "city": "Bangalore", "country": "India", "state": "Karnataka", "device": "Desktop", "browser": "Torr"}`,
		`{"ip": "192.168.100.12", "city": "Kashi", "country": "India", "state": "UP", "device": "Desktop", "browser": "Mozilla Firefox"}`,
	}

	// parsing log entry JSONs into a slice of LogEntry structs
	var logs []LogEntry
	for _, logJSON := range logJSONs {
		var logEntry LogEntry
		if err := json.Unmarshal([]byte(logJSON), &logEntry); err != nil {
			fmt.Println("Error parsing log entry:", err)
			continue
		}
		logs = append(logs, logEntry)
	}

	// sample rules to evaluate (multiple rules joined by "AND" or "OR")
	rules := []Rule{
		{Attribute: "ip", Operator: "==", Value: "192.168.100.13", Logical: "OR"},
		{Attribute: "city", Operator: "==", Value: "Bangalore", Logical: "OR"},
	}

	// processing the log entries concurrently and compute attributes
	results := ProcessLogs(logs, rules)

	// printing the computed attributes for each log entry
	for i, result := range results {
		fmt.Printf("Attributes for Log Entry %d:\nVPN: %v\nRisk Score: %d\nTrusted Device: %v\nTrusted Network: %v\nAuth Fail: %v\n\n",
			i+1, result.VPN, result.RiskScore, result.TrustedDevice, result.TrustedNetwork, result.AuthFail)
	}
}
