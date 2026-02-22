package classify

// Result is the classification output shared across all classifiers.
type Result struct {
	Classification string  `json:"classification"`
	Confidence     float64 `json:"confidence"`
	Blocked        bool    `json:"blocked"`
	AttackType     string  `json:"attack_type"`
	Classifier     string  `json:"classifier"`
	Reason         string  `json:"reason"`
	ResponseTimeMs float64 `json:"response_time_ms,omitempty"`
	RulesVersion   int     `json:"rules_version,omitempty"`
}
