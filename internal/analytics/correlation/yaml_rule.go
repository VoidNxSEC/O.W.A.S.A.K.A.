package correlation

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"gopkg.in/yaml.v3"
)

// YAMLRuleSpec defines the on-disk format for a correlation rule.
type YAMLRuleSpec struct {
	RuleName    string      `yaml:"name"`
	Description string      `yaml:"description"`
	Severity    string      `yaml:"severity"`
	EventType   string      `yaml:"event_type"`
	Logic       string      `yaml:"logic"` // "and" (default) or "or"
	Conditions  []Condition `yaml:"conditions"`
}

// Condition is a single field check against event metadata.
type Condition struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"` // equals, contains, gt, lt, exists
	Value    string `yaml:"value"`
}

// YAMLRule wraps a loaded spec and implements the Rule interface.
type YAMLRule struct {
	spec YAMLRuleSpec
}

func (r *YAMLRule) Name() string { return r.spec.RuleName }

func (r *YAMLRule) Evaluate(e models.NetworkEvent) *models.NetworkEvent {
	// Filter by event type if specified
	if r.spec.EventType != "" && string(e.Type) != r.spec.EventType {
		return nil
	}

	if len(r.spec.Conditions) == 0 {
		return nil
	}

	useOr := strings.EqualFold(r.spec.Logic, "or")
	matched := 0

	for _, c := range r.spec.Conditions {
		if evalCondition(c, e) {
			matched++
			if useOr {
				break // one match is enough for OR logic
			}
		}
	}

	fire := false
	if useOr {
		fire = matched > 0
	} else {
		fire = matched == len(r.spec.Conditions)
	}

	if !fire {
		return nil
	}

	severity := r.spec.Severity
	if severity == "" {
		severity = "MEDIUM"
	}

	return &models.NetworkEvent{
		ID:          uuid.NewString(),
		Type:        models.EventAlert,
		Timestamp:   time.Now().UTC(),
		Source:      "CorrelationEngine",
		Destination: e.Source,
		Metadata: map[string]any{
			"rule":        r.spec.RuleName,
			"description": r.spec.Description,
			"severity":    severity,
			"trigger_id":  e.ID,
		},
	}
}

func evalCondition(c Condition, e models.NetworkEvent) bool {
	// Resolve the field value from metadata or top-level fields
	raw := resolveField(c.Field, e)

	switch c.Operator {
	case "exists":
		return raw != nil
	case "equals":
		return fmt.Sprintf("%v", raw) == c.Value
	case "contains":
		s, ok := raw.(string)
		if !ok {
			s = fmt.Sprintf("%v", raw)
		}
		return strings.Contains(s, c.Value)
	case "gt":
		return toFloat(raw) > toFloat(c.Value)
	case "lt":
		return toFloat(raw) < toFloat(c.Value)
	default:
		return false
	}
}

func resolveField(field string, e models.NetworkEvent) any {
	switch field {
	case "source":
		return e.Source
	case "destination":
		return e.Destination
	case "type":
		return string(e.Type)
	default:
		if e.Metadata != nil {
			return e.Metadata[field]
		}
		return nil
	}
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		f, _ := strconv.ParseFloat(n, 64)
		return f
	default:
		return 0
	}
}

// LoadRulesFromDir reads all .yaml/.yml files from a directory and returns Rule implementations.
func LoadRulesFromDir(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading rules dir %s: %w", dir, err)
	}

	var rules []Rule
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading rule file %s: %w", entry.Name(), err)
		}

		var spec YAMLRuleSpec
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("parsing rule file %s: %w", entry.Name(), err)
		}
		if spec.RuleName == "" {
			continue
		}
		rules = append(rules, &YAMLRule{spec: spec})
	}
	return rules, nil
}

// LoadRulesFromFS reads all .yaml/.yml files from an fs.FS rooted at dir.
func LoadRulesFromFS(fsys fs.FS, dir string) ([]Rule, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("reading embedded rules dir %s: %w", dir, err)
	}

	var rules []Rule
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		data, err := fs.ReadFile(fsys, dir+"/"+entry.Name())
		if err != nil {
			return nil, fmt.Errorf("reading embedded rule %s: %w", entry.Name(), err)
		}

		var spec YAMLRuleSpec
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("parsing embedded rule %s: %w", entry.Name(), err)
		}
		if spec.RuleName == "" {
			continue
		}
		rules = append(rules, &YAMLRule{spec: spec})
	}
	return rules, nil
}
