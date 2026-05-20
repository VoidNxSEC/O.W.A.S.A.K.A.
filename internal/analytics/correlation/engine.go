package correlation

import (
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

type AlertCallback func(models.NetworkEvent)

// Engine inspects incoming SIEM events against Sigma schemas or internal heuristics
type Engine struct {
	cfg       *config.CorrelationConfig
	logger    *logging.Logger
	rules     []Rule
	onAlert   AlertCallback
}

// NewEngine spans a real-time event inspector
func NewEngine(cfg *config.CorrelationConfig, logger *logging.Logger) *Engine {
	e := &Engine{
		cfg:    cfg,
		logger: logger,
		rules:  DefaultRules(),
	}

	// Load custom YAML rules from disk
	if cfg.CustomRulesEnabled && cfg.RulesDir != "" {
		yamlRules, err := LoadRulesFromDir(cfg.RulesDir)
		if err != nil {
			logger.Errorw("Failed to load YAML correlation rules", "dir", cfg.RulesDir, "error", err)
		} else if len(yamlRules) > 0 {
			e.rules = append(e.rules, yamlRules...)
			logger.Infow("Loaded YAML correlation rules", "count", len(yamlRules), "dir", cfg.RulesDir)
		}
	}

	return e
}

// SetAlertCallback links the Engine's physical threat discoveries back to the main Event Pipeline
func (e *Engine) SetAlertCallback(cb AlertCallback) {
	e.onAlert = cb
}

// Analyze matches an event through the rule matrix rapidly in-memory
func (e *Engine) Analyze(event models.NetworkEvent) {
	if !e.cfg.Enabled || event.Type == models.EventAlert {
		return
	}

	for _, rule := range e.rules {
		if alert := rule.Evaluate(event); alert != nil {
			e.logger.Errorw("⚠️  THREAT DETECTED IN PIPELINE  ⚠️",
				"rule", rule.Name(),
				"trigger_event", event.ID,
			)
			if e.onAlert != nil {
				e.onAlert(*alert)
			}
		}
	}
}

// AnalyzeAsset scans discovered hosts/configurations for anomalies
func (e *Engine) AnalyzeAsset(a models.Asset) {
	// Future expansion: Track Rogue APs, banned MAC addresses, unauthorized hardware
}
