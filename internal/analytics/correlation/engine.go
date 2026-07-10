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

	// Load built-in rules embedded in the binary.
	builtIn, err := LoadRulesFromFS(embeddedRulesFS, "rules")
	if err != nil {
		logger.Errorw("Failed to load embedded correlation rules", "error", err)
	} else if len(builtIn) > 0 {
		e.rules = append(e.rules, builtIn...)
		logger.Infow("Loaded built-in YAML correlation rules", "count", len(builtIn))
	}

	// Append operator-supplied rules from disk (overrides or extensions).
	if cfg.RulesDir != "" {
		custom, err := LoadRulesFromDir(cfg.RulesDir)
		if err != nil {
			logger.Errorw("Failed to load custom correlation rules", "dir", cfg.RulesDir, "error", err)
		} else if len(custom) > 0 {
			e.rules = append(e.rules, custom...)
			logger.Infow("Loaded custom YAML correlation rules", "count", len(custom), "dir", cfg.RulesDir)
		}
	}

	logger.Infow("Correlation engine ready", "total_rules", len(e.rules))
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
