package correlation

import "embed"

//go:embed rules/*.yaml
var embeddedRulesFS embed.FS
