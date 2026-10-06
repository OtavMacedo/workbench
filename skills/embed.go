// Package skills ships the same Agent Skill used by Vercel Skills in the CLI.
package skills

import _ "embed"

//go:embed workbench/SKILL.md
var Workbench []byte
