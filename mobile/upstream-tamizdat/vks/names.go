package vks

import (
	"github.com/funnybones69/tamizdat/vks/olc/core/names"
)

// DisplayName returns a random realistic Russian display name (gender-agreed,
// with casual latin/nickname variants). Delegates to the shared generator so
// every participant name across the stack comes from one pool.
func DisplayName() string {
	return names.Generate()
}
