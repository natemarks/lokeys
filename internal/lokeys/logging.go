package lokeys

import (
	"fmt"
	"io"
	"os"
	"sync"
)

var (
	verboseMu      sync.RWMutex
	verboseEnabled bool
	verboseWriter  io.Writer = os.Stderr
)

// SetVerbose enables or disables verbose logging globally.
func SetVerbose(enabled bool) {
	verboseMu.Lock()
	defer verboseMu.Unlock()
	verboseEnabled = enabled
}

func vlogf(format string, args ...interface{}) {
	verboseMu.RLock()
	enabled := verboseEnabled
	out := verboseWriter
	verboseMu.RUnlock()
	if !enabled {
		return
	}
	fmt.Fprintf(out, "[lokeys] "+format+"\n", args...)
}
