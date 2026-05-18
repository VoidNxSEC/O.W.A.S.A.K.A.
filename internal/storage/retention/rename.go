package retention

import "os"

// renameImpl is the os.Rename indirection used by atomicRename. Kept
// in its own file so the testable shim in retention.go can stub it
// without pulling in os dependencies during the unit-test build path.
func renameImpl(src, dst string) error {
	return os.Rename(src, dst)
}
