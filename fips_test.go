package argon

import (
	"crypto/fips140"
	"errors"
	"testing"
)

func TestFIPSPolicy(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("requires FIPS mode")
	}
	for _, operation := range []func() error{
		func() error { _, err := Hash("password"); return err },
		func() error { _, err := Verify("password", "invalid"); return err },
	} {
		if err := operation(); !errors.Is(err, ErrFIPSUnsupported) {
			t.Fatalf("operation error = %v", err)
		}
	}
}
