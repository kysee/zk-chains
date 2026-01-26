package bprn

import "testing"

func TestProve(t *testing.T) {
	prover := NewBPrNListener(nil)
	prover.startRoutine(1621)
}
