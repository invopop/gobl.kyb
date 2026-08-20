//go:build mage

// Mage targets for gobl.kyb. Run via `mage <target>`.
package main

import (
	"github.com/magefile/mage/sh"
)

// Lint runs golangci-lint over the entire module.
func Lint() error {
	return sh.RunV("golangci-lint", "run", "./...")
}

// Test runs the Go test suite.
func Test() error {
	return sh.RunV("go", "test", "./...")
}

// TestRace runs the suite with the race detector enabled.
func TestRace() error {
	return sh.RunV("go", "test", "-race", "./...")
}

// Check runs Lint and TestRace; the recommended pre-PR gate.
func Check() error {
	if err := Lint(); err != nil {
		return err
	}
	return TestRace()
}

// Build compiles the gobl.kyb binary into ./bin.
func Build() error {
	return sh.RunV("go", "build", "-o", "./bin/gobl.kyb", "./cmd/gobl.kyb")
}
