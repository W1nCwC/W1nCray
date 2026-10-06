//go:build race

package core

// raceEnabled is true when the test binary is built with -race. Used to skip
// tests that trip data races inside upstream Xray (documented at the skip
// site) and to scale timing windows.
const raceEnabled = true
