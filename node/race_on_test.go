//go:build race

package node

// raceEnabled is true when the test binary is built with -race. Used to skip
// tests that trip data races inside upstream Xray (documented at the skip
// site).
const raceEnabled = true
