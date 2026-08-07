// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logsrvclient/backoff.go
package logsrvclient

import (
	"context"
	"math"
	"math/rand/v2"
	"time"
)

// InitialReconnectInterval is the first retry delay; each subsequent attempt
// doubles it until MaxInterval caps the series.
const InitialReconnectInterval = time.Second

// DefaultMaxInterval caps the backoff series when a caller passes a
// non-positive maxInterval.
const DefaultMaxInterval = time.Minute

// maxBackoffExponent caps the math.Pow(2, n) input to keep backoff from
// overflowing float64 into +Inf during infinite-reconnect runs. 2^62ns is
// already ~146 years — well past any realistic maxInterval.
const maxBackoffExponent = 62

// Backoff returns the delay to wait after `attempts` consecutive failures,
// capped at maxInterval and jittered.
//
// The jitter is equal jitter -- base/2 + rand(0, base/2) -- not full jitter,
// so a fleet of clients that lost the same server does not reconnect in a
// synchronized wave while still guaranteeing a floor of maxInterval/2 once the
// series is saturated. math/rand/v2 is auto-seeded per process and safe for
// concurrent use.
func Backoff(attempts int, maxInterval time.Duration) time.Duration {
	if maxInterval <= 0 {
		maxInterval = DefaultMaxInterval
	}
	exp := min(attempts, maxBackoffExponent)
	backoff := min(
		float64(InitialReconnectInterval)*math.Pow(2, float64(exp)),
		float64(maxInterval),
	)
	half := time.Duration(backoff) / 2
	if half > 0 {
		return half + time.Duration(rand.Int64N(int64(half)))
	}
	return time.Duration(backoff)
}

// Sleep waits for d, or returns ctx.Err() if cancellation arrives first. Used
// for backoff and jitter splays that must respect shutdown.
func Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
