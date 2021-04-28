package auth

import (
	"math"
	"net/http"
	"sync"
	"time"
)

type rateLimiter struct {
	mutex   sync.Mutex
	records map[string]*rateRecord

	// the last time we checked for old records
	lastCheck float64
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		records: make(map[string]*rateRecord),
	}
}

type rateRecord struct {
	name   string
	rate   float64
	period float64
	at     float64
	value  float64
}

func (r *rateLimiter) removeExpired(now float64) {
	// only call when locked

	// ten minutes
	if now-r.lastCheck < 10*60 {
		return
	}

	for name, rec := range r.records {
		rec.update(now)
		if rec.value == 0 {
			delete(r.records, name)
		}
	}
}

func (r *rateLimiter) getRecord(name string, rate, period, now float64) *rateRecord {
	rec := r.records[name]
	if rec == nil {
		rec = &rateRecord{name: name, rate: rate, period: period, at: now}
		r.records[name] = rec
	} else {
		rec.update(now)
	}
	return rec
}

func (r *rateLimiter) isAllowed(name string, cost, rate float64, periodTime time.Duration, update bool) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := float64(now().Unix())
	r.removeExpired(now)
	period := float64(periodTime / time.Second)
	record := r.getRecord(name, rate, period, now)
	if record.value+cost < record.rate {
		if update {
			record.value += cost
		}
		return true
	}
	return false
}

func (r *rateLimiter) hasRecord(name string) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := float64(now().Unix())
	record := r.records[name]
	if record != nil {
		record.update(now)
		return record.value > 0
	}

	return false
}

func (record *rateRecord) update(now float64) {
	elapsed := now - record.at

	// leaky bucket algorithm
	record.value = math.Max(0, record.value-elapsed*record.rate/
		record.period)
	record.at = now
}

var globalLimiter *rateLimiter

func init() {
	globalLimiter = newRateLimiter()
}

// RateLimitAllows will return true if the given operation is allowed. Name is an
// arbitrary string that uniquely identifies the user and operation.
// cost is the cost of the operation, and rate is the max cost allowed in the
// given time period.
//
// Example: user 123 logs in, and the maximum attempts allowed are
// 5 in a 10 minute period.
// if auth.RateLimitAllows(name, 1, 5, 10 * time.Minute) {
//     // succeeded
// }
func RateLimitAllows(name string, cost, rate float64, period time.Duration) bool {
	return globalLimiter.isAllowed(name, cost, rate, period, true)
}

// RateLimitCheck checks if the given operation would be allowed, but does not update
// it.
func RateLimitCheck(name string, cost, rate float64, period time.Duration) bool {
	return globalLimiter.isAllowed(name, cost, rate, period, false)
}

// DoRateLimit will rate limit an operation on both the user and ip address.
// If it is not allowed, it will return false
// If it is allowed, it will then assume the operation was carried out and return true
func DoRateLimit(operation string, req *http.Request, user string, rate float64, period time.Duration) bool {
	userlimit := operation + ":" + user
	iplimit := operation + ":" + GetIPAddress(req)

	if !globalLimiter.isAllowed(userlimit, 1, rate, period, false) ||
		!globalLimiter.isAllowed(iplimit, 1, rate, period, false) {
		HTTPPanic(429, "try again later")
	}

	globalLimiter.isAllowed(userlimit, 1, rate, period, true)
	globalLimiter.isAllowed(iplimit, 1, rate, period, true)
	return true
}

// HasRateLimit returns true if the bucket for the given operation has
// any attempts, regardless of wether they have reached the limit or not.
func HasRateLimit(name string) bool {
	return globalLimiter.hasRecord(name)
}
