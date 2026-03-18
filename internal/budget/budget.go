package budget

import (
	"fmt"
	"sync"
	"time"
)

type DomainBudget struct {
	MaxRequestsPerHour int `yaml:"max_requests_per_hour"`
	LoopThreshold      int `yaml:"loop_threshold"`
}

type Guard struct {
	mu      sync.Mutex
	budgets map[string]DomainBudget

	counters map[string][]time.Time

	loopTracker map[string][]time.Time
}

func New(budgets map[string]DomainBudget) *Guard {
	if budgets == nil {
		budgets = make(map[string]DomainBudget)
	}
	return &Guard{
		budgets:     budgets,
		counters:    make(map[string][]time.Time),
		loopTracker: make(map[string][]time.Time),
	}
}

func (g *Guard) Check(domain, method, url string) (blocked bool, warning string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	hour := time.Hour

	budget, hasBudget := g.budgets[domain]
	if !hasBudget {

		for d, b := range g.budgets {
			if matchesDomain(domain, d) {
				budget = b
				hasBudget = true
				break
			}
		}
	}

	if hasBudget && budget.MaxRequestsPerHour > 0 {

		window := pruneOlderThan(g.counters[domain], now.Add(-hour))
		window = append(window, now)
		g.counters[domain] = window

		if len(window) > budget.MaxRequestsPerHour {
			return true, fmt.Sprintf("rate limit exceeded: %d/%d requests/hour to %s",
				len(window), budget.MaxRequestsPerHour, domain)
		}
	} else {

		window := pruneOlderThan(g.counters[domain], now.Add(-hour))
		g.counters[domain] = append(window, now)
	}

	threshold := 5
	if hasBudget && budget.LoopThreshold > 0 {
		threshold = budget.LoopThreshold
	}

	key := method + " " + url
	loopWindow := pruneOlderThan(g.loopTracker[key], now.Add(-2*time.Minute))
	loopWindow = append(loopWindow, now)
	g.loopTracker[key] = loopWindow

	if len(loopWindow) >= threshold {
		warning = fmt.Sprintf("loop suspected: %s called %d times in 2 min",
			url, len(loopWindow))
	}

	return false, warning
}

func (g *Guard) Stats() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.counters))
	now := time.Now()
	for domain, timestamps := range g.counters {
		out[domain] = len(pruneOlderThan(timestamps, now.Add(-time.Hour)))
	}
	return out
}

func pruneOlderThan(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	return ts[i:]
}

func matchesDomain(host, parent string) bool {
	if host == parent {
		return true
	}
	if len(host) > len(parent)+1 {
		suffix := "." + parent
		return host[len(host)-len(suffix):] == suffix
	}
	return false
}

