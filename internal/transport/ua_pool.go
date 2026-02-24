// Package transport provides User-Agent rotation pool for HTTP appearance
package transport

import (
	"math/rand"
	"sync"
	"time"
)

// UA pools organized by browser type
var (
	chromeUAList  []string
	firefoxUAList []string
	safariUAList  []string
	edgeUAList    []string
	allUAList     []string

	uaPoolInitOnce sync.Once
	uaRandMu       sync.Mutex
	uaRand         *rand.Rand
)

func initUA() {
	// Chrome User-Aents (Windows, macOS, Linux)
	chromeUAList = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
	}

	// Firefox User-Agents
	firefoxUAList = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
	}

	// Safari User-Agents
	safariUAList = []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
	}

	// Edge User-Agents
	edgeUAList = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	}

	// Combine all UAs
	allUAList = make([]string, 0,
		len(chromeUAList)+len(firefoxUAList)+len(safariUAList)+len(edgeUAList))
	allUAList = append(allUAList, chromeUAList...)
	allUAList = append(allUAList, firefoxUAList...)
	allUAList = append(allUAList, safariUAList...)
	allUAList = append(allUAList, edgeUAList...)

	// Initialize random source with time-based seed
	uaRand = rand.New(rand.NewSource(time.Now().UnixNano()))
}

// GetRandomUA returns a random User-Agent from all available pools
func GetRandomUA() string {
	uaPoolInitOnce.Do(initUA)

	uaRandMu.Lock()
	defer uaRandMu.Unlock()

	if len(allUAList) == 0 {
		return ""
	}
	return allUAList[uaRand.Intn(len(allUAList))]
}

// GetChromeUA returns a random Chrome User-Agent
func GetChromeUA() string {
	uaPoolInitOnce.Do(initUA)

	uaRandMu.Lock()
	defer uaRandMu.Unlock()

	if len(chromeUAList) == 0 {
		return ""
	}
	return chromeUAList[uaRand.Intn(len(chromeUAList))]
}

// GetFirefoxUA returns a random Firefox User-Agent
func GetFirefoxUA() string {
	uaPoolInitOnce.Do(initUA)

	uaRandMu.Lock()
	defer uaRandMu.Unlock()

	if len(firefoxUAList) == 0 {
		return ""
	}
	return firefoxUAList[uaRand.Intn(len(firefoxUAList))]
}

// GetSafariUA returns a random Safari User-Agent
func GetSafariUA() string {
	uaPoolInitOnce.Do(initUA)

	uaRandMu.Lock()
	defer uaRandMu.Unlock()

	if len(safariUAList) == 0 {
		return ""
	}
	return safariUAList[uaRand.Intn(len(safariUAList))]
}

// GetEdgeUA returns a random Edge User-Agent
func GetEdgeUA() string {
	uaPoolInitOnce.Do(initUA)

	uaRandMu.Lock()
	defer uaRandMu.Unlock()

	if len(edgeUAList) == 0 {
		return ""
	}
	return edgeUAList[uaRand.Intn(len(edgeUAList))]
}

// GetUAByBrowser returns a random User-Agent for the specified browser
// Supported browsers: chrome, firefox, safari, edge, any
func GetUAByBrowser(browser string) string {
	switch browser {
	case "chrome":
		return GetChromeUA()
	case "firefox":
		return GetFirefoxUA()
	case "safari":
		return GetSafariUA()
	case "edge":
		return GetEdgeUA()
	default:
		return GetRandomUA()
	}
}

// UACount returns the total number of User-Agents in the pool
func UACount() int {
	uaPoolInitOnce.Do(initUA)
	return len(allUAList)
}
