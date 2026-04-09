package whitelist_dynamic

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config holds the plugin configuration.
type Config struct {
	Sources         []string `yaml:"sources" json:"sources"`
	RefreshInterval string   `yaml:"refreshInterval" json:"refreshInterval"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		RefreshInterval: "5m",
	}
}

// Plugin implements the Traefik middleware interface.
type Plugin struct {
	name    string
	next    http.Handler
	allowed []*net.IPNet
	mu      sync.RWMutex
	stopCh  chan struct{}
}

// New creates a new plugin instance.
func New(next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Sources) == 0 {
		return nil, fmt.Errorf("whitelist-dynamic: sources cannot be empty")
	}

	interval, err := time.ParseDuration(config.RefreshInterval)
	if err != nil {
		interval = 5 * time.Minute
	}

	p := &Plugin{
		name:   name,
		next:   next,
		stopCh: make(chan struct{}),
	}

	// Initial resolution
	p.updateAllowed(config.Sources)

	// Start background resolver
	go p.resolverLoop(config.Sources, interval)

	return p, nil
}

// resolverLoop periodically re-resolves hostnames and updates the allowed list.
func (p *Plugin) resolverLoop(sources []string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.updateAllowed(sources)
		case <-p.stopCh:
			return
		}
	}
}

// updateAllowed parses IPs, CIDRs, and resolves hostnames into a thread-safe allowlist.
func (p *Plugin) updateAllowed(sources []string) {
	var newAllowed []*net.IPNet

	for _, src := range sources {
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}

		// 1. Exact IP
		if ip := net.ParseIP(src); ip != nil {
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			newAllowed = append(newAllowed, &net.IPNet{IP: ip, Mask: mask})
			continue
		}

		// 2. CIDR Range
		_, ipNet, err := net.ParseCIDR(src)
		if err == nil {
			newAllowed = append(newAllowed, ipNet)
			continue
		}

		// 3. Hostname (dynamic resolution)
		ips, err := net.LookupHost(src)
		if err != nil {
			log.Printf("whitelist-dynamic: DNS resolution failed for %s: %v", src, err)
			continue
		}
		for _, ipStr := range ips {
			if ip := net.ParseIP(ipStr); ip != nil {
				mask := net.CIDRMask(32, 32)
				if ip.To4() == nil {
					mask = net.CIDRMask(128, 128)
				}
				newAllowed = append(newAllowed, &net.IPNet{IP: ip, Mask: mask})
			}
		}
	}

	p.mu.Lock()
	p.allowed = newAllowed
	p.mu.Unlock()
}

func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := req.RemoteAddr
	// Strip port if present
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	p.mu.RLock()
	allowed := p.allowed
	p.mu.RUnlock()

	for _, ipNet := range allowed {
		if ipNet.Contains(ip) {
			p.next.ServeHTTP(rw, req)
			return
		}
	}

	http.Error(rw, "Forbidden", http.StatusForbidden)
}
