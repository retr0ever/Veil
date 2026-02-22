// Package netguard provides SSRF protection by blocking connections to
// private/internal IP ranges. Used by both the proxy handler (at connection
// time) and the site creation handler (at registration time).
package netguard

import "net"

// BlockedCIDRs are private/internal networks that upstreams must never resolve to.
var BlockedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",    // loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918 / Docker bridge networks
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // link-local / cloud metadata
		"0.0.0.0/8",      // unspecified
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local
	}
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, ipNet, _ := net.ParseCIDR(c)
		nets = append(nets, ipNet)
	}
	return nets
}()

// IsBlocked returns true if the IP falls within a private/internal range.
func IsBlocked(ip net.IP) bool {
	for _, cidr := range BlockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
