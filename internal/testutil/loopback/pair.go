// Package loopback allocates local sockets for synthetic protocol fixtures.
package loopback

import (
	"fmt"
	"math/rand/v2"
	"net"
)

// Pair binds TCP and UDP to one nonprivileged loopback port. Windows has
// different excluded ranges for each protocol; its sequential ephemeral
// allocator can repeatedly select ports reserved for the other protocol.
// Choose independent candidates and retry boundedly without changing the OS.
func Pair() (net.Listener, net.PacketConn, error) {
	var last error
	for attempt := 0; attempt < 32; attempt++ {
		address := fmt.Sprintf("127.0.0.1:%d", 16384+rand.IntN(65536-16384))
		u, err := net.ListenPacket("udp", address)
		if err != nil {
			last = err
			continue
		}
		l, err := net.Listen("tcp", u.LocalAddr().String())
		if err == nil {
			return l, u, nil
		}
		u.Close()
		last = err
	}
	return nil, nil, fmt.Errorf("allocate loopback TCP/UDP pair: %w", last)
}
