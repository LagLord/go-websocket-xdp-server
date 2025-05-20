package models

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	//lint:ignore ST1001 acceptable here.
	. "ws-server/src/constants"
)

type CompactAddr struct {
	IP   uint32 // IPv4-only
	Port uint16
}

// Convert net.IP to [16]byte
func NewCompactAddr(ip net.IP, port uint16) CompactAddr {
	ip = ip.To4()
	ip4 := uint32(ip[3])<<24 | uint32(ip[2])<<16 | uint32(ip[1])<<8 | uint32(ip[0])

	return CompactAddr{IP: ip4, Port: port}
}

type Rate struct {
	FirstReqUnixTsInMs       int64
	ValidNextReqTs           int64
	LastRateLimitViolationTs int64

	TokensLeft          int8
	ConnectTokenLeft    int8
	RateLimitViolations int8
}

func (rate *Rate) WaitForToken(ctx context.Context, tokenQty uint) (bool, error) {
	var timerDur time.Duration = 0
	var shouldDisconnect = false
	unixTsNow := time.Now().UnixMilli()
	// if (rate.RateLimitViolations != 0) {
	// 	timerDur += time.Second * 1
	// }

	if rate.TokensLeft <= 0 {
		if rate.RateLimitViolations > 0 {
			if (rate.LastRateLimitViolationTs - unixTsNow) < RATE_LIMIT_INTERVAL/10 {
				shouldDisconnect = true
			} else {
				rate.RateLimitViolations = 0
			}
		}
		sleepMs := rate.FirstReqUnixTsInMs + RATE_LIMIT_INTERVAL + 1 - unixTsNow
		if sleepMs > 0 {
			fmt.Printf("rate limited waiting for %v ms\n", sleepMs)
			timerDur += time.Duration(sleepMs) * time.Millisecond
			unixTsNow += sleepMs
		}
		rate.RateLimitViolations++
		rate.LastRateLimitViolationTs = unixTsNow
	}
	if rate.FirstReqUnixTsInMs+RATE_LIMIT_INTERVAL < unixTsNow {
		rate.FirstReqUnixTsInMs = unixTsNow
		rate.TokensLeft = MAX_TOKENS
	}
	rate.TokensLeft -= 1

	select {
	case <-ctx.Done():
		return shouldDisconnect, ctx.Err()
	case <-time.After(timerDur):
		return shouldDisconnect, nil
	}
}

//go:inline
func (rate *Rate) WindowActive() bool {
	return rate.FirstReqUnixTsInMs+RATE_LIMIT_INTERVAL > time.Now().UnixMilli()
}

type ConnectionRateData struct {
	ConnectionActive bool
	RateData         Rate
}

func StringTo20Byte(s string) [20]byte {
	var result [20]byte
	copy(result[:], s) // Copies up to 20 bytes, pads with zeros if shorter
	return result
}

type PairedUserConnFields struct {
	PlayerIDs       [][]byte
	PlayerAddresses []CompactAddr
	Mu              sync.Mutex
}

func (p *PairedUserConnFields) Show() {
	fmt.Printf("PairedUserConnFields: %v : %v", p.PlayerIDs, p.PlayerAddresses)
}

func (p *PairedUserConnFields) Add(playerID string, playerAddr CompactAddr) {
	p.Mu.Lock()
	p.PlayerIDs = append(p.PlayerIDs, unsafe.Slice(unsafe.StringData(playerID), len(playerID)))
	p.PlayerAddresses = append(p.PlayerAddresses, playerAddr)
	p.Mu.Unlock()
}

func (p *PairedUserConnFields) Remove(index int) error {
	// Check for empty slices
	if len(p.PlayerIDs) == 0 || len(p.PlayerAddresses) == 0 {
		return errors.New("slices are empty")
	}

	// Validate index
	if index < 0 || index >= len(p.PlayerIDs) {
		return fmt.Errorf("index %d out of bounds", index)
	}

	// Swap with last element (if needed)
	sliceLen := len(p.PlayerIDs)

	p.Mu.Lock()
	if index != sliceLen-1 {
		p.PlayerIDs[index] = p.PlayerIDs[sliceLen-1]
		p.PlayerAddresses[index] = p.PlayerAddresses[sliceLen-1]
	}

	// Truncate slices
	p.PlayerIDs = p.PlayerIDs[:sliceLen-1]
	p.PlayerAddresses = p.PlayerAddresses[:sliceLen-1]
	p.Mu.Unlock()

	return nil
}
