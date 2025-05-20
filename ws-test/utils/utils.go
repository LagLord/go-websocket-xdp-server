package utils

import (
	"fmt"
	"unsafe"

	//lint:ignore ST1001 acceptable here.
	. "go-first/ws-test/constants"
	"go-first/ws-test/models"

	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func Ternary[T any](condition bool, trueVal, falseVal T) T {
	if condition {
		return trueVal
	}
	return falseVal
}

func DropOldConnections(oldRemoteAddress models.CompactAddr, remoteAddr string, mu *sync.RWMutex, activeConnectionsToDrop *[]models.CompactAddr) models.CompactAddr {
	// Split the remote address (e.g., "192.168.1.1:8080")
	remoteParts := strings.Split(remoteAddr, ":")
	if len(remoteParts) < 2 {
		return models.CompactAddr{}
	}

	// Parse IP (handles both IPv4 and IPv6)
	ip := net.ParseIP(remoteParts[0])
	if ip == nil {
		return models.CompactAddr{}
	}

	// Parse port
	port, err := strconv.ParseUint(remoteParts[1], 10, 16)
	if err != nil {
		return models.CompactAddr{}
	}

	// Create CompactAddr
	_remoteAddr := models.NewCompactAddr(ip, uint16(port))

	if oldRemoteAddress.Port != 0 {
		if oldRemoteAddress != _remoteAddr {
			// This will drop the old client's connection
			mu.Lock()
			*activeConnectionsToDrop = append(*activeConnectionsToDrop, oldRemoteAddress)
			mu.Unlock()
		} else {
			// if address is the same then we need to exit
			return models.CompactAddr{}
		}
	}

	return _remoteAddr
}

func SaveConnectionRequestData(
	hardRateLimitedIPMap *map[uint32]models.Rate,
	ip uint32,
	mu *sync.Mutex,
) int64 {
	mu.Lock()
	defer mu.Unlock()

	_rate, exists := (*hardRateLimitedIPMap)[ip]
	unixTsNow := time.Now().UnixMilli()
	// If connected earlier or it's been 1s
	if exists {
		fmt.Printf("[%v]_rate %v\n", unsafe.Sizeof(models.Rate{}), _rate)
		windowActive := _rate.WindowActive()
		_rate.ConnectTokenLeft = max(0, _rate.ConnectTokenLeft-TOKEN_CONSUMPTION_PER_REQUEST)

		// If another violation or all tokens spent
		var violationActive = (_rate.ValidNextReqTs > unixTsNow)
		var tokensSpent = (_rate.ConnectTokenLeft == 0 && windowActive)
		if violationActive || tokensSpent {
			// Rate limit violation in case missed by xdp
			_rate.RateLimitViolations++
			backoff := min(EXPONENTIAL_BACKOFF_RATE_LIMIT_MS*(1<<_rate.RateLimitViolations), MAX_RETRY_AFTER_MS)
			_rate.ValidNextReqTs = unixTsNow + int64(backoff)

			if violationActive {
				RemoveOldMapUpdatesFromQueue(ip)
			}
			// Add to blocked ips
			AddMapUpdateToQueue(MapUpdateOp{
				OpType: MapAdd,
				IP:     ip,
			})
			// Remove from blocked ips after rate limit ts
			go func() {
				time.After(time.Duration(int64(backoff)) * time.Millisecond)
				AddMapUpdateToQueue(MapUpdateOp{
					OpType: MapRemove,
					IP:     ip,
				})
			}()

		} else if !windowActive {
			_rate.FirstReqUnixTsInMs = unixTsNow
			_rate.ValidNextReqTs = 0
			_rate.ConnectTokenLeft = MAX_CONNECT_TOKENS - TOKEN_CONSUMPTION_PER_REQUEST
		}

	} else {
		_rate = models.Rate{
			FirstReqUnixTsInMs: unixTsNow,
			ConnectTokenLeft:   MAX_CONNECT_TOKENS - TOKEN_CONSUMPTION_PER_REQUEST,
		}
	}

	(*hardRateLimitedIPMap)[ip] = _rate

	fmt.Printf("Player not found/authenticated\n%v\n%v\n", ip, hardRateLimitedIPMap)
	return _rate.ValidNextReqTs
}
