package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	//lint:ignore ST1001 acceptable here.
	. "go-first/ws-test/constants"
	"go-first/ws-test/models"
	"go-first/ws-test/utils"

	"github.com/coder/websocket"
)

// PlayerId -> IP:port map per authenticated player
//
// # valid address means player is connected
var authenticatedPlayerToAddrMap map[[20]byte]models.CompactAddr

// Rate limit playerId map per authenticated player stays active between disconnects
var rateLimitMap map[[20]byte]*models.Rate

// Rate limit IPv4 address map any possible connection requests made by an ip will be recorded
var hardRateLimitedIPMap map[[4]byte]models.Rate
var hrlMutex sync.Mutex

var connectionStructuresMutex sync.RWMutex
var activeConnectionsToDrop []models.CompactAddr

func InitGlobalStructs() {

	authenticatedPlayerToAddrMap = map[[20]byte]models.CompactAddr{}
	authenticatedPlayerToAddrMap[models.StringTo20Byte("cardano")] = models.NewCompactAddr(net.IP{}, 0)

	rateLimitMap = map[[20]byte]*models.Rate{}

	hardRateLimitedIPMap = map[[4]byte]models.Rate{}
	activeConnectionsToDrop = make([]models.CompactAddr, 0, 5)

}

// echoServer is the WebSocket echo server implementation.
// It ensures the client speaks the echo subprotocol and
// only allows one message every 100ms with a 10 message burst.
type echoServer struct {
	// logf controls where logs are sent.
	logf func(f string, v ...interface{})
}

func getSizeInBytes(m map[string][]string) int {
	data, _ := json.Marshal(m)
	return len(data) // Returns size in bytes
}

//go:inline
func isOldClient(remoteAddress models.CompactAddr) bool {
	// We don't need to modify any mappings
	if len(activeConnectionsToDrop) > 0 {
		connectionStructuresMutex.RLock()
		for i, _remoteAddress := range activeConnectionsToDrop {
			if _remoteAddress == remoteAddress {
				var sliceLen = len(activeConnectionsToDrop)

				connectionStructuresMutex.RUnlock()
				connectionStructuresMutex.Lock()
				if i != sliceLen-1 {
					activeConnectionsToDrop[i] = activeConnectionsToDrop[sliceLen-1]
				}
				activeConnectionsToDrop = activeConnectionsToDrop[:sliceLen-1]

				connectionStructuresMutex.Unlock()
				return true
			}
		}
		connectionStructuresMutex.RUnlock()
	}
	return false
}

func (s echoServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Sec-Websocket-Protocol") != "echo" {
		http.Error(w, "client must speak the echo subprotocol", 400)
		return
	}

	playerId := models.StringTo20Byte(r.Header.Get("Player-ID"))

	fmt.Printf("[%v] Connection Req from -> %v\n%v\n", getSizeInBytes(r.Header), playerId, r.Header)
	fmt.Printf("Connection IP:Port -> %v\n", r.RemoteAddr)

	oldRemoteAddress, exists := authenticatedPlayerToAddrMap[playerId]
	remoteAddr := utils.DropOldConnections(oldRemoteAddress, r.RemoteAddr, &connectionStructuresMutex, &activeConnectionsToDrop)
	if remoteAddr.Port == 0 {
		// Invalid remote connection
		http.Error(w, "invalid ipv4 address", 400)
		return
	}
	if !exists {
		retryNextTs := utils.SaveConnectionRequestData(&hardRateLimitedIPMap, remoteAddr.IP, &hrlMutex)
		var builder strings.Builder
		builder.WriteString("invalid request")
		tsNow := time.Now().UnixMilli()
		if retryNextTs > tsNow {
			builder.WriteString(", retry after ")
			builder.WriteString(strconv.FormatInt(retryNextTs, 10))
		}
		http.Error(w, builder.String(), 400)
		return
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"echo"},
	})
	if err != nil {
		s.logf("%v", err)
		return
	}
	shouldCloseConn := true

	defer func() {
		if shouldCloseConn {
			c.CloseNow()
		}
		connectionStructuresMutex.Lock()
		authenticatedPlayerToAddrMap[playerId] = models.CompactAddr{}
		connectionStructuresMutex.Unlock()
	}()

	authenticatedPlayerToAddrMap[playerId] = remoteAddr
	// If player's connections is successful request tokens will stay 0
	existingConnectionData, exists := rateLimitMap[playerId]
	var (
		useExisting              = exists && existingConnectionData.WindowActive()
		startTime                int64
		validNextReqTs           int64
		tokensLeft               int8
		connectTokensLeft        int8
		lastRateLimitViolationTs int64
		rateLimitViolations      int8
	)

	if useExisting {
		startTime = existingConnectionData.FirstReqUnixTsInMs
		tokensLeft = existingConnectionData.TokensLeft
		connectTokensLeft = max(0, existingConnectionData.ConnectTokenLeft-TOKEN_CONSUMPTION_PER_REQUEST)
		validNextReqTs = existingConnectionData.ValidNextReqTs
		lastRateLimitViolationTs = existingConnectionData.LastRateLimitViolationTs
		rateLimitViolations = existingConnectionData.RateLimitViolations
	} else {
		startTime = time.Now().UnixMilli()
		tokensLeft = 10
		connectTokensLeft = MAX_CONNECT_TOKENS
	}

	newConnectionData := models.Rate{
		FirstReqUnixTsInMs:       startTime,
		ValidNextReqTs:           validNextReqTs,
		TokensLeft:               tokensLeft,
		ConnectTokenLeft:         connectTokensLeft,
		LastRateLimitViolationTs: lastRateLimitViolationTs,
		RateLimitViolations:      rateLimitViolations,
	}

	rateLimitMap[playerId] = &newConnectionData
	for {
		if isOldClient(remoteAddr) {
			s.logf("Old client disconnected %v", r.RemoteAddr)
			return
		}
		err = echo(c, &newConnectionData)
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
			return
		}
		if err != nil {
			s.logf("failed to echo with %v: %v", r.RemoteAddr, err)
			if err.Error() == "rate limit exeeded" {
				c.Close(websocket.StatusTryAgainLater, "too many requests")
				shouldCloseConn = false
			}
			return
		}
	}
}

// echo reads from the WebSocket connection and then writes
// the received message back to it.
// The entire function has 10s to complete.
func echo(c *websocket.Conn, l *models.Rate) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	shouldDisconnect, err := l.WaitForToken(ctx, 1)
	if shouldDisconnect {
		backoff := min(EXPONENTIAL_BACKOFF_RATE_LIMIT_MS*(1<<l.RateLimitViolations), MAX_RETRY_AFTER_MS)
		l.ValidNextReqTs = time.Now().UnixMilli() + int64(backoff)
		return errors.New("rate limit exeeded")
	}
	if err != nil {
		return err
	}

	fmt.Printf("%v -> %v\n", time.Now().UnixMilli(), l)

	typ, r, err := c.Reader(ctx) // Waits for msg from client
	if err != nil {
		return err
	}

	fmt.Printf("%v ReadFinished\n", time.Now().UnixMilli())

	w, err := c.Writer(ctx, typ)
	if err != nil {
		return err
	}
	// content, err := ioutil.ReadAll(r)
	// if err != nil {
	// 	fmt.Println("Error reading:", err)
	// }

	// // Print the content as a string
	// fmt.Printf("%v -> %v\n", time.Now().UnixMilli(), string(content))

	_, err = io.Copy(w, r)
	if err != nil {
		return fmt.Errorf("failed to io.Copy: %w", err)
	}

	err = w.Close()
	return err
}
