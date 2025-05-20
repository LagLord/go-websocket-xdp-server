package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type ServerContext struct {

	// PlayerId -> IP:port map per authenticated player
	//
	// # valid address means player is connected
	AuthenticatedPlayerIDToAddrMap map[[20]byte]models.CompactAddr

	// Rate limit playerId map per authenticated player stays active between disconnects
	RateLimitMap map[[20]byte]*models.Rate

	// Rate limit IPv4 address map any possible connection requests made by an ip will be recorded
	HardRateLimitedIPMap map[uint32]models.Rate

	HRLMutex                  sync.Mutex
	ConnectionStructuresMutex sync.RWMutex
	ActiveConnectionsToDrop   []models.CompactAddr
}

func InitGlobalStructs(serverCtx *ServerContext) {

	serverCtx.AuthenticatedPlayerIDToAddrMap = map[[20]byte]models.CompactAddr{}
	serverCtx.AuthenticatedPlayerIDToAddrMap[models.StringTo20Byte("cardano")] = models.NewCompactAddr([]byte{0, 0, 0, 0}, 0)

	serverCtx.RateLimitMap = map[[20]byte]*models.Rate{}

	serverCtx.HardRateLimitedIPMap = map[uint32]models.Rate{}

	serverCtx.HRLMutex = sync.Mutex{}
	serverCtx.ConnectionStructuresMutex = sync.RWMutex{}
	serverCtx.ActiveConnectionsToDrop = make([]models.CompactAddr, 0, 5)

}

// echoServer is the WebSocket echo server implementation.
// It ensures the client speaks the echo subprotocol and
// only allows one message every 100ms with a 10 message burst.
type echoServer struct {
	// logf controls where logs are sent.
	logf      func(f string, v ...interface{})
	serverCtx *ServerContext
}

func getSizeInBytes(m map[string][]string) int {
	data, _ := json.Marshal(m)
	return len(data) // Returns size in bytes
}

//go:inline
func checkAndUpdateOldClient(
	remoteAddress models.CompactAddr,
	activeConnectionsToDrop []models.CompactAddr,
	connectionStructuresMutex *sync.RWMutex,
) []models.CompactAddr {
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
				return activeConnectionsToDrop
			}
		}
		connectionStructuresMutex.RUnlock()
	}
	return nil
}

func (s echoServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Sec-Websocket-Protocol") != "echo" {
		http.Error(w, "client must speak the echo subprotocol", 400)
		return
	}
	serverCtx := s.serverCtx

	playerId := models.StringTo20Byte(r.Header.Get("Player-ID"))

	s.logf("[%v] Connection Req from -> %v\n%v\n", getSizeInBytes(r.Header), playerId, r.Header)
	s.logf("Connection IP:Port -> %v\n", r.RemoteAddr)

	oldRemoteAddress, exists := serverCtx.AuthenticatedPlayerIDToAddrMap[playerId]
	remoteAddr := utils.DropOldConnections(oldRemoteAddress, r.RemoteAddr, &serverCtx.ConnectionStructuresMutex, &serverCtx.ActiveConnectionsToDrop)
	if remoteAddr.Port == 0 {
		// Invalid remote connection
		http.Error(w, "invalid ipv4 address", 400)
		return
	}
	if !exists {
		retryNextTs := utils.SaveConnectionRequestData(&serverCtx.HardRateLimitedIPMap, remoteAddr.IP, &serverCtx.HRLMutex)
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
		serverCtx.ConnectionStructuresMutex.Lock()
		serverCtx.AuthenticatedPlayerIDToAddrMap[playerId] = models.CompactAddr{}
		serverCtx.ConnectionStructuresMutex.Unlock()
	}()

	serverCtx.AuthenticatedPlayerIDToAddrMap[playerId] = remoteAddr
	// If player's connections is successful request tokens will stay 0
	existingConnectionData, exists := serverCtx.RateLimitMap[playerId]
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

	serverCtx.RateLimitMap[playerId] = &newConnectionData
	for {
		newActiveConnsToDrop := checkAndUpdateOldClient(remoteAddr, serverCtx.ActiveConnectionsToDrop, &serverCtx.ConnectionStructuresMutex)

		if newActiveConnsToDrop != nil {
			serverCtx.ActiveConnectionsToDrop = newActiveConnsToDrop
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
// The entire function has 30s to complete.
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
