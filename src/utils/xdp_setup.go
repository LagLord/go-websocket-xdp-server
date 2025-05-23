package utils

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	cilium "github.com/cilium/ebpf"
)

type MapOp string

const (
	MapAdd    MapOp = "add"
	MapRemove MapOp = "remove"
)

type MapUpdateOp struct {
	OpType MapOp
	IP     uint32
}

var gBlockedIpsMap *cilium.Map
var gMapUpdateQueue []MapUpdateOp = make([]MapUpdateOp, 1)

func SetupXdp(_interface string) {
	deviceName := _interface // "wlp0s20f3"

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	bpfModule, err := bpf.NewModuleFromFile("xdp_filter.bpf.o")
	stopOnError(err)
	defer bpfModule.Close()

	stopOnError(bpfModule.BPFLoadObject())

	xdpProg, err := bpfModule.GetProgram("xdp_filter")
	stopOnError(err)

	err = xdpProg.AttachXDPLegacy(deviceName, bpf.XDPFlagsReplace)
	stopOnError(err)
	err = xdpProg.DetachXDPLegacy(deviceName, bpf.XDPFlagsReplace)
	stopOnError(err)

	_, err = xdpProg.AttachXDP(deviceName)
	stopOnError(err)

	// Load the pinned BPF map (or from ELF)
	_blockedIPsMap, err := cilium.LoadPinnedMap("/sys/fs/bpf/blocked_ips", nil)
	if err != nil {
		fmt.Printf("Failed to load BPF map: %v\n", err)
	}
	defer _blockedIPsMap.Close()
	gBlockedIpsMap = _blockedIPsMap

	<-sig
	// Dont need to detach it as the new AttachXDP uses bpf_link and will detach automatically
	// err = xdpProg.DetachXDPLegacy(deviceName, bpf.XDPFlagsReplace)
	// stopOnError(err)
	fmt.Println("Cleaning up")
}

func BlockIpAddress(ipKey uint32) bool {
	// --- ADD AN IP TO BLOCK ---
	if gBlockedIpsMap == nil {
		return false
	}

	value := uint8(1) // 1 = blocked

	// Insert into map
	err := gBlockedIpsMap.Put(ipKey, value)
	if err != nil {
		log.Fatalf("Failed to block IP: %v\n", err)
	}
	fmt.Printf("Blocked IP: %v hex:0x%x\n", ipKey, ipKey)
	return true
}

func UnblockedIpAddress(ipToBlock uint32) bool {
	if gBlockedIpsMap == nil {
		return false
	}
	// --- DELETE AN IP (UNBLOCK) ---
	err := gBlockedIpsMap.Delete(ipToBlock)
	if err != nil {
		log.Fatalf("Failed to unblock IP: %v", err)
	}
	// fmt.Printf("Unblocked IP: %s\n", ipToBlock)
	return true
}

// This will be called with mutex
func AddMapUpdateToQueue(updateOp MapUpdateOp) {
	gMapUpdateQueue = append(gMapUpdateQueue, updateOp)
}

func RemoveOldMapUpdatesFromQueue(ip uint32) {
	for i, op := range gMapUpdateQueue {
		if op.IP == ip {
			// Remove old update
			sliceLen := len(gMapUpdateQueue)
			if i != sliceLen-1 {
				gMapUpdateQueue[i] = gMapUpdateQueue[sliceLen-1]
			}
			gMapUpdateQueue = gMapUpdateQueue[:sliceLen-1]
		}
	}
}

func ProcessMapQueueUpdates(mu *sync.Mutex) {
	for {
		time.Sleep(100 * time.Millisecond)

		mu.Lock()
		if len(gMapUpdateQueue) == 0 {
			mu.Unlock()
			continue
		}

		for _, op := range gMapUpdateQueue {
			switch op.OpType {
			case MapAdd:
				BlockIpAddress(op.IP)
			case MapRemove:
				UnblockedIpAddress(op.IP)
			}
		}
		gMapUpdateQueue = gMapUpdateQueue[:0]
		mu.Unlock()
	}
}

func stopOnError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}
