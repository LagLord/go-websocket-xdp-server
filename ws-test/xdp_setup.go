package main

import (
	"C"

	bpf "github.com/aquasecurity/libbpfgo"
)
import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
)

func setupXdp() {
	deviceName := "eth0" // "loopback0"

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, iface := range interfaces {
		fmt.Println(iface.Name) // Prints all valid device names
	}

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

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	stopOnError(err)

	rb.Poll(300)
	numberOfEventsReceived := 0

recvLoop:

	for {
		b := <-eventsChannel
		fmt.Printf("Received %v", binary.LittleEndian.Uint32(b))
		numberOfEventsReceived++
		if numberOfEventsReceived > 5 {
			break recvLoop
		}
	}

	rb.Stop()
	rb.Close()

	<-sig
	// Dont need to detach it as the new AttachXDP uses bpf_link and will detach automatically
	// err = xdpProg.DetachXDPLegacy(deviceName, bpf.XDPFlagsReplace)
	// stopOnError(err)
	fmt.Println("Cleaning up")
}

func stopOnError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}
