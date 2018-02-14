package yggdrasil

// This sends packets to peers using SCTP as a transport

// TODO:
//  Something needs to make sure we're getting *valid* packets
//  Could be used to DoS (connect, give someone else's keys, spew garbage)
//  I guess the "peer" part should watch for link packets, disconnect?

// FIXME timeouts don't work
//  Issue with the sctp implementation / go language
//    See: https://github.com/golang/go/issues/22191
//  Keep starting/canceling a timer instead
//  Close the connection if a timer ever fires
//  Bad in general, but good enough for this use case

import "net"
import "time"
import "errors"
import "sync"
import "fmt"

import "github.com/Arceliar/sctp"

const sctp_msgSize = 2048 + 65535 // TODO figure out what makes sense

type sctpInterface struct {
	core  *Core
	serv  *sctp.SCTPListener
	mutex sync.Mutex // Protecting the below
	calls map[string]struct{}
}

type sctpKeys struct {
	box boxPubKey
	sig sigPubKey
}

func (iface *sctpInterface) init(core *Core, addr string) {
	iface.core = core
	sctpAddr, err := sctp.ResolveSCTPAddr("sctp", addr)
	if err != nil {
		panic(err)
	}
	iface.serv, err = sctp.ListenSCTP("sctp", sctpAddr)
	if err != nil {
		panic(err)
	}
	iface.calls = make(map[string]struct{})
	go iface.listener()
}

func (iface *sctpInterface) listener() {
	defer iface.serv.Close()
	iface.core.log.Println("Listening on:", iface.serv.Addr().String())
	for {
		sock, err := iface.serv.Accept()
		if err != nil {
			panic(err)
		}
		go iface.handler(sock.(*sctp.SCTPConn))
	}
}

func (iface *sctpInterface) call(saddr string) {
	sctpAddr, err := sctp.ResolveSCTPAddr("sctp", saddr)
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}
	go func() {
		quit := false
		iface.mutex.Lock()
		if _, isIn := iface.calls[saddr]; isIn {
			quit = true
		} else {
			iface.calls[saddr] = struct{}{}
			defer func() {
				iface.mutex.Lock()
				delete(iface.calls, saddr)
				iface.mutex.Unlock()
			}()
		}
		iface.mutex.Unlock()
		if !quit {
			sock, err := sctp.DialSCTP("sctp", nil, sctpAddr)
			if err != nil {
				return
			}
			iface.handler(sock)
		}
	}()
}

func (iface *sctpInterface) handler(sock *sctp.SCTPConn) {
	defer sock.Close()
	// Get our keys
	keys := []byte{}
	keys = append(keys, sctp_key[:]...)
	keys = append(keys, iface.core.boxPub[:]...)
	keys = append(keys, iface.core.sigPub[:]...)
	_, err := sock.Write(keys)
	if err != nil {
		return
	}
	timeout := time.Now().Add(6 * time.Second)
	sock.SetReadDeadline(timeout)
	n, err := sock.Read(keys)
	if err != nil {
		return
	}
	if n < len(keys) { /*panic("Partial key packet?") ;*/
		return
	}
	ks := sctpKeys{}
	if !sctp_chop_keys(&ks.box, &ks.sig, &keys) { /*panic("Invalid key packet?") ;*/
		return
	}
	// Quit the parent call if this is a connection to ourself
	equiv := func(k1, k2 []byte) bool {
		for idx := range k1 {
			if k1[idx] != k2[idx] {
				return false
			}
		}
		return true
	}
	if equiv(ks.box[:], iface.core.boxPub[:]) {
		return
	} // testing
	if equiv(ks.sig[:], iface.core.sigPub[:]) {
		return
	}
	// Note that multiple connections to the same node are allowed
	//  E.g. over different interfaces
	linkIn := make(chan []byte, 1)
	p := iface.core.peers.newPeer(&ks.box, &ks.sig) //, in, out)
	in := func(bs []byte) {
		p.handlePacket(bs, linkIn)
	}
	out := make(chan []byte, 32) // TODO? what size makes sense
	defer close(out)
	go func() {
		for msg := range out {
			start := time.Now()
			size, _ := sock.Write(msg)
			timed := time.Since(start)
			util_putBytes(msg)
			p.updateBandwidth(size, timed)
		}
	}()
	p.out = func(msg []byte) {
		defer func() { recover() }()
		select {
		case out <- msg:
		default:
			util_putBytes(msg)
		}
	}
	go p.linkLoop(linkIn)
	defer func() {
		// Put all of our cleanup here...
		p.core.peers.mutex.Lock()
		oldPorts := p.core.peers.getPorts()
		newPorts := make(map[switchPort]*peer)
		for k, v := range oldPorts {
			newPorts[k] = v
		}
		delete(newPorts, p.port)
		p.core.peers.putPorts(newPorts)
		p.core.peers.mutex.Unlock()
		close(linkIn)
	}()
	them := sock.RemoteAddr()
	themNodeID := getNodeID(&ks.box)
	themAddr := address_addrForNodeID(themNodeID)
	themAddrString := net.IP(themAddr[:]).String()
	themString := fmt.Sprintf("%s@%s", themAddrString, them)
	iface.core.log.Println("Connected:", themString)
	iface.reader(sock, in) // In this goroutine, because of defers
	iface.core.log.Println("Disconnected:", themString)
	return
}

func (iface *sctpInterface) reader(sock *sctp.SCTPConn, in func([]byte)) {
	bs := make([]byte, 2*sctp_msgSize)
	for {
		timeout := time.Now().Add(6 * time.Second)
		sock.SetReadDeadline(timeout)
		n, err := sock.Read(bs)
		if err != nil || n == 0 {
			break
		}
		if n > sctp_msgSize {
			continue
		}
		msg := append(util_getBytes(), bs[:n]...)
		in(msg)
	}
}

////////////////////////////////////////////////////////////////////////////////

// Magic bytes to check
var sctp_key = [...]byte{'k', 'e', 'y', 's'}
var sctp_msg = [...]byte{0xde, 0xad, 0xb1, 0x75} // "dead bits"

func sctp_chop_keys(box *boxPubKey, sig *sigPubKey, bs *[]byte) bool {
	// This one is pretty simple: we know how long the message should be
	// So don't call this with a message that's too short
	if len(*bs) < len(sctp_key)+len(*box)+len(*sig) {
		return false
	}
	for idx := range sctp_key {
		if (*bs)[idx] != sctp_key[idx] {
			return false
		}
	}
	(*bs) = (*bs)[len(sctp_key):]
	copy(box[:], *bs)
	(*bs) = (*bs)[len(box):]
	copy(sig[:], *bs)
	(*bs) = (*bs)[len(sig):]
	return true
}

func sctp_chop_msg(bs *[]byte) ([]byte, bool, error) {
	// Returns msg, ok, err
	if len(*bs) < len(sctp_msg) {
		return nil, false, nil
	}
	for idx := range sctp_msg {
		if (*bs)[idx] != sctp_msg[idx] {
			return nil, false, errors.New("Bad message!")
		}
	}
	msgLen, msgLenLen := wire_decode_uint64((*bs)[len(sctp_msg):])
	if msgLen > sctp_msgSize {
		return nil, false, errors.New("Oversized message!")
	}
	msgBegin := len(sctp_msg) + msgLenLen
	msgEnd := msgBegin + int(msgLen)
	if msgLenLen == 0 || len(*bs) < msgEnd {
		// We don't have the full message
		// Need to buffer this and wait for the rest to come in
		return nil, false, nil
	}
	msg := (*bs)[msgBegin:msgEnd]
	(*bs) = (*bs)[msgEnd:]
	return msg, true, nil
}
