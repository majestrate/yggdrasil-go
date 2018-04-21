package i2p

import (
	"net"
)

// i2p network session
type Session interface {

	// get session name
	Name() string
	// open a new control socket
	// does handshaske
	OpenControlSocket() (net.Conn, error)

	// get printable b32.i2p address
	B32Addr() string

	// implements network.Network
	LocalAddr() net.Addr

	PacketConn() net.PacketConn

	// implements network.Session
	Lookup(name, port string) (net.Addr, error)

	// lookup an i2p address
	LookupI2P(name string) (I2PAddr, error)

	// open the session, generate keys, start up destination etc
	Open() error

	// close the session
	Close() error
}

// create a new i2p session

func NewSession(name, addr, keyfile string, opts map[string]string) Session {
	return &samSession{
		style:      "DATAGRAM",
		name:       name,
		addr:       addr,
		minversion: "3.0",
		maxversion: "3.0",
		keys:       NewKeyfile(keyfile),
		opts:       opts,
		lookup:     make(chan *lookupReq, 18),
	}
}
