package p2p

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/pasichDev/noso-go/v2/types"
)

// ProtocolHello is the libp2p protocol ID for the application-level status
// handshake. Both sides send their Status (including cumulative work) and each
// learns the other's. v6 uses the binary framing of wire.go.
const ProtocolHello protocol.ID = "/NosoX/hello/v6"

func (n *Libp2pNode) installHelloHandler() {
	n.host.SetStreamHandler(ProtocolHello, func(s network.Stream) {
		// Joined by Shutdown like every other task, so the handler cannot touch the
		// chain after the node has been told to stop.
		if !n.launch(func() { n.handleHello(s) }) {
			_ = s.Reset()
		}
	})
	// On every successful connection, exchange status.
	n.host.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, conn network.Conn) {
			pid := conn.RemotePeer()
			n.launch(func() { n.queryStatus(pid) })
		},
	})
}

func (n *Libp2pNode) handleHello(s network.Stream) {
	{
		defer s.Close()
		pid := s.Conn().RemotePeer()
		_ = s.SetDeadline(time.Now().Add(10 * time.Second))
		if n.book.isBanned(pid) || !n.hello.allow(pid) {
			_ = s.Reset()
			return
		}
		raw, err := readFrame(s, maxStatusBytes)
		if err != nil {
			return
		}
		st, err := decodeStatus(raw)
		if err != nil {
			n.penalize(pid, penaltyGarbage, "malformed hello")
			return
		}
		_ = writeFrame(s, encodeStatus(n.localStatus()))
		n.acceptStatus(pid, st)
	}
}

// queryStatus opens a hello stream to pid, sends our status, reads theirs and
// wakes the sync loop.
func (n *Libp2pNode) queryStatus(pid peer.ID) {
	ctx, cancel := context.WithTimeout(n.ctx, 15*time.Second)
	defer cancel()
	s, err := n.host.NewStream(ctx, pid, ProtocolHello)
	if err != nil {
		return
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	if err := writeFrame(s, encodeStatus(n.localStatus())); err != nil {
		return
	}
	raw, err := readFrame(s, maxStatusBytes)
	if err != nil {
		return
	}
	st, err := decodeStatus(raw)
	if err != nil {
		n.penalize(pid, penaltyGarbage, "malformed hello")
		return
	}
	n.acceptStatus(pid, st)
}

// acceptStatus records a peer's advertised chain state. A peer on another
// network or protocol version is disconnected and banned for a while.
func (n *Libp2pNode) acceptStatus(pid peer.ID, st Status) {
	if st.NetworkMagic != n.magic || st.Version != types.BlockVersion {
		n.penalize(pid, penaltyInvalid, "wrong network or version")
		return
	}
	n.book.mu.Lock()
	ps := n.book.get(pid)
	ps.status, ps.haveStatus, ps.statusAt = st, true, time.Now()
	n.book.mu.Unlock()
	n.remember(pid)
	n.kickSync()
}

func (n *Libp2pNode) localStatus() Status {
	tip, _ := n.chain.Tip()
	return Status{
		Version:      types.BlockVersion,
		NetworkMagic: n.magic,
		Height:       tip.Height,
		TipHash:      types.HeaderID(&tip),
		TotalWork:    n.chain.TotalWork(),
	}
}
