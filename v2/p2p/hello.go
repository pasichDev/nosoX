package p2p

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/pasichDev/noso-go/v2/types"
)

// ProtocolHello is the libp2p protocol ID for the application-level
// status handshake. A fresh node uses it on every new peer connection
// to discover whether the peer is ahead and a cold-sync should start.
const ProtocolHello protocol.ID = "/noso/hello/2"

// Status is what the hello handshake exchanges.
type Status struct {
	Version      uint32
	NetworkMagic uint32
	Height       uint64
	TipHash      types.Hash
}

func (n *Libp2pNode) installHelloHandler() {
	n.host.SetStreamHandler(ProtocolHello, func(s network.Stream) {
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(10 * time.Second))
		// We don't care what the peer sends; respond with our own status.
		_ = writeFrame(s, encodeStatus(n.localStatus()))
	})

	// On every successful peer connect, query their status and start
	// cold-sync if we're behind.
	n.host.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, conn network.Conn) {
			pid := conn.RemotePeer()
			n.launch(func() { n.helloAndCatchUp(pid) })
		},
	})
}

// helloAndCatchUp opens a hello stream to pid, reads their Status,
// kicks cold-sync if we're behind.
func (n *Libp2pNode) helloAndCatchUp(pid peer.ID) {
	ctx, cancel := context.WithTimeout(n.ctx, 15*time.Second)
	defer cancel()
	s, err := n.host.NewStream(ctx, pid, ProtocolHello)
	if err != nil {
		return
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	// Send our status (optional; the peer's handler ignores the body).
	if err := writeFrame(s, encodeStatus(n.localStatus())); err != nil {
		return
	}
	// Read peer's status.
	raw, err := readFrame(s, 1024)
	if err != nil {
		return
	}
	st, err := decodeStatus(raw)
	if err != nil {
		return
	}
	if st.NetworkMagic != n.magic || st.Version != types.BlockVersion {
		return // wrong network — silently drop
	}
	if st.Height > 0 {
		n.kickColdSync(pid, st.Height)
	}
}

func (n *Libp2pNode) localStatus() Status {
	tip, _ := n.chain.Tip()
	return Status{
		Version:      types.BlockVersion,
		NetworkMagic: n.magic,
		Height:       tip.Height,
		TipHash:      types.HeaderID(&tip),
	}
}

func encodeStatus(st Status) []byte {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(st)
	return buf.Bytes()
}

func decodeStatus(raw []byte) (Status, error) {
	var st Status
	err := decodeWire(raw, &st, 1024)
	return st, err
}

// writeFrame prepends a 4-byte big-endian length to body.
func writeFrame(w io.Writer, body []byte) error {
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(body)))
	if _, err := w.Write(lp[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// readFrame reads a length-prefixed payload bounded by maxLen bytes.
func readFrame(r io.Reader, maxLen uint32) ([]byte, error) {
	var lp [4]byte
	if _, err := io.ReadFull(r, lp[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lp[:])
	if n > maxLen {
		return nil, io.ErrShortBuffer
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}
