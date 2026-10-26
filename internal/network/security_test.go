package network

import (
	"bufio"
	"bytes"
	"context"
	"github.com/pasichDev/noso-go/internal/blockchain"
	"github.com/pasichDev/noso-go/internal/crypto"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWhitespaceLineDoesNotPanic(t *testing.T) {
	s := NewServer("", log.New(io.Discard, "", 0))
	a, b := net.Pipe()
	defer b.Close()
	done := make(chan any, 1)
	go func() { defer func() { done <- recover() }(); s.handleConn(context.Background(), a) }()
	_, _ = io.WriteString(b, " \t \r\n")
	_ = b.Close()
	if p := <-done; p != nil {
		t.Fatalf("remote whitespace panicked: %v", p)
	}
}

func TestOverlongUnterminatedLineCloses(t *testing.T) {
	s := NewServer("", log.New(io.Discard, "", 0))
	a, b := net.Pipe()
	defer b.Close()
	done := make(chan struct{})
	go func() { s.handleConn(context.Background(), a); close(done) }()
	go func() { _, _ = io.WriteString(b, strings.Repeat("x", maxLineLen+100)) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("overlong unterminated line kept connection open")
	}
}

func TestWhitespaceFollowedByCommand(t *testing.T) {
	s := NewServer("", log.New(io.Discard, "", 0))
	s.HandleFunc("PING", func(_ context.Context, w *bufio.Writer, _ string, _ []string) error {
		_, e := w.WriteString("pong\n")
		return e
	})
	a, b := net.Pipe()
	defer b.Close()
	go s.handleConn(context.Background(), a)
	go func() { _, _ = io.WriteString(b, " \t\nPING\n") }()
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(b).ReadString('\n')
	if err != nil || line != "pong\n" {
		t.Fatalf("got %q: %v", line, err)
	}
}

func TestSubmitRejectsUnownedAddress(t *testing.T) {
	kp, e := crypto.GenerateKeyPair()
	if e != nil {
		t.Fatal(e)
	}
	owner, _ := crypto.AddressFromPublicKey(kp.PublicKey, crypto.AddressTypeRegular)
	victimKey, _ := crypto.GenerateKeyPair()
	victim, _ := crypto.AddressFromPublicKey(victimKey.PublicKey, crypto.AddressTypeRegular)
	order, e := blockchain.NewTransferOrder(blockchain.Sender{Hash: owner, PublicKey: kp.PublicKey, PrivateKey: kp.PrivateKey}, victim, 1000000000, "hi", time.Now().Unix(), 60000)
	if e != nil {
		t.Fatal(e)
	}
	order.Address = victim
	msg := strconv.FormatInt(order.TimeStamp, 10) + order.Address + order.Receiver + strconv.FormatInt(order.AmmountTrf, 10) + strconv.FormatInt(order.AmmountFee, 10) + strconv.Itoa(int(order.TrxLine))
	order.Signature, e = crypto.SignString([]byte(msg), kp.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	fields := []string{order.OrderID, "1", order.OrderType, strconv.FormatInt(order.TimeStamp, 10), order.Reference, "1", order.Sender, order.Address, order.Receiver, strconv.FormatInt(order.AmmountFee, 10), strconv.FormatInt(order.AmmountTrf, 10), order.Signature, order.TrfrID}
	svc := &Service{Pending: NewPendingPool()}
	var out bytes.Buffer
	w := bufio.NewWriter(&out)
	if e = svc.handleSubmitOrder(context.Background(), w, "NSLORDER", fields); e != nil {
		t.Fatal(e)
	}
	_ = w.Flush()
	if svc.Pending.Len() != 0 {
		t.Fatalf("unowned victim address admitted: %s", out.String())
	}
}
