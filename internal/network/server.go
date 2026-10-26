// Package network implements the legacy line-based TCP server used by the
// NosoDart client (and by extension the NosoSova Flutter wallet). Every
// supported command corresponds to a request the live NosoDart code is
// known to send:
//
//	NODESTATUS\n          -> space-separated node status
//	NSLMNS\n              -> seed list dump
//	NSLPENDFULL\n         -> pending pool dump (CSV per entry)
//	GETZIPSUMARY\n        -> binary ZIP of sumary.psk
//	NSLCFG\n              -> nosocfg.psk contents
//	NSLGVT\n              -> binary GVT file
//	NSLBALANCE <hash>\n   -> address balance, base units
//	NSLORDER ... \n       -> submit transfer order
//	NSLCUSTOM ... \n      -> submit custom (alias) order
//
// Full Pascal P2P interop (PSK headers, $PING/$PONG, $LASTBLOCK zip stream,
// $MNREPO/$MNCHECK etc.) is out of scope for this port — the Noso network
// is dead, there are no live peers to talk to. Only the client-facing
// commands NosoSova depends on are kept alive here.
package network

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// maxLineLen bounds a single request line; Pascal allowed MaxInt which is
// a DoS vector. 8 KiB is far more than the longest valid command (an
// NSLORDER batch is well under that).
const maxLineLen = 8 * 1024

// Handler dispatches a parsed command. Implementations are stateless w.r.t.
// the connection and may share state (summary store, mempool, etc.) via
// the closure environment.
type Handler interface {
	HandleCommand(ctx context.Context, w *bufio.Writer, cmd string, args []string) error
}

// HandlerFunc adapts a function value to the Handler interface.
type HandlerFunc func(ctx context.Context, w *bufio.Writer, cmd string, args []string) error

// HandleCommand implements Handler.
func (f HandlerFunc) HandleCommand(ctx context.Context, w *bufio.Writer, cmd string, args []string) error {
	return f(ctx, w, cmd, args)
}

// Server is the TCP server lifecycle wrapper. Create with NewServer,
// register handlers, call Start, then Shutdown.
type Server struct {
	addr     string
	handlers map[string]Handler
	mu       sync.RWMutex
	listener net.Listener
	wg       sync.WaitGroup
	logger   *log.Logger
	active   map[net.Conn]struct{}
	stopping bool
	slots    chan struct{}

	// timeouts protect against slow clients and dead connections.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// NewServer returns a server that listens on addr (host:port).
func NewServer(addr string, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		addr:         addr,
		handlers:     make(map[string]Handler),
		active:       make(map[net.Conn]struct{}),
		slots:        make(chan struct{}, 128),
		logger:       logger,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Handle registers handler for the given command. Command names are
// uppercased internally so the lookup is case-insensitive — NosoDart sends
// uppercase, but we don't want to depend on that.
func (s *Server) Handle(cmd string, h Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[strings.ToUpper(cmd)] = h
}

// HandleFunc is the convenience wrapper for function-valued handlers.
func (s *Server) HandleFunc(cmd string, f HandlerFunc) { s.Handle(cmd, f) }

// Start begins accepting connections. It returns once the listener is up;
// connections are served on background goroutines bounded by the server's
// internal WaitGroup. Use Shutdown to stop.
func (s *Server) Start(ctx context.Context) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.wg.Add(1)
	go s.acceptLoop(ctx)
	return nil
}

func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.logger.Printf("network: accept error: %v", err)
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			<-s.slots
			_ = conn.Close()
			continue
		}
		s.active[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer func() { <-s.slots; s.mu.Lock(); delete(s.active, conn); s.mu.Unlock() }()
			defer s.wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stop := context.AfterFunc(connCtx, func() { _ = conn.Close() })
	defer stop()
	r := bufio.NewReaderSize(conn, maxLineLen+1)
	w := bufio.NewWriter(conn)
	for {
		readTimeout := s.IdleTimeout
		if s.ReadTimeout > 0 && (readTimeout <= 0 || s.ReadTimeout < readTimeout) {
			readTimeout = s.ReadTimeout
		}
		if readTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		}
		raw, err := r.ReadSlice('\n')
		line := string(raw)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Printf("network: read from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}
		if len(line) > maxLineLen {
			s.logger.Printf("network: oversized line from %s (%d B), closing", conn.RemoteAddr(), len(line))
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		cmd := strings.ToUpper(fields[0])
		args := fields[1:]
		s.mu.RLock()
		h, ok := s.handlers[cmd]
		s.mu.RUnlock()
		if s.WriteTimeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}
		if !ok {
			_, _ = fmt.Fprintf(w, "ERROR unknown command %s\n", cmd)
			_ = w.Flush()
			continue
		}
		if err := h.HandleCommand(connCtx, w, cmd, args); err != nil {
			s.logger.Printf("network: handler %s error: %v", cmd, err)
			_, _ = fmt.Fprintf(w, "ERROR %v\n", err)
		}
		if err := w.Flush(); err != nil {
			return
		}
	}
}

// Shutdown stops accepting new connections and waits for in-flight ones to
// finish.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.mu.Lock()
	s.stopping = true
	for conn := range s.active {
		_ = conn.Close()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Addr returns the actual listen address (useful when tests use :0).
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr
}
