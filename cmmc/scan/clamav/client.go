// Package clamav speaks the clamd INSTREAM protocol. One short-lived
// TCP (or Unix-socket) connection per Scan call; no connection
// pooling — the expected throughput for a small/midsize CUI cabinet
// is single-digit uploads per second, well under what a sequential
// dial-per-scan can handle, and it sidesteps stale-connection bugs
// reported against pooled go-clamd libraries.
//
// Protocol reference: clamd(8) §INSTREAM.
//   > INSTREAM chunked scan of the stream that follows.
//   > Each chunk is the size (uint32 big-endian) followed by the data.
//   > A zero-length chunk marks end-of-stream.
//
// Reply format:
//   "stream: OK\0"
//   "stream: <sig> FOUND\0"
//   "stream: <detail> ERROR\0"
package clamav

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/filebrowser/filebrowser/v2/cmmc/scan"
)

func init() {
	scan.RegisterBackend("clamav", factoryFromEnv)
}

// factoryFromEnv is the scan.RegisterBackend callback. Reads
// FB_CMMC_AV_ADDR (e.g., "tcp://localhost:3310",
// "unix:///var/run/clamav/clamd.sock") and returns a ready Scanner.
func factoryFromEnv() (scan.Scanner, error) {
	addr := strings.TrimSpace(os.Getenv("FB_CMMC_AV_ADDR"))
	if addr == "" {
		return nil, fmt.Errorf("clamav: FB_CMMC_AV_ADDR not set")
	}
	return New(addr, scan.DefaultTimeout)
}

// Client is a clamd INSTREAM client. Safe for concurrent use —
// every Scan dials a fresh connection.
type Client struct {
	network string // "tcp" or "unix"
	address string // "host:port" or "/path/to/socket"
	timeout time.Duration
}

// New parses a clamd address URI and returns a Client. Supported
// schemes: tcp://, unix://. The caller's Context still bounds each
// Scan call; `timeout` is a ceiling for slow clamd on big payloads.
func New(addrURI string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(addrURI)
	if err != nil {
		return nil, fmt.Errorf("clamav: parse addr %q: %w", addrURI, err)
	}
	c := &Client{timeout: timeout}
	switch u.Scheme {
	case "tcp":
		c.network = "tcp"
		c.address = u.Host
	case "unix":
		c.network = "unix"
		// url.Path starts with `/` for absolute paths which is what
		// we want for unix sockets.
		c.address = u.Path
	default:
		return nil, fmt.Errorf("clamav: unsupported scheme %q (need tcp:// or unix://)", u.Scheme)
	}
	if c.address == "" {
		return nil, fmt.Errorf("clamav: empty address in %q", addrURI)
	}
	return c, nil
}

// chunkSize is clamd's recommended max chunk in INSTREAM. 64 KiB is
// well under StreamMaxLength (default 25 MB in clamd) and matches
// what the libraries most commonly used in production (go-clamd,
// clamav-client) send. Bigger chunks do not speed up scanning —
// clamd processes each chunk serially anyway.
const chunkSize = 64 * 1024

// Scan streams `r` through clamd and reports the verdict. Context
// cancellation closes the connection and returns ctx.Err().
// Errors from the wire or protocol decode are wrapped in
// scan.ErrUnavailable so the caller's Mode gate can distinguish
// "file is clean/infected" from "backend broken."
func (c *Client) Scan(ctx context.Context, r io.Reader) (scan.Result, error) {
	dialer := &net.Dialer{Timeout: c.timeout}
	conn, err := dialer.DialContext(ctx, c.network, c.address)
	if err != nil {
		return scan.Result{}, fmt.Errorf("%w: dial: %v", scan.ErrUnavailable, err)
	}
	defer conn.Close()

	// Propagate deadline to the connection so a hung clamd doesn't
	// wedge us past the caller's request timeout.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(c.timeout))
	}

	// Close the connection if Context cancels mid-scan.
	ctxDone := ctx.Done()
	if ctxDone != nil {
		go func() {
			<-ctxDone
			_ = conn.Close()
		}()
	}

	// Send the command. The leading 'z' is the null-terminated
	// variant; we use it consistently so responses are also
	// null-terminated and bufio.ReadString('\x00') works cleanly.
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return scan.Result{}, fmt.Errorf("%w: write cmd: %v", scan.ErrUnavailable, err)
	}

	// Stream chunks.
	buf := make([]byte, chunkSize)
	for {
		n, readErr := io.ReadFull(r, buf)
		if n > 0 {
			// 4-byte big-endian length prefix.
			if err := binary.Write(conn, binary.BigEndian, uint32(n)); err != nil {
				return scan.Result{}, fmt.Errorf("%w: write chunk len: %v", scan.ErrUnavailable, err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return scan.Result{}, fmt.Errorf("%w: write chunk: %v", scan.ErrUnavailable, err)
			}
		}
		if readErr != nil {
			// io.ReadFull returns io.EOF on a completely empty read
			// and io.ErrUnexpectedEOF when it got a partial chunk.
			// Both mean "we've sent everything."
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
				break
			}
			return scan.Result{}, fmt.Errorf("%w: read source: %v", scan.ErrUnavailable, readErr)
		}
	}

	// Terminating zero-length chunk.
	if err := binary.Write(conn, binary.BigEndian, uint32(0)); err != nil {
		return scan.Result{}, fmt.Errorf("%w: write terminator: %v", scan.ErrUnavailable, err)
	}

	// Read the null-terminated reply.
	reader := bufio.NewReader(conn)
	reply, err := reader.ReadString(0x00)
	if err != nil {
		return scan.Result{}, fmt.Errorf("%w: read reply: %v", scan.ErrUnavailable, err)
	}
	return parseReply(strings.TrimRight(reply, "\x00"))
}

// parseReply handles the three clamd verdicts. Exposed for tests.
func parseReply(reply string) (scan.Result, error) {
	// "stream: OK" → clean
	// "stream: <sig> FOUND" → infected
	// "stream: <msg> ERROR" → backend error
	if reply == "stream: OK" {
		return scan.Result{Clean: true}, nil
	}
	if strings.HasSuffix(reply, " FOUND") {
		inner := strings.TrimPrefix(reply, "stream: ")
		sig := strings.TrimSuffix(inner, " FOUND")
		return scan.Result{Clean: false, Signature: sig}, nil
	}
	if strings.HasSuffix(reply, " ERROR") {
		return scan.Result{}, fmt.Errorf("%w: clamd: %s", scan.ErrUnavailable, reply)
	}
	return scan.Result{}, fmt.Errorf("%w: unknown reply: %q", scan.ErrUnavailable, reply)
}
