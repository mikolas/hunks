package gdb

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/mikolas/hunks/internal/amiga"
)

const (
	// DefaultAddr is Amiberry's default loopback GDB server address.
	DefaultAddr = "127.0.0.1:2345"

	// maxReadChunk is the maximum byte count requested per `m` packet.
	// Amiberry's Session::packet_size is 65536 (max 32768 raw bytes); 16 KiB stays well below it.
	maxReadChunk uint32 = 0x4000
)

// Registers holds the 18 Motorola 68000 registers returned by Amiberry's `g` packet.
type Registers struct {
	D  [8]uint32 `json:"d"`
	A  [8]uint32 `json:"a"`
	SR uint16    `json:"sr"`
	PC uint32    `json:"pc"`
}

// MemoryRegion describes a physical memory region reported by Amiberry's `monitor memory-map`.
type MemoryRegion struct {
	Address uint32 `json:"address"`
	Size    uint32 `json:"size"`
	Type    string `json:"type"` // "ram", "rom", "io"
	Chip    bool   `json:"chip"`
	Name    string `json:"name"`
}

// AmigaSegment describes a loaded AmigaDOS hunk reported by `monitor segments`.
type AmigaSegment struct {
	Index   int    `json:"index"`
	Address uint32 `json:"address"`
	Size    uint32 `json:"size"`
}

// ProcessSegments describes the active AmigaDOS process and its loaded hunks from `monitor segments`.
type ProcessSegments struct {
	Process  uint32         `json:"process"`
	Name     string         `json:"name"`
	Command  string         `json:"command"`
	Segments []AmigaSegment `json:"segments"`
}

// Client is a pure-Go GDB Remote Serial Protocol client tailored to Amiberry's GDB stub.
type Client struct {
	conn    net.Conn
	reader  *bufio.Reader
	timeout time.Duration
	noAck   bool
}

// NormalizeAddr normalizes a user-supplied GDB address string ("", "default", ":2345", "2345", or "host:port").
func NormalizeAddr(addr string) string {
	clean := strings.TrimSpace(addr)
	if clean == "" || strings.EqualFold(clean, "default") || clean == "true" {
		return DefaultAddr
	}
	if strings.HasPrefix(clean, ":") {
		return "127.0.0.1" + clean
	}
	if !strings.Contains(clean, ":") {
		return "127.0.0.1:" + clean
	}
	return clean
}

// Dial connects to Amiberry's GDB stub, negotiates QStartNoAckMode, and waits for the CPU to halt (`?` -> `S05`).
func Dial(addr string, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	norm := NormalizeAddr(addr)
	conn, err := net.DialTimeout("tcp", norm, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to Amiberry GDB server at %s: %w", norm, err)
	}
	c := &Client{
		conn:    conn,
		reader:  bufio.NewReaderSize(conn, 128*1024),
		timeout: timeout,
	}

	if reply, err := c.sendPacket("QStartNoAckMode"); err == nil && reply == "OK" {
		c.noAck = true
	}

	// Amiberry halts the CPU asynchronously at the next debugger boundary on connect.
	// Sending `?` sets `await_stop = true` in Amiberry and blocks until `S05` is returned.
	stopReply, err := c.sendPacket("?")
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed waiting for Amiberry CPU halt (is Amiberry paused in UI?): %w", err)
	}
	if strings.HasPrefix(stopReply, "E") {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected error halting Amiberry CPU: %s", stopReply)
	}
	return c, nil
}

// Detach sends `D` so Amiberry cleans up temporary breakpoints/watches and resumes execution, then closes the socket.
func (c *Client) Detach() error {
	if c == nil || c.conn == nil {
		return nil
	}
	_, _ = c.sendPacket("D")
	err := c.conn.Close()
	c.conn = nil
	return err
}

// Close closes the underlying socket connection without sending `D` if already detached.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func packetChecksum(payload string) byte {
	var sum byte
	for i := 0; i < len(payload); i++ {
		sum += payload[i]
	}
	return sum
}

func (c *Client) sendPacket(payload string) (string, error) {
	return c.sendPacketWithTimeout(payload, c.timeout)
}

func (c *Client) sendPacketWithTimeout(payload string, timeout time.Duration) (string, error) {
	if c.conn == nil {
		return "", fmt.Errorf("GDB connection is closed")
	}
	_ = c.conn.SetDeadline(time.Now().Add(timeout))
	sum := packetChecksum(payload)
	wire := fmt.Sprintf("$%s#%02x", payload, sum)
	if _, err := io.WriteString(c.conn, wire); err != nil {
		return "", err
	}

	if !c.noAck {
		for {
			b, err := c.reader.ReadByte()
			if err != nil {
				return "", err
			}
			if b == '+' {
				break
			}
			if b == '-' {
				if _, err := io.WriteString(c.conn, wire); err != nil {
					return "", err
				}
			} else if b == '$' {
				_ = c.reader.UnreadByte()
				break
			}
		}
	}

	return c.readReplyFrame()
}

func (c *Client) readReplyFrame() (string, error) {
	for {
		b, err := c.reader.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '$' {
			break
		}
	}
	body, err := c.reader.ReadString('#')
	if err != nil {
		return "", err
	}
	payload := body[:len(body)-1]
	var chk [2]byte
	if _, err := io.ReadFull(c.reader, chk[:]); err != nil {
		return "", err
	}
	wantBytes, err := hex.DecodeString(string(chk[:]))
	if err != nil || len(wantBytes) != 1 || wantBytes[0] != packetChecksum(payload) {
		if !c.noAck {
			_, _ = io.WriteString(c.conn, "-")
		}
		return "", fmt.Errorf("GDB packet checksum mismatch on reply %q", payload)
	}
	if !c.noAck {
		_, _ = io.WriteString(c.conn, "+")
	}
	return payload, nil
}

// ReadRegisters fetches the 18 big-endian 32-bit registers (D0-D7, A0-A7, SR, PC) via `g`.
func (c *Client) ReadRegisters() (Registers, error) {
	reply, err := c.sendPacket("g")
	if err != nil {
		return Registers{}, err
	}
	if strings.HasPrefix(reply, "E") {
		return Registers{}, fmt.Errorf("GDB read registers failed: %s", reply)
	}
	if len(reply) < 18*8 {
		return Registers{}, fmt.Errorf("short GDB register reply (%d hex chars, want >= 144)", len(reply))
	}
	raw, err := hex.DecodeString(reply[:18*8])
	if err != nil {
		return Registers{}, fmt.Errorf("invalid hex in GDB register reply: %w", err)
	}
	var regs Registers
	for i := 0; i < 8; i++ {
		regs.D[i] = binary.BigEndian.Uint32(raw[i*4 : (i+1)*4])
	}
	for i := 0; i < 8; i++ {
		regs.A[i] = binary.BigEndian.Uint32(raw[(8+i)*4 : (9+i)*4])
	}
	regs.SR = uint16(binary.BigEndian.Uint32(raw[16*4 : 17*4]))
	regs.PC = binary.BigEndian.Uint32(raw[17*4 : 18*4])
	return regs, nil
}

// ReadMemory reads `length` bytes starting at physical `addr` in 16 KiB `m` chunks.
func (c *Client) ReadMemory(addr, length uint32) ([]byte, error) {
	out := make([]byte, 0, length)
	cur := addr
	rem := length
	for rem > 0 {
		chunk := min(rem, maxReadChunk)
		cmd := fmt.Sprintf("m%x,%x", cur, chunk)
		reply, err := c.sendPacket(cmd)
		if err != nil {
			return nil, fmt.Errorf("read memory at 0x%X (len 0x%X): %w", cur, chunk, err)
		}
		if strings.HasPrefix(reply, "E") {
			return nil, fmt.Errorf("Amiberry rejected memory read at 0x%X (len 0x%X): %s", cur, chunk, reply)
		}
		decoded, err := hex.DecodeString(reply)
		if err != nil {
			return nil, fmt.Errorf("decode memory reply at 0x%X: %w", cur, err)
		}
		if uint32(len(decoded)) != chunk {
			return nil, fmt.Errorf("short memory read at 0x%X: got %d bytes, want %d", cur, len(decoded), chunk)
		}
		out = append(out, decoded...)
		cur += chunk
		rem -= chunk
	}
	return out, nil
}

// ReadCustomSnapshot reads Amiberry's 512-byte saved custom chip register snapshot ($DFF000..$DFF1FF).
func (c *Client) ReadCustomSnapshot() (amiga.CustomSnapshot, error) {
	var snap amiga.CustomSnapshot
	raw, err := c.ReadMemory(amiga.CustomBase, amiga.CustomSnapshotLen)
	if err != nil {
		return snap, err
	}
	copy(snap[:], raw)
	return snap, nil
}

// Monitor sends an Amiberry `qRcmd` monitor command and returns the decoded text/JSON response.
func (c *Client) Monitor(command string) (string, error) {
	hexCmd := hex.EncodeToString([]byte(command))
	reply, err := c.sendPacket("qRcmd," + hexCmd)
	if err != nil {
		return "", err
	}
	if reply == "" {
		return "", fmt.Errorf("monitor command %q unsupported by target", command)
	}
	if strings.HasPrefix(reply, "E") {
		return "", fmt.Errorf("monitor command %q failed: %s", command, reply)
	}
	if reply == "OK" {
		return "", nil
	}
	decoded, err := hex.DecodeString(reply)
	if err != nil {
		return "", fmt.Errorf("invalid hex in monitor reply for %q: %w", command, err)
	}
	return string(decoded), nil
}

// MemoryMap queries `monitor memory-map` (with `qXfer:memory-map:read` XML fallback)
// and returns all physical memory regions reported by Amiberry.
func (c *Client) MemoryMap() ([]MemoryRegion, error) {
	if jsonText, err := c.Monitor("memory-map"); err == nil && jsonText != "" {
		var wrapper struct {
			Addressing string         `json:"addressing"`
			Truncated  bool           `json:"truncated"`
			Regions    []MemoryRegion `json:"regions"`
		}
		if err := json.Unmarshal([]byte(jsonText), &wrapper); err == nil && len(wrapper.Regions) > 0 {
			return wrapper.Regions, nil
		}
	}

	// Fallback to standard GDB qXfer:memory-map:read::0,fff XML
	reply, err := c.sendPacket("qXfer:memory-map:read::0,7fff")
	if err != nil || len(reply) < 2 || strings.HasPrefix(reply, "E") {
		return nil, fmt.Errorf("failed to query Amiberry memory map")
	}
	xmlPayload := reply[1:]
	var xmlMap struct {
		Memories []struct {
			Type   string `xml:"type,attr"`
			Start  uint32 `xml:"start,attr"`
			Length uint32 `xml:"length,attr"`
		} `xml:"memory"`
	}
	if err := xml.Unmarshal([]byte(xmlPayload), &xmlMap); err != nil {
		return nil, fmt.Errorf("failed to parse memory-map XML: %w", err)
	}
	regions := make([]MemoryRegion, 0, len(xmlMap.Memories))
	for _, m := range xmlMap.Memories {
		isChip := m.Type == "ram" && m.Start == 0
		name := m.Type
		if isChip {
			name = "Chip memory"
		}
		regions = append(regions, MemoryRegion{
			Address: m.Start,
			Size:    m.Length,
			Type:    m.Type,
			Chip:    isChip,
			Name:    name,
		})
	}
	return regions, nil
}

// Segments queries `monitor segments` to inspect the active AmigaDOS process's loaded hunks.
// Returns (nil, nil) if no AmigaDOS process is active (e.g. non-DOS trackloader game).
func (c *Client) Segments() (*ProcessSegments, error) {
	jsonText, err := c.Monitor("segments")
	if err != nil || jsonText == "" {
		return nil, nil
	}
	var proc ProcessSegments
	if err := json.Unmarshal([]byte(jsonText), &proc); err != nil {
		return nil, err
	}
	return &proc, nil
}

// WaitProcessBreak arms a one-shot stop at the entry of AmigaDOS process `procName`,
// resumes emulation (`c`), and blocks until Amiberry stops at the process entry.
func (c *Client) WaitProcessBreak(procName string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if _, err := c.Monitor("process-break name " + procName); err != nil {
		return fmt.Errorf("arm process-break for %q: %w", procName, err)
	}
	stopReply, err := c.sendPacketWithTimeout("c", timeout)
	if err != nil {
		// Attempt to re-halt the target and clear the armed process-break before returning.
		_ = c.conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.conn.Write([]byte{0x03})
		_, _ = c.readReplyFrame()
		_, _ = c.Monitor("process-break clear")
		return fmt.Errorf("waiting for process %q to start: %w", procName, err)
	}
	if !strings.HasPrefix(stopReply, "S") && !strings.HasPrefix(stopReply, "T") {
		return fmt.Errorf("unexpected stop reply waiting for process %q: %s", procName, stopReply)
	}
	return nil
}
