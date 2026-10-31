package gdb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type mockAmiberryServer struct {
	ln       net.Listener
	regs     Registers
	chipRAM  []byte
	slowRAM  []byte
	custom   [512]byte
	detached bool
}

func startMockAmiberry(t *testing.T) *mockAmiberryServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &mockAmiberryServer{
		ln:      ln,
		chipRAM: make([]byte, 0x8000), // 32 KiB (2 chunks of 16 KiB)
		slowRAM: make([]byte, 0x4000), // 16 KiB at $C00000
	}
	for i := range srv.chipRAM {
		srv.chipRAM[i] = byte((i * 7) & 0xFF)
	}
	for i := range srv.slowRAM {
		srv.slowRAM[i] = byte((i * 3) & 0xFF)
	}
	// Populate custom snapshot: DMACON=$03E0, INTENA=$4020, COP1LC=$00002400, BPLCON0=$4200 (4 planes), BPL1PT=$00003000
	binary.BigEndian.PutUint16(srv.custom[0x096:], 0x03E0)
	binary.BigEndian.PutUint16(srv.custom[0x09A:], 0x4020)
	binary.BigEndian.PutUint32(srv.custom[0x080:], 0x00002400)
	binary.BigEndian.PutUint16(srv.custom[0x100:], 0x4200)
	binary.BigEndian.PutUint32(srv.custom[0x0E0:], 0x00003000)
	binary.BigEndian.PutUint16(srv.custom[0x180:], 0x0123)
	binary.BigEndian.PutUint16(srv.custom[0x182:], 0x0FFF)

	srv.regs = Registers{
		D:  [8]uint32{1, 2, 3, 4, 5, 6, 7, 8},
		A:  [8]uint32{0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x00DFF000, 0x6000, 0x7F00},
		SR: 0x2700,
		PC: 0x00001234,
	}

	go srv.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return srv
}

func writeGDBFrame(w io.Writer, noAck bool, payload string) {
	if !noAck {
		_, _ = io.WriteString(w, "+")
	}
	sum := packetChecksum(payload)
	_, _ = fmt.Fprintf(w, "$%s#%02x", payload, sum)
}

func (s *mockAmiberryServer) serve() {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	noAck := false
	for {
		b, err := r.ReadByte()
		if err != nil {
			return
		}
		if b != '$' {
			continue
		}
		body, err := r.ReadString('#')
		if err != nil {
			return
		}
		var chk [2]byte
		if _, err := io.ReadFull(r, chk[:]); err != nil {
			return
		}
		req := body[:len(body)-1]
		switch {
		case req == "QStartNoAckMode":
			writeGDBFrame(conn, noAck, "OK")
			noAck = true
		case req == "?":
			writeGDBFrame(conn, noAck, "S05")
		case req == "D":
			s.detached = true
			writeGDBFrame(conn, noAck, "OK")
			return
		case req == "c":
			writeGDBFrame(conn, noAck, "S05")
		case req == "g":
			var buf [18 * 4]byte
			for i := 0; i < 8; i++ {
				binary.BigEndian.PutUint32(buf[i*4:], s.regs.D[i])
				binary.BigEndian.PutUint32(buf[(8+i)*4:], s.regs.A[i])
			}
			binary.BigEndian.PutUint32(buf[16*4:], uint32(s.regs.SR))
			binary.BigEndian.PutUint32(buf[17*4:], s.regs.PC)
			writeGDBFrame(conn, noAck, hex.EncodeToString(buf[:]))
		case strings.HasPrefix(req, "m"):
			parts := strings.Split(req[1:], ",")
			var addr, length uint32
			_, _ = fmt.Sscanf(parts[0], "%x", &addr)
			_, _ = fmt.Sscanf(parts[1], "%x", &length)
			switch {
			case addr == 0xDFF000 && length == 0x200:
				writeGDBFrame(conn, noAck, hex.EncodeToString(s.custom[:]))
			case addr+length <= uint32(len(s.chipRAM)):
				writeGDBFrame(conn, noAck, hex.EncodeToString(s.chipRAM[addr:addr+length]))
			case addr >= 0xC00000 && (addr-0xC00000)+length <= uint32(len(s.slowRAM)):
				off := addr - 0xC00000
				writeGDBFrame(conn, noAck, hex.EncodeToString(s.slowRAM[off:off+length]))
			default:
				writeGDBFrame(conn, noAck, "E01")
			}
		case strings.HasPrefix(req, "qRcmd,"):
			rawCmd, _ := hex.DecodeString(req[6:])
			cmd := string(rawCmd)
			switch {
			case cmd == "memory-map":
				jsonReply := fmt.Sprintf(
					`{"addressing":"physical","truncated":false,"regions":[{"address":0,"size":%d,"type":"ram","chip":true,"name":"Chip memory"},{"address":12582912,"size":%d,"type":"ram","chip":false,"name":"Slow memory"},{"address":16252928,"size":524288,"type":"rom","chip":false,"name":"Kickstart ROM"}]}`,
					len(s.chipRAM), len(s.slowRAM),
				)
				writeGDBFrame(conn, noAck, hex.EncodeToString([]byte(jsonReply)))
			case strings.HasPrefix(cmd, "process-break name "):
				writeGDBFrame(conn, noAck, "OK")
			default:
				writeGDBFrame(conn, noAck, "E01")
			}
		default:
			writeGDBFrame(conn, noAck, "")
		}
	}
}

func TestClientSnapshotWorkflow(t *testing.T) {
	srv := startMockAmiberry(t)
	c, err := Dial(srv.ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.WaitProcessBreak("MyGame", 2*time.Second); err != nil {
		t.Fatalf("WaitProcessBreak: %v", err)
	}

	regs, err := c.ReadRegisters()
	if err != nil {
		t.Fatalf("ReadRegisters: %v", err)
	}
	if regs.PC != 0x00001234 || regs.SR != 0x2700 || regs.A[5] != 0x00DFF000 {
		t.Fatalf("unexpected registers: %+v", regs)
	}

	regions, err := c.MemoryMap()
	if err != nil {
		t.Fatalf("MemoryMap: %v", err)
	}
	if len(regions) != 3 {
		t.Fatalf("expected 3 regions, got %d", len(regions))
	}
	if !regions[0].Chip || regions[0].Type != "ram" || regions[0].Size != uint32(len(srv.chipRAM)) {
		t.Fatalf("unexpected region[0]: %+v", regions[0])
	}

	chipDump, err := c.ReadMemory(0, uint32(len(srv.chipRAM)))
	if err != nil {
		t.Fatalf("ReadMemory chip: %v", err)
	}
	if !bytes.Equal(chipDump, srv.chipRAM) {
		t.Fatalf("chipRAM mismatch across multi-chunk read")
	}

	slowDump, err := c.ReadMemory(0xC00000, uint32(len(srv.slowRAM)))
	if err != nil {
		t.Fatalf("ReadMemory slow: %v", err)
	}
	if !bytes.Equal(slowDump, srv.slowRAM) {
		t.Fatalf("slowRAM mismatch")
	}

	custom, err := c.ReadCustomSnapshot()
	if err != nil {
		t.Fatalf("ReadCustomSnapshot: %v", err)
	}
	if custom.DMACON() != 0x03E0 || custom.INTENA() != 0x4020 || custom.COP1LC() != 0x00002400 {
		t.Fatalf("unexpected custom snapshot values: DMACON=%#x INTENA=%#x COP1LC=%#x",
			custom.DMACON(), custom.INTENA(), custom.COP1LC())
	}
	if custom.ActivePlanes() != 4 || custom.BPLPT()[0] != 0x00003000 {
		t.Fatalf("unexpected BPL state: planes=%d BPL1PT=%#x", custom.ActivePlanes(), custom.BPLPT()[0])
	}
	pal := custom.Palette12()
	if pal[0] != 0x0123 || pal[1] != 0x0FFF {
		t.Fatalf("unexpected palette: %#x, %#x", pal[0], pal[1])
	}

	if err := c.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if !srv.detached {
		t.Fatalf("expected server to receive D (detach)")
	}
}
