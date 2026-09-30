package selfupdate

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"testing"
)

// elfHeader is the smallest ELF file debug/elf reads: a 64 bit header with no
// program and no section headers.
func elfHeader(machine elf.Machine, abi elf.OSABI) []byte {
	header := make([]byte, 64)
	copy(header, elf.ELFMAG)
	header[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	header[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	header[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	header[elf.EI_OSABI] = byte(abi)
	le := binary.LittleEndian
	le.PutUint16(header[16:], uint16(elf.ET_EXEC))
	le.PutUint16(header[18:], uint16(machine))
	le.PutUint32(header[20:], uint32(elf.EV_CURRENT))
	le.PutUint16(header[52:], 64) // ehsize
	le.PutUint16(header[54:], 56) // phentsize
	le.PutUint16(header[58:], 64) // shentsize
	return header
}

// machoHeader is a 64 bit Mach-O header with no load commands.
func machoHeader(cpu macho.Cpu) []byte {
	header := make([]byte, 32)
	le := binary.LittleEndian
	le.PutUint32(header[0:], macho.Magic64)
	le.PutUint32(header[4:], uint32(cpu))
	le.PutUint32(header[12:], uint32(macho.TypeExec))
	return header
}

// peHeader is a DOS stub pointing at a COFF header with no sections and no
// optional header, padded to what debug/pe reads of the stub.
func peHeader(machine uint16) []byte {
	header := make([]byte, 128)
	copy(header, "MZ")
	le := binary.LittleEndian
	le.PutUint32(header[0x3c:], 64)
	copy(header[64:], "PE\x00\x00")
	le.PutUint16(header[68:], machine)
	return header
}

func TestPlatformOf(t *testing.T) {
	tests := []struct {
		name         string
		file         []byte
		goos, goarch string
	}{
		{"linux amd64", elfHeader(elf.EM_X86_64, elf.ELFOSABI_NONE), "linux", "amd64"},
		{"linux arm64", elfHeader(elf.EM_AARCH64, elf.ELFOSABI_NONE), "linux", "arm64"},
		{"freebsd amd64", elfHeader(elf.EM_X86_64, elf.ELFOSABI_FREEBSD), "freebsd", "amd64"},
		{"darwin arm64", machoHeader(macho.CpuArm64), "darwin", "arm64"},
		{"darwin amd64", machoHeader(macho.CpuAmd64), "darwin", "amd64"},
		{"windows amd64", peHeader(pe.IMAGE_FILE_MACHINE_AMD64), "windows", "amd64"},
		{"windows arm64", peHeader(pe.IMAGE_FILE_MACHINE_ARM64), "windows", "arm64"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			goos, goarch, err := platformOf(bytes.NewReader(test.file))
			if err != nil {
				t.Fatalf("platformOf: %v", err)
			}
			if goos != test.goos || goarch != test.goarch {
				t.Errorf("got %s/%s, want %s/%s", goos, goarch, test.goos, test.goarch)
			}
		})
	}
}

// The test binary is a native executable, which is as real a sample of this
// platform's format as there is.
func TestPlatformOfThisBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	file, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	goos, goarch, err := platformOf(file)
	if err != nil {
		t.Fatalf("platformOf: %v", err)
	}
	if goos != runtime.GOOS || goarch != runtime.GOARCH {
		t.Errorf("got %s/%s, want %s/%s", goos, goarch, runtime.GOOS, runtime.GOARCH)
	}
}

func TestPlatformOfRefusesOtherFiles(t *testing.T) {
	for _, file := range [][]byte{nil, []byte("#!/bin/sh\necho go-fs 9.9.9\n"), bytes.Repeat([]byte{0}, 4096)} {
		if _, _, err := platformOf(bytes.NewReader(file)); !errors.Is(err, errNotExecutable) {
			t.Errorf("%q: %v", file[:min(len(file), 16)], err)
		}
	}
}
