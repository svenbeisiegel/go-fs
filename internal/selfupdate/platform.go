package selfupdate

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"io"
)

// errNotExecutable is a file that is none of the executable formats go-fs is
// built as.
var errNotExecutable = errors.New("the file is not an ELF, Mach-O or PE executable")

// platformOf reads the header of an executable and reports the GOOS and
// GOARCH it was built for. Only the header is read, and nothing is run: this
// is what turns away a build for another machine before it is ever started.
func platformOf(r io.ReaderAt) (goos, goarch string, err error) {
	if file, err := elf.NewFile(r); err == nil {
		return elfOS(file.OSABI), elfArch(file.Machine), nil
	}
	if file, err := macho.NewFile(r); err == nil {
		return "darwin", machoArch(file.Cpu), nil
	}
	// debug/pe also reads a bare COFF object, which has no DOS stub, and takes
	// even a file of zeros for one; an executable always starts with the stub
	if isDOSStub(r) {
		if file, err := pe.NewFile(r); err == nil {
			return "windows", peArch(file.Machine), nil
		}
	}
	return "", "", errNotExecutable
}

func isDOSStub(r io.ReaderAt) bool {
	stub := make([]byte, 2)
	_, err := r.ReadAt(stub, 0)
	return err == nil && string(stub) == "MZ"
}

func elfOS(abi elf.OSABI) string {
	switch abi {
	case elf.ELFOSABI_FREEBSD:
		return "freebsd"
	case elf.ELFOSABI_NETBSD:
		return "netbsd"
	case elf.ELFOSABI_OPENBSD:
		return "openbsd"
	default:
		// the Go linker leaves the ABI at none for linux
		return "linux"
	}
}

func elfArch(machine elf.Machine) string {
	switch machine {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_386:
		return "386"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_RISCV:
		return "riscv64"
	default:
		return machine.String()
	}
}

func machoArch(cpu macho.Cpu) string {
	switch cpu {
	case macho.CpuAmd64:
		return "amd64"
	case macho.CpuArm64:
		return "arm64"
	default:
		return cpu.String()
	}
}

func peArch(machine uint16) string {
	switch machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "386"
	default:
		return "unknown"
	}
}
