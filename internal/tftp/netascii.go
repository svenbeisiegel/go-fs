package tftp

import "io"

const (
	cr  = 0x0D
	lf  = 0x0A
	nul = 0x00
)

// netasciiReader converts host line endings into the netascii representation
// defined by RFC 764: a line feed becomes CR LF, a lone carriage return becomes
// CR NUL. The pending carriage return is carried across reads, so the
// conversion is independent of where the chunk boundaries fall.
type netasciiReader struct {
	src       io.Reader
	in        []byte
	out       []byte
	pendingCR bool
	eof       bool
}

func newNetasciiReader(src io.Reader) *netasciiReader {
	return &netasciiReader{src: src, in: make([]byte, 8192)}
}

func (r *netasciiReader) Read(p []byte) (int, error) {
	for len(r.out) == 0 && !r.eof {
		n, err := r.src.Read(r.in)
		if n > 0 {
			r.encode(r.in[:n])
		}
		if err == io.EOF {
			r.eof = true
			if r.pendingCR {
				r.pendingCR = false
				r.out = append(r.out, nul)
			}
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if len(r.out) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *netasciiReader) encode(chunk []byte) {
	for _, b := range chunk {
		if r.pendingCR {
			r.pendingCR = false
			if b == lf {
				r.out = append(r.out, lf)
				continue
			}
			r.out = append(r.out, nul)
			if b == cr {
				r.pendingCR = true
				r.out = append(r.out, cr)
				continue
			}
			r.out = append(r.out, b)
			continue
		}
		switch b {
		case cr:
			r.pendingCR = true
			r.out = append(r.out, cr)
		case lf:
			r.out = append(r.out, cr, lf)
		default:
			r.out = append(r.out, b)
		}
	}
}

// netasciiWriter reverses the netascii representation back into host line
// endings on its way to dst.
type netasciiWriter struct {
	dst       io.Writer
	pendingCR bool
}

func newNetasciiWriter(dst io.Writer) *netasciiWriter {
	return &netasciiWriter{dst: dst}
}

func (w *netasciiWriter) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p))
	for _, b := range p {
		if w.pendingCR {
			w.pendingCR = false
			switch b {
			case lf:
				out = append(out, lf)
			case nul:
				out = append(out, cr)
			case cr:
				out = append(out, cr)
				w.pendingCR = true
			default:
				out = append(out, cr, b)
			}
			continue
		}
		if b == cr {
			w.pendingCR = true
			continue
		}
		out = append(out, b)
	}
	if len(out) > 0 {
		if _, err := w.dst.Write(out); err != nil {
			return 0, err
		}
	}
	// report the input as consumed, the conversion changes the length
	return len(p), nil
}

// Flush writes a carriage return that was still pending at the end of the
// transfer.
func (w *netasciiWriter) Flush() error {
	if !w.pendingCR {
		return nil
	}
	w.pendingCR = false
	_, err := w.dst.Write([]byte{cr})
	return err
}
