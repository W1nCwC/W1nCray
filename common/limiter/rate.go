package limiter

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

// WaitN blocks until n bytes may pass the bucket. Unlike rate.Limiter.WaitN it
// accepts n larger than the burst by waiting in burst-sized chunks; XrayR
// called WaitN directly, which fails immediately for such n and let large
// buffers bypass the limit.
func WaitN(ctx context.Context, l *rate.Limiter, n int) error {
	for n > 0 {
		chunk := min(n, l.Burst())
		if chunk <= 0 {
			// Burst 0 with a finite limit never admits anything; treat it
			// as unlimited rather than blocking the connection forever.
			return nil
		}
		if err := l.WaitN(ctx, chunk); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

// Writer throttles a buf.Writer.
type Writer struct {
	buf.Writer
	ctx     context.Context
	limiter *rate.Limiter
}

// NewWriter wraps w so that data written through it obeys l.
func NewWriter(ctx context.Context, w buf.Writer, l *rate.Limiter) *Writer {
	return &Writer{Writer: w, ctx: ctx, limiter: l}
}

// WriteMultiBuffer implements buf.Writer.
func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := WaitN(w.ctx, w.limiter, int(mb.Len())); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// Close implements common.Closable.
func (w *Writer) Close() error {
	return common.Close(w.Writer)
}

// Interrupt implements common.Interruptible.
func (w *Writer) Interrupt() {
	common.Interrupt(w.Writer)
}

// Reader throttles a buf.Reader.
type Reader struct {
	buf.Reader
	ctx     context.Context
	limiter *rate.Limiter
}

// NewReader wraps r so that data read through it obeys l.
func NewReader(ctx context.Context, r buf.Reader, l *rate.Limiter) *Reader {
	return &Reader{Reader: r, ctx: ctx, limiter: l}
}

// ReadMultiBuffer implements buf.Reader.
func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if n := int(mb.Len()); n > 0 {
		if werr := WaitN(r.ctx, r.limiter, n); werr != nil {
			buf.ReleaseMulti(mb)
			return nil, werr
		}
	}
	return mb, err
}

// Interrupt implements common.Interruptible.
func (r *Reader) Interrupt() {
	common.Interrupt(r.Reader)
}

// Close implements common.Closable.
func (r *Reader) Close() error {
	return common.Close(r.Reader)
}
