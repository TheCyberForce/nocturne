package proto

const (
	windowWords = 32
	// WindowSize is how far behind the highest seen counter a packet may
	// arrive and still be accepted.
	WindowSize = windowWords * 64
)

// ReplayWindow is a sliding bitmap over received counters. It must only
// be updated with counters of packets that passed authentication.
type ReplayWindow struct {
	top  uint64
	bits [windowWords]uint64
}

// Accept reports whether counter is new, and records it if so.
func (w *ReplayWindow) Accept(counter uint64) bool {
	word, bit := (counter/64)%windowWords, uint64(1)<<(counter%64)
	if counter > w.top {
		if counter-w.top >= WindowSize {
			w.bits = [windowWords]uint64{}
		} else {
			for c := w.top + 1; c <= counter; c++ {
				w.bits[(c/64)%windowWords] &^= 1 << (c % 64)
			}
		}
		w.top = counter
	} else if w.top-counter >= WindowSize || w.bits[word]&bit != 0 {
		return false
	}
	w.bits[word] |= bit
	return true
}
