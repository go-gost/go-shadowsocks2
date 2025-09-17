package shadowaead2022

import (
	"math/bits"
)

// SlidingWindow implements proper anti-replay protection using a bitmap-based sliding window.
// This is what the SIP022 spec actually requires: "employ a sliding window filter".
//
// The window tracks received packet IDs using a bitmap. Each bit represents whether
// a specific packet ID has been received. The window slides forward as newer packets arrive.
type SlidingWindow struct {
	maxPacketID uint64   // Highest packet ID seen so far
	bitmap      []uint64 // Bitmap of received packets, bitmap[0] covers newest packets
	windowSize  uint64   // Size of the sliding window (e.g., 2000)
}

// NewSlidingWindow creates a sliding window filter for anti-replay protection.
// windowSize should be the maximum allowed gap between packet IDs (typically 2000).
func NewSlidingWindow(windowSize uint64) *SlidingWindow {
	if windowSize == 0 {
		windowSize = 2000 // SIP022 default
	}

	// Calculate bitmap size: need enough uint64s to cover windowSize bits
	bitmapSize := (windowSize + 63) / 64

	return &SlidingWindow{
		maxPacketID: 0,
		bitmap:      make([]uint64, bitmapSize),
		windowSize:  windowSize,
	}
}

// Validate checks if a packet ID is valid (not a replay and within window).
// Returns true if the packet should be accepted, false if it's a replay or too old.
//
// This is the correct implementation:
// - Packets older than (maxPacketID - windowSize) are rejected (too old)
// - Packets already received are rejected (replay attack)
// - New packets update the bitmap and slide the window if necessary
func (w *SlidingWindow) Validate(packetID uint64) bool {
	// Special case: first packet ever
	if w.maxPacketID == 0 {
		w.maxPacketID = packetID
		w.markReceived(0) // Mark position 0 in bitmap
		return true
	}

	// Packet too old: outside the window
	// Avoid integer overflow by checking: packetID < maxPacketID - windowSize
	if packetID < w.maxPacketID && w.maxPacketID-packetID > w.windowSize {
		return false
	}

	// New packet: newer than anything we've seen
	if packetID > w.maxPacketID {
		shift := packetID - w.maxPacketID
		w.shiftWindow(shift)
		w.maxPacketID = packetID
		w.markReceived(0) // New max is always at position 0
		return true
	}

	// Packet within window: check if it's a replay
	offset := w.maxPacketID - packetID
	if w.isReceived(offset) {
		return false // Replay attack detected
	}

	w.markReceived(offset)
	return true
}

// shiftWindow shifts the bitmap left by n positions (for newer packets).
// This is called when we receive a packet newer than maxPacketID.
func (w *SlidingWindow) shiftWindow(shift uint64) {
	if shift == 0 {
		return
	}

	// If shift is larger than window, just clear everything
	if shift >= w.windowSize {
		for i := range w.bitmap {
			w.bitmap[i] = 0
		}
		return
	}

	// Shift by whole uint64s first
	wholeShift := shift / 64
	bitShift := shift % 64

	if wholeShift > 0 {
		// Shift array elements
		copy(w.bitmap[wholeShift:], w.bitmap)
		// Clear the vacated elements
		for i := uint64(0); i < wholeShift && i < uint64(len(w.bitmap)); i++ {
			w.bitmap[i] = 0
		}
	}

	// Shift remaining bits
	if bitShift > 0 {
		for i := len(w.bitmap) - 1; i > 0; i-- {
			w.bitmap[i] = (w.bitmap[i] << bitShift) | (w.bitmap[i-1] >> (64 - bitShift))
		}
		w.bitmap[0] <<= bitShift
	}
}

// isReceived checks if a packet at the given offset from maxPacketID has been received.
// offset 0 means maxPacketID itself, offset 1 means maxPacketID-1, etc.
func (w *SlidingWindow) isReceived(offset uint64) bool {
	if offset >= w.windowSize {
		return false
	}

	idx := offset / 64
	bit := offset % 64

	if idx >= uint64(len(w.bitmap)) {
		return false
	}

	return (w.bitmap[idx] & (1 << bit)) != 0
}

// markReceived marks a packet at the given offset as received.
func (w *SlidingWindow) markReceived(offset uint64) {
	if offset >= w.windowSize {
		return
	}

	idx := offset / 64
	bit := offset % 64

	if idx < uint64(len(w.bitmap)) {
		w.bitmap[idx] |= (1 << bit)
	}
}

// Count returns the number of packets marked as received in the window.
// This is mainly useful for debugging and testing.
func (w *SlidingWindow) Count() int {
	count := 0
	for _, word := range w.bitmap {
		count += bits.OnesCount64(word)
	}
	return count
}
