package gauntlet

// A test-only QR reader (#120). It reads a clean code -- one with no
// damage, so no error correction -- from the module matrix the enrol
// reply carries, and hands back the byte-mode payload. It exists so the
// round-trip invariant (decode the matrix, get the URI back) can be
// proved without a third-party decoder (owner decision 2c, 2026-11-17).
//
// The steps follow ISO/IEC 18004: read and BCH-check the format bits,
// take the error-correction level and mask, unmask, read the codewords
// in placement order skipping the function patterns, de-interleave the
// blocks, drop the error-correction codewords, and decode byte mode.
// Block tables are carried for error-correction level M only, the level
// the enrol reply uses; any other level is refused.

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// qrContent is what qrRead recovers.
type qrContent struct {
	Version int    // 1 to 40
	Level   byte   // 'L', 'M', 'Q' or 'H'
	Mask    int    // 0 to 7
	Payload []byte // the byte-mode data
}

// qrBlocksM is the ISO/IEC 18004 Table 9 row for level M, one entry per
// version (index version-1): error-correction codewords per block, then
// the number of blocks and data codewords per block in group 1, then
// the same for group 2 (zero blocks when the version has one group).
var qrBlocksM = [40][5]int{
	{10, 1, 16, 0, 0}, {16, 1, 28, 0, 0}, {26, 1, 44, 0, 0}, {18, 2, 32, 0, 0},
	{24, 2, 43, 0, 0}, {16, 4, 27, 0, 0}, {18, 4, 31, 0, 0}, {22, 2, 38, 2, 39},
	{22, 3, 36, 2, 37}, {26, 4, 43, 1, 44}, {30, 1, 50, 4, 51}, {22, 6, 36, 2, 37},
	{22, 8, 37, 1, 38}, {24, 4, 40, 5, 41}, {24, 5, 41, 5, 42}, {28, 7, 45, 3, 46},
	{28, 10, 46, 1, 47}, {26, 9, 43, 4, 44}, {26, 3, 44, 11, 45}, {26, 3, 41, 13, 42},
	{26, 17, 42, 0, 0}, {28, 17, 46, 0, 0}, {28, 4, 47, 14, 48}, {28, 6, 45, 14, 46},
	{28, 8, 47, 13, 48}, {28, 19, 46, 4, 47}, {28, 22, 45, 3, 46}, {28, 3, 45, 23, 46},
	{28, 21, 45, 7, 46}, {28, 19, 47, 10, 48}, {28, 2, 46, 29, 47}, {28, 10, 46, 23, 47},
	{28, 14, 46, 21, 47}, {28, 14, 46, 23, 47}, {28, 12, 47, 26, 48}, {28, 6, 47, 34, 48},
	{28, 29, 46, 14, 47}, {28, 13, 46, 32, 47}, {28, 40, 47, 7, 48}, {28, 18, 47, 31, 48},
}

// qrBlockSizes lists the data-codeword count of every block of version
// v at level M, in block order, and the error-correction codewords each
// block carries.
func qrBlockSizes(v int) (data []int, ecPerBlock int) {
	row := qrBlocksM[v-1]
	for range row[1] {
		data = append(data, row[2])
	}
	for range row[3] {
		data = append(data, row[4])
	}
	return data, row[0]
}

// qrBCH returns value<<shift with the BCH remainder of generator gen
// appended: the 15-bit format word (5 value bits, shift 10, gen 0x537)
// or the 18-bit version word (6 value bits, shift 12, gen 0x1F25).
func qrBCH(value, valueBits, shift, gen int) int {
	rem := value << shift
	for i := valueBits + shift - 1; i >= shift; i-- {
		if rem>>i&1 == 1 {
			rem ^= gen << (i - shift)
		}
	}
	return value<<shift | rem
}

// qrFormatWord is the 15 format bits as drawn: BCH(15,5) of the 5-bit
// level-and-mask value, XOR the mask pattern 101010000010010.
func qrFormatWord(levelBits, mask int) int {
	return qrBCH(levelBits<<3|mask, 5, 10, 0x537) ^ 0x5412
}

// qrAlignCentres lists the alignment-pattern centre coordinates of
// version v (the same list serves rows and columns); none for version 1.
func qrAlignCentres(v int) []int {
	if v == 1 {
		return nil
	}
	n := v/7 + 2
	span, gaps := v*4+4, n*2-2
	step := (span + gaps - 1) / gaps * 2 // ceil(span/gaps), doubled
	if v == 32 {
		step = 26 // the one version where the formula is off
	}
	out := make([]int, n)
	out[0] = 6
	for i, pos := n-1, v*4+10; i >= 1; i, pos = i-1, pos-step {
		out[i] = pos
	}
	return out
}

// qrFunctionMask marks every module of version v that is not data: the
// finders with their separators, the timing lines, the alignment
// patterns, both format areas, the dark module and, from version 7, the
// two version areas.
func qrFunctionMask(v int) [][]bool {
	n := 17 + 4*v
	fn := make([][]bool, n)
	for i := range fn {
		fn[i] = make([]bool, n)
	}
	mark := func(r0, c0, h, w int) {
		for r := r0; r < r0+h; r++ {
			for c := c0; c < c0+w; c++ {
				fn[r][c] = true
			}
		}
	}
	mark(0, 0, 9, 9)   // top-left finder, separator, format bits
	mark(0, n-8, 9, 8) // top-right finder, separator, format bits
	mark(n-8, 0, 8, 9) // bottom-left finder, separator, format bits (and the dark module)
	mark(6, 0, 1, n)   // row timing
	mark(0, 6, n, 1)   // column timing
	mark(n-8, 8, 1, 1) // the dark module
	centres := qrAlignCentres(v)
	for i, r := range centres {
		for j, c := range centres {
			last := len(centres) - 1
			if (i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0) {
				continue // would sit on a finder
			}
			mark(r-2, c-2, 5, 5)
		}
	}
	if v >= 7 {
		mark(0, n-11, 6, 3)
		mark(n-11, 0, 3, 6)
	}
	return fn
}

// qrMaskBit reports whether mask pattern m flips the module at row i,
// column j.
func qrMaskBit(m, i, j int) bool {
	switch m {
	case 0:
		return (i+j)%2 == 0
	case 1:
		return i%2 == 0
	case 2:
		return j%3 == 0
	case 3:
		return (i+j)%3 == 0
	case 4:
		return (i/2+j/3)%2 == 0
	case 5:
		return i*j%2+i*j%3 == 0
	case 6:
		return (i*j%2+i*j%3)%2 == 0
	default:
		return ((i+j)%2+i*j%3)%2 == 0
	}
}

// qrRead decodes rows, a matrix as the enrol reply carries it (one
// string per row, '1' dark, '0' light, no quiet zone), without error
// correction.
func qrRead(rows []string) (qrContent, error) {
	n := len(rows)
	if n < 21 || n > 177 || (n-17)%4 != 0 {
		return qrContent{}, fmt.Errorf("side %d is not a QR size", n)
	}
	dark := make([][]bool, n)
	for r, row := range rows {
		if len(row) != n {
			return qrContent{}, fmt.Errorf("row %d has %d modules, want %d", r, len(row), n)
		}
		dark[r] = make([]bool, n)
		for c := range n {
			switch row[c] {
			case '1':
				dark[r][c] = true
			case '0':
			default:
				return qrContent{}, fmt.Errorf("row %d column %d is %q, want 0 or 1", r, c, row[c])
			}
		}
	}
	v := (n - 17) / 4

	// Format information: two copies, most significant bit first.
	word := func(cells [][2]int) int {
		w := 0
		for _, rc := range cells {
			w <<= 1
			if dark[rc[0]][rc[1]] {
				w |= 1
			}
		}
		return w
	}
	first := [][2]int{{8, 0}, {8, 1}, {8, 2}, {8, 3}, {8, 4}, {8, 5}, {8, 7}, {8, 8}, {7, 8}, {5, 8}, {4, 8}, {3, 8}, {2, 8}, {1, 8}, {0, 8}}
	var second [][2]int
	for r := n - 1; r >= n-7; r-- {
		second = append(second, [2]int{r, 8})
	}
	for c := n - 8; c < n; c++ {
		second = append(second, [2]int{8, c})
	}
	f1, f2 := word(first), word(second)
	if f1 != f2 {
		return qrContent{}, fmt.Errorf("the two format copies differ: %015b and %015b", f1, f2)
	}
	data := (f1 ^ 0x5412) >> 10
	if qrFormatWord(data>>3, data&7) != f1 {
		return qrContent{}, fmt.Errorf("format bits %015b fail the BCH check", f1)
	}
	levelBits, mask := data>>3, data&7
	level := map[int]byte{1: 'L', 0: 'M', 3: 'Q', 2: 'H'}[levelBits]
	if level != 'M' {
		return qrContent{}, fmt.Errorf("error-correction level %c: this reader carries level M tables only", level)
	}

	// Version information, versions 7 and up: two copies, each checked.
	if v >= 7 {
		want := qrBCH(v, 6, 12, 0x1F25)
		var upper, lower int
		for i := range 18 {
			if dark[i/3][n-11+i%3] {
				upper |= 1 << i
			}
			if dark[n-11+i%3][i/3] {
				lower |= 1 << i
			}
		}
		if upper != want || lower != want {
			return qrContent{}, fmt.Errorf("version bits %018b / %018b, want %018b for version %d", upper, lower, want, v)
		}
	}

	// Codewords in placement order: column pairs from the right, upward
	// then downward, the vertical timing column skipped.
	fn := qrFunctionMask(v)
	var bits []bool
	up := true
	for x := n - 1; x >= 1; x -= 2 {
		if x == 6 {
			x = 5
		}
		for step := range n {
			r := step
			if up {
				r = n - 1 - step
			}
			for _, c := range [2]int{x, x - 1} {
				if fn[r][c] {
					continue
				}
				b := dark[r][c]
				if qrMaskBit(mask, r, c) {
					b = !b
				}
				bits = append(bits, b)
			}
		}
		up = !up
	}
	stream := make([]byte, len(bits)/8) // leftover remainder bits are dropped
	for i := range stream {
		for k := range 8 {
			stream[i] <<= 1
			if bits[i*8+k] {
				stream[i] |= 1
			}
		}
	}

	// De-interleave: data codewords first, taken round-robin across the
	// blocks, then the error-correction codewords the same way; each
	// block's are checked against the ones recomputed from its data.
	sizes, ec := qrBlockSizes(v)
	total := 0
	for _, s := range sizes {
		total += s
	}
	if len(stream) != total+ec*len(sizes) {
		return qrContent{}, fmt.Errorf("version %d holds %d codewords, its table says %d", v, len(stream), total+ec*len(sizes))
	}
	blocks := make([][]byte, len(sizes))
	pos := 0
	for i := range slices.Max(sizes) {
		for b, s := range sizes {
			if i < s {
				blocks[b] = append(blocks[b], stream[pos])
				pos++
			}
		}
	}
	ecBlocks := make([][]byte, len(sizes))
	for range ec {
		for b := range sizes {
			ecBlocks[b] = append(ecBlocks[b], stream[pos])
			pos++
		}
	}
	var codewords []byte
	for b, blk := range blocks {
		if want := qrRSRemainder(blk, ec); !bytes.Equal(want, ecBlocks[b]) {
			return qrContent{}, fmt.Errorf("block %d error-correction codewords % X, recomputed % X", b, ecBlocks[b], want)
		}
		codewords = append(codewords, blk...)
	}

	// Byte mode: 0100, a count of 8 bits (versions 1-9) or 16 (10-40), the bytes.
	r := bitReader{data: codewords}
	if mode, ok := r.take(4); !ok || mode != 0b0100 {
		return qrContent{}, fmt.Errorf("mode indicator %04b, want byte mode 0100", mode)
	}
	countBits := 8
	if v >= 10 {
		countBits = 16
	}
	count, ok := r.take(countBits)
	if !ok {
		return qrContent{}, errors.New("data ends inside the character count")
	}
	payload := make([]byte, count)
	for i := range payload {
		b, ok := r.take(8)
		if !ok {
			return qrContent{}, fmt.Errorf("data ends after %d of %d bytes", i, count)
		}
		payload[i] = byte(b)
	}
	return qrContent{Version: v, Level: level, Mask: mask, Payload: payload}, nil
}

// qrRSRemainder returns the n error-correction codewords of data:
// ISO/IEC 18004 section 7.5.2 -- the remainder of data*x^n divided by
// the generator polynomial, the product of (x - a^i) for i = 0..n-1,
// over GF(256) with the primitive polynomial 0x11D. Written here from
// the standard, not shared with the encoder under test.
func qrRSRemainder(data []byte, n int) []byte {
	var exp [512]byte
	var log [256]int
	x := 1
	for i := range 255 {
		exp[i], log[x] = byte(x), i
		x <<= 1
		if x > 255 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		exp[i] = exp[i-255]
	}
	mul := func(a, b byte) byte {
		if a == 0 || b == 0 {
			return 0
		}
		return exp[log[a]+log[b]]
	}
	gen := []byte{1} // highest power first
	for i := range n {
		next := make([]byte, len(gen)+1)
		for j, c := range gen {
			next[j] ^= c
			next[j+1] ^= mul(c, exp[i]) // minus is plus in GF(2^8)
		}
		gen = next
	}
	rem := make([]byte, n)
	for _, d := range data {
		f := d ^ rem[0]
		copy(rem, rem[1:])
		rem[n-1] = 0
		for j := range n {
			rem[j] ^= mul(gen[j+1], f)
		}
	}
	return rem
}

// bitReader reads big-endian bit groups from data.
type bitReader struct {
	data []byte
	pos  int
}

func (r *bitReader) take(n int) (int, bool) {
	if r.pos+n > len(r.data)*8 {
		return 0, false
	}
	v := 0
	for range n {
		v = v<<1 | int(r.data[r.pos/8]>>(7-r.pos%8)&1)
		r.pos++
	}
	return v, true
}

// ---- The reader's own tests ------------------------------------------
//
// None of these uses the encoder the enrol reply is built with. They
// stand on constants from ISO/IEC 18004 (the format words, the version
// word, the alignment centres, the raw module counts) and on matrices
// painted below by hand from a codeword stream written out bit by bit.

// TestQRFormatWordsMatchTheStandard pins the eight level-M format
// words, already masked, as ISO/IEC 18004 Table C.1 prints them, and
// the same words computed by qrBCH.
func TestQRFormatWordsMatchTheStandard(t *testing.T) {
	want := [8]int{
		0b101010000010010, 0b101000100100101, 0b101111001111100, 0b101101101001011,
		0b100010111111001, 0b100000011001110, 0b100111110010111, 0b100101010100000,
	}
	for mask, w := range want {
		if got := qrFormatWord(0, mask); got != w { // level M is 00
			t.Errorf("format word for M, mask %d = %015b, want %015b", mask, got, w)
		}
	}
	// A level other than M, from the same table: L (01), mask 0.
	if got := qrFormatWord(1, 0); got != 0b111011111000100 {
		t.Errorf("format word for L, mask 0 = %015b, want 111011111000100", got)
	}
}

// TestQRVersionWordsMatchTheStandard pins versions 7 and 8 from
// ISO/IEC 18004 Table D.1.
func TestQRVersionWordsMatchTheStandard(t *testing.T) {
	for v, want := range map[int]int{7: 0x07C94, 8: 0x085BC} {
		if got := qrBCH(v, 6, 12, 0x1F25); got != want {
			t.Errorf("version word for %d = %#x, want %#x", v, got, want)
		}
	}
}

// TestQRAlignmentCentresMatchTheStandard pins ISO/IEC 18004 Annex E for
// the versions where the step rule is easiest to get wrong.
func TestQRAlignmentCentresMatchTheStandard(t *testing.T) {
	for v, want := range map[int][]int{
		1:  nil,
		2:  {6, 18},
		7:  {6, 22, 38},
		14: {6, 26, 46, 66},
		32: {6, 34, 60, 86, 112, 138},
		36: {6, 24, 50, 76, 102, 128, 154},
		40: {6, 30, 58, 86, 114, 142, 170},
	} {
		if got := qrAlignCentres(v); !slices.Equal(got, want) {
			t.Errorf("alignment centres of version %d = %v, want %v", v, got, want)
		}
	}
}

// TestQRDataModulesMatchTheStandardAndTheTables: the modules left after
// the function patterns are what the standard says (the five literals
// are its Table 1 "data modules" column; the formula covers the rest),
// and the codewords of the block table fill them to within the
// remainder bits, for all forty versions.
func TestQRDataModulesMatchTheStandardAndTheTables(t *testing.T) {
	literal := map[int]int{1: 208, 2: 359, 3: 567, 7: 1568, 40: 29648}
	for v := 1; v <= 40; v++ {
		free := 0
		for _, row := range qrFunctionMask(v) {
			for _, f := range row {
				if !f {
					free++
				}
			}
		}
		want := (16*v+128)*v + 64
		if v >= 2 {
			na := v/7 + 2
			want -= (25*na-10)*na - 55
		}
		if v >= 7 {
			want -= 36
		}
		if free != want {
			t.Errorf("version %d has %d data modules, want %d", v, free, want)
		}
		if lit, ok := literal[v]; ok && free != lit {
			t.Errorf("version %d has %d data modules, the standard says %d", v, free, lit)
		}
		sizes, ec := qrBlockSizes(v)
		codewords := ec * len(sizes)
		for _, s := range sizes {
			codewords += s
		}
		if codewords != free/8 {
			t.Errorf("version %d: block table gives %d codewords, the symbol holds %d", v, codewords, free/8)
		}
	}
}

// qrBits writes bit groups big-endian.
type qrBits struct{ bits []bool }

func (w *qrBits) put(value, n int) {
	for i := n - 1; i >= 0; i-- {
		w.bits = append(w.bits, value>>i&1 == 1)
	}
}

// qrByteModeData is the data codewords of payload in byte mode for a
// symbol holding capacity of them: mode, count, bytes, terminator, zero
// padding to a byte, then the pad bytes EC and 11 alternately.
func qrByteModeData(payload []byte, countBits, capacity int) []byte {
	var w qrBits
	w.put(0b0100, 4)
	w.put(len(payload), countBits)
	for _, b := range payload {
		w.put(int(b), 8)
	}
	w.put(0, min(4, capacity*8-len(w.bits)))
	for len(w.bits)%8 != 0 {
		w.put(0, 1)
	}
	out := make([]byte, len(w.bits)/8)
	for i := range out {
		for k := range 8 {
			out[i] <<= 1
			if w.bits[i*8+k] {
				out[i] |= 1
			}
		}
	}
	for pad := byte(0xEC); len(out) < capacity; pad ^= 0xEC ^ 0x11 {
		out = append(out, pad)
	}
	return out
}

// qrPaint draws a version 1, 5, 7 or 10 level-M symbol: the function
// patterns drawn out cell by cell (and recorded as drawn), then the
// interleaved codewords laid in by column pair, masked.
func qrPaint(t *testing.T, v, mask int, data []byte, blockSizes []int, ecPer int) []string {
	t.Helper()
	return qrPaintTampered(t, v, mask, data, blockSizes, ecPer, nil)
}

// qrPaintTampered is qrPaint with a hook that may alter the interleaved
// codeword stream (data then error correction) before it is laid in.
func qrPaintTampered(t *testing.T, v, mask int, data []byte, blockSizes []int, ecPer int, tamper func(stream []byte)) []string {
	t.Helper()
	n := 17 + 4*v
	dark := make([][]bool, n)
	taken := make([][]bool, n)
	for i := range dark {
		dark[i], taken[i] = make([]bool, n), make([]bool, n)
	}
	set := func(r, c int, d bool) { dark[r][c], taken[r][c] = d, true }

	finder := []string{"1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111"}
	for _, origin := range [][2]int{{0, 0}, {0, n - 7}, {n - 7, 0}} {
		for r := -1; r <= 7; r++ { // the light separator is the ring around it
			for c := -1; c <= 7; c++ {
				rr, cc := origin[0]+r, origin[1]+c
				if rr < 0 || cc < 0 || rr >= n || cc >= n {
					continue
				}
				set(rr, cc, r >= 0 && r < 7 && c >= 0 && c < 7 && finder[r][c] == '1')
			}
		}
	}
	for i := 8; i < n-8; i++ {
		set(6, i, i%2 == 0)
		set(i, 6, i%2 == 0)
	}
	centres := map[int][]int{1: nil, 5: {6, 30}, 7: {6, 22, 38}, 10: {6, 28, 50}}[v]
	for _, r := range centres {
		for _, c := range centres {
			if (r < 8 && c < 8) || (r < 8 && c > n-9) || (r > n-9 && c < 8) {
				continue // would sit on a finder
			}
			for dr := -2; dr <= 2; dr++ {
				for dc := -2; dc <= 2; dc++ {
					ring := max(dr, -dr, dc, -dc)
					set(r+dr, c+dc, ring != 1)
				}
			}
		}
	}
	set(n-8, 8, true) // the dark module

	// Format information, both copies, from the literal table.
	fw := [8]int{
		0b101010000010010, 0b101000100100101, 0b101111001111100, 0b101101101001011,
		0b100010111111001, 0b100000011001110, 0b100111110010111, 0b100101010100000,
	}[mask]
	for i := range 15 { // bit i, least significant first
		d := fw>>i&1 == 1
		switch {
		case i < 6:
			set(i, 8, d)
		case i == 6:
			set(7, 8, d)
		case i == 7:
			set(8, 8, d)
		case i == 8:
			set(8, 7, d)
		default:
			set(8, 14-i, d)
		}
		if i < 8 {
			set(8, n-1-i, d)
		} else {
			set(n-15+i, 8, d)
		}
	}
	if v >= 7 {
		vw := map[int]int{7: 0x07C94, 10: 0x0A4D3}[v]
		for i := range 18 {
			d := vw>>i&1 == 1
			set(i/3, n-11+i%3, d)
			set(n-11+i%3, i/3, d)
		}
	}

	// Interleave: data round-robin over the blocks, then each block's
	// error-correction codewords the same way.
	var stream []byte
	offset := make([]int, len(blockSizes))
	for b := 1; b < len(blockSizes); b++ {
		offset[b] = offset[b-1] + blockSizes[b-1]
	}
	for i := range slices.Max(blockSizes) {
		for b, s := range blockSizes {
			if i < s {
				stream = append(stream, data[offset[b]+i])
			}
		}
	}
	ecs := make([][]byte, len(blockSizes))
	for b, s := range blockSizes {
		ecs[b] = qrRSRemainder(data[offset[b]:offset[b]+s], ecPer)
	}
	for i := range ecPer {
		for b := range blockSizes {
			stream = append(stream, ecs[b][i])
		}
	}
	if tamper != nil {
		tamper(stream)
	}

	// Lay the bits in: right to left in column pairs, the timing column
	// skipped, direction alternating, starting upward.
	next := 0
	bit := func() bool {
		if next >= len(stream)*8 {
			next++
			return false // remainder bits are zero
		}
		d := stream[next/8]>>(7-next%8)&1 == 1
		next++
		return d
	}
	upward := true
	for right := n - 1; right > 0; right -= 2 {
		if right == 6 {
			right--
		}
		for k := range n {
			r := k
			if upward {
				r = n - 1 - k
			}
			for _, c := range []int{right, right - 1} {
				if !taken[r][c] {
					d := bit()
					if qrMaskBit(mask, r, c) {
						d = !d
					}
					dark[r][c] = d
				}
			}
		}
		upward = !upward
	}

	rows := make([]string, n)
	for r := range rows {
		var sb strings.Builder
		for c := range n {
			if dark[r][c] {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('0')
			}
		}
		rows[r] = sb.String()
	}
	return rows
}

// TestQRReadHandBuiltSymbols reads symbols painted by qrPaint: version
// 1 from a stream written out in hex by hand, then multi-block versions
// that exercise de-interleaving (5: two equal blocks; 10: four blocks of
// 43 and one of 44, with the 16-bit count) and the version bits (7, 10).
func TestQRReadHandBuiltSymbols(t *testing.T) {
	// "HELLO": 0100 | 00000101 | 48 45 4C 4C 4F | 0000 -> 40 54 84 54 C4 C4 F0,
	// then pad bytes EC 11 to the version's 16 data codewords.
	hello := []byte{0x40, 0x54, 0x84, 0x54, 0xC4, 0xC4, 0xF0, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC}
	if got := qrByteModeData([]byte("HELLO"), 8, 16); string(got) != string(hello) {
		t.Fatalf("data helper gave % X, the hand-written stream is % X", got, hello)
	}

	long := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*7 + 3)
		}
		return b
	}
	tests := []struct {
		name       string
		v, mask    int
		data       []byte
		payload    []byte
		blockSizes []int
		ecPer      int
	}{
		{"v1 HELLO mask 2", 1, 2, hello, []byte("HELLO"), []int{16}, 10},
		{"v5 two blocks mask 5", 5, 5, qrByteModeData([]byte("otpauth://totp/Gate:bob?secret=ABCDEFGH&issuer=Gate;0123456789"), 8, 86),
			[]byte("otpauth://totp/Gate:bob?secret=ABCDEFGH&issuer=Gate;0123456789"), []int{43, 43}, 24},
		{"v7 four blocks, version bits, mask 7", 7, 7, qrByteModeData(long(100), 8, 124), long(100), []int{31, 31, 31, 31}, 18},
		{"v10 unequal groups, 16-bit count, mask 3", 10, 3, qrByteModeData(long(150), 16, 216), long(150), []int{43, 43, 43, 43, 44}, 26},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows := qrPaint(t, tc.v, tc.mask, tc.data, tc.blockSizes, tc.ecPer)
			got, err := qrRead(rows)
			if err != nil {
				t.Fatalf("qrRead: %v", err)
			}
			if got.Version != tc.v || got.Level != 'M' || got.Mask != tc.mask {
				t.Errorf("read version %d level %c mask %d, want %d M %d", got.Version, got.Level, got.Mask, tc.v, tc.mask)
			}
			if string(got.Payload) != string(tc.payload) {
				t.Errorf("payload = % X, want % X", got.Payload, tc.payload)
			}
		})
	}
}

// TestQRReadRefusesWhatIsNotACleanByteModeLevelMCode.
func TestQRReadRefusesWhatIsNotACleanByteModeLevelMCode(t *testing.T) {
	hello := qrByteModeData([]byte("HELLO"), 8, 16)
	good := qrPaint(t, 1, 2, hello, []int{16}, 10)
	if _, err := qrRead(good); err != nil {
		t.Fatalf("the control symbol does not read: %v", err)
	}
	flip := func(rows []string, r, c int) []string {
		out := slices.Clone(rows)
		b := []byte(out[r])
		b[c] ^= 1 // '0' <-> '1'
		out[r] = string(b)
		return out
	}
	badChar := slices.Clone(good)
	badChar[3] = strings.Replace(badChar[3], "1", "x", 1)
	for name, rows := range map[string][]string{
		"one format copy altered":    flip(good, 8, 0),
		"the other copy altered":     flip(good, 20, 8),
		"not square":                 good[:20],
		"a character that is no bit": badChar,
	} {
		if _, err := qrRead(rows); err == nil {
			t.Errorf("%s: qrRead succeeded, want an error", name)
		}
	}
	// A different mode indicator: numeric (0001) in place of byte.
	numeric := slices.Clone(hello)
	numeric[0] = numeric[0]&0x0F | 0x10
	if _, err := qrRead(qrPaint(t, 1, 2, numeric, []int{16}, 10)); err == nil {
		t.Error("a numeric-mode symbol was read as byte mode")
	}
}

// TestQRReedSolomonMatchesTheStandardExample pins qrRSRemainder to the
// ISO/IEC 18004 Annex I example: version 1-M, "01234567" (numeric mode:
// 0001, count 8, then the digits -> 10 20 0C 56 61 80, padded EC 11).
func TestQRReedSolomonMatchesTheStandardExample(t *testing.T) {
	data := []byte{0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11}
	want := []byte{0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55}
	if got := qrRSRemainder(data, 10); !bytes.Equal(got, want) {
		t.Errorf("EC = % X, want % X", got, want)
	}
}

// TestQRReadRefusesAWrongErrorCorrectionCodeword flips one EC codeword
// of a valid symbol, in a single-block and a multi-block version.
func TestQRReadRefusesAWrongErrorCorrectionCodeword(t *testing.T) {
	hello := qrByteModeData([]byte("HELLO"), 8, 16)
	if _, err := qrRead(qrPaintTampered(t, 1, 2, hello, []int{16}, 10, nil)); err != nil {
		t.Fatalf("control symbol: %v", err)
	}
	rows := qrPaintTampered(t, 1, 2, hello, []int{16}, 10, func(s []byte) { s[len(s)-1] ^= 0x01 })
	if _, err := qrRead(rows); err == nil {
		t.Error("v1: a flipped EC codeword was accepted")
	}
	data := qrByteModeData([]byte("otpauth://totp/Gate:bob?secret=ABCDEFGH&issuer=Gate;0123456789"), 8, 86)
	rows = qrPaintTampered(t, 5, 5, data, []int{43, 43}, 24, func(s []byte) { s[86+5] ^= 0x80 })
	if _, err := qrRead(rows); err == nil {
		t.Error("v5: a flipped EC codeword was accepted")
	}
}
