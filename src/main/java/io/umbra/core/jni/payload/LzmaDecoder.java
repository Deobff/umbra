package io.umbra.core.jni.payload;

import java.io.IOException;

/**
 * LZMA symbol decoder: literals, matches and rep-matches.
 *
 * <p>Ported from the reference implementation's {@code LzmaDecoder}. The state
 * transitions (0..11), the {@code distSlot} layout, the direct-bit loop and the
 * aligned distance bits all come straight from the LZMA specification; they are
 * reproduced unchanged because a single off-by-one silently produces wrong
 * bytes for every match after it.</p>
 */
public final class LzmaDecoder extends LzmaState {

    final LzDictionary dict;
    final RangeDecoder rc;
    private final DistanceDecoder literalDecoder;
    private final LengthDecoder matchLenDecoder = new LengthDecoder(this);
    private final LengthDecoder repLenDecoder = new LengthDecoder(this);

    public LzmaDecoder(LzDictionary dict, RangeDecoder rc, int lc, int lp, int pb) {
        super(pb);
        this.dict = dict;
        this.rc = rc;
        this.literalDecoder = new DistanceDecoder(this, lc, lp);
        this.reset();
    }

    @Override
    public void reset() {
        super.reset();
        this.literalDecoder.reset();
        this.matchLenDecoder.reset();
        this.repLenDecoder.reset();
    }

    /** Decodes until {@code dict.pos == dict.limit}. */
    public void decode() throws IOException {
        if (this.dict.pendingLen > 0) {
            this.dict.repeat(this.dict.pendingDist, this.dict.pendingLen);
        }
        while (this.dict.pos < this.dict.limit) {
            int posState = this.dict.pos & this.posMask;
            if (this.rc.decodeBit(this.isMatch[this.state.state], posState) == 0) {
                decodeLiteral();
                continue;
            }
            int len;
            if (this.rc.decodeBit(this.isRep, this.state.state) == 0) {
                len = decodeMatch(posState);
            } else {
                len = decodeRepMatch(posState);
            }
            this.dict.repeat(this.reps[0], len);
        }
        this.rc.normalize();
    }

    private void decodeLiteral() throws IOException {
        int i = ((this.dict.getByte(0) >> (8 - this.literalDecoder.lc))
                + ((this.dict.pos & this.literalDecoder.posMask) << this.literalDecoder.lc));
        BitTreeDecoder subcoder = this.literalDecoder.subcoders[i];
        int symbol = 1;
        if (this.state.state < 7) {
            do {
                symbol = (symbol << 1) | this.rc.decodeBit(subcoder.probs, symbol);
            } while (symbol < 256);
        } else {
            int matchByte = this.dict.getByte(this.reps[0]);
            int offset = 256;
            do {
                matchByte <<= 1;
                int matchBit = matchByte & offset;
                int bit = this.rc.decodeBit(subcoder.probs, offset + matchBit + symbol);
                symbol = (symbol << 1) | bit;
                offset &= (0 - bit) ^ ~matchBit;
            } while (symbol < 256);
        }
        this.dict.buf[this.dict.pos++] = (byte) symbol;
        if (this.dict.full < this.dict.pos) {
            this.dict.full = this.dict.pos;
        }
        if (this.state.state <= 3) {
            this.state.state = 0;
        } else if (this.state.state <= 9) {
            this.state.state -= 3;
        } else {
            this.state.state -= 6;
        }
    }

    private int decodeMatch(int posState) throws IOException {
        this.state.state = this.state.state < 7 ? 7 : 10;
        this.reps[3] = this.reps[2];
        this.reps[2] = this.reps[1];
        this.reps[1] = this.reps[0];
        int len = this.matchLenDecoder.decode(posState);
        int distSlot = this.rc.decodeBitTree(this.distSlots[len < 6 ? len - 2 : 3]);
        if (distSlot < 4) {
            this.reps[0] = distSlot;
        } else {
            int limit = (distSlot >> 1) - 1;
            this.reps[0] = (2 | (distSlot & 1)) << limit;
            if (distSlot < 14) {
                this.reps[0] |= this.rc.decodeReverseBitTree(this.distSpecial[distSlot - 4]);
            } else {
                int count = limit - 4;
                int directBits = 0;
                do {
                    this.rc.normalize();
                    this.rc.range >>>= 1;
                    int t = (this.rc.code - this.rc.range) >>> 31;
                    this.rc.code -= this.rc.range & (t - 1);
                    directBits = (directBits << 1) | (1 - t);
                } while (--count != 0);
                this.reps[0] |= directBits << 4;
                this.reps[0] |= this.rc.decodeReverseBitTree(this.distAlign);
            }
        }
        return len;
    }

    private int decodeRepMatch(int posState) throws IOException {
        if (this.rc.decodeBit(this.isRep0, this.state.state) == 0) {
            if (this.rc.decodeBit(this.isRep0Long[this.state.state], posState) == 0) {
                this.state.state = this.state.state < 7 ? 9 : 11;
                return 1;
            }
        } else {
            int dist;
            if (this.rc.decodeBit(this.isRep1, this.state.state) == 0) {
                dist = this.reps[1];
            } else {
                if (this.rc.decodeBit(this.isRep2, this.state.state) == 0) {
                    dist = this.reps[2];
                } else {
                    dist = this.reps[3];
                    this.reps[3] = this.reps[2];
                }
                this.reps[2] = this.reps[1];
            }
            this.reps[1] = this.reps[0];
            this.reps[0] = dist;
        }
        this.state.state = this.state.state < 7 ? 8 : 11;
        return this.repLenDecoder.decode(posState);
    }
}
