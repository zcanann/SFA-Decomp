#include "main/engine_shared.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/floorf.h"

extern f32 lbl_803DE544;

int getLActions(int a, int b, u16 idx)
{
    void* buf = mmAlloc(0x28, -1, NULL);
    getTabEntry(buf, 0xc, idx * 0x28, 0x28);
    mm_free(buf);
    return 0;
}

#pragma dont_inline on
void render_copyPackedU64Tail(u64* dst, u32 packed)
{
    /* Preserve bytes before the unaligned source offset; fill the tail from
       the aligned 64-bit word. */
    u64 src = *(u64*)(packed & ~7);

    switch (packed & 7)
    {
    case 0: *dst = src;
        break;
    case 1: *dst = (*dst & 0xff00000000000000ULL) | (src >> 8);
        break;
    case 2: *dst = (*dst & 0xffff000000000000ULL) | (src >> 16);
        break;
    case 3: *dst = (*dst & 0xffffff0000000000ULL) | (src >> 24);
        break;
    case 4: *dst = (*dst & 0xffffffff00000000ULL) | (src >> 32);
        break;
    case 5: *dst = (*dst & 0xffffffffff000000ULL) | (src >> 40);
        break;
    case 6: *dst = (*dst & 0xffffffffffff0000ULL) | (src >> 48);
        break;
    case 7: *dst = (*dst & 0xffffffffffffff00ULL) | (src >> 56);
        break;
    }
}
#pragma dont_inline reset

#pragma dont_inline on
void render_copyPackedU64Head(u64* dst, u32 packed)
{
    /* Fill the head from the aligned 64-bit word; preserve bytes after the
       unaligned source offset. */
    u64 src = *(u64*)(packed & ~7);

    switch (packed & 7)
    {
    case 0: *dst = src;
        break;
    case 1: *dst = (*dst & 0xffULL) | (src << 8);
        break;
    case 2: *dst = (*dst & 0xffffULL) | (src << 16);
        break;
    case 3: *dst = (*dst & 0xffffffULL) | (src << 24);
        break;
    case 4: *dst = (*dst & 0xffffffffULL) | (src << 32);
        break;
    case 5: *dst = (*dst & 0xffffffffffULL) | (src << 40);
        break;
    case 6: *dst = (*dst & 0xffffffffffffULL) | (src << 48);
        break;
    case 7: *dst = (*dst & 0xffffffffffffffULL) | (src << 56);
        break;
    }
}
#pragma dont_inline reset

int getEnvfxActImmediately(int a, int b, u16 idx, int d)
{
    u8 raw[0x80];
    EnvfxActEntry* e = (EnvfxActEntry*)(((u32)raw + 0x1f) & ~0x1f);

    getTabEntry(e, 0x57, idx * 0x60, 0x60);
    if (e != NULL)
    {
        if (e->kind <= 2 || e->kind == 4)
        {
            (*gNewCloudsInterface)->updateEnvfxAct(a, b, e, d);
        }
        else if (e->kind == 3)
        {
            e->field_2a = 0;
            (*gSky2Interface)->updateEnvfxAct(a, b, e, d, idx);
        }
        else if (e->kind == 5)
        {
            e->field_2a = 0;
            (*gSkyInterface)->updateEnvfxAct(a, b, e, d);
        }
        else if (e->kind == 6)
        {
            (*gCloudActionInterface)->updateEnvfxAct(a, b, e, d, idx);
        }
    }
    return 0;
}

int getEnvfxAct(int a, int b, u16 idx, int d)
{
    u8 raw[0x80];
    EnvfxActEntry* e = (EnvfxActEntry*)(((u32)raw + 0x1f) & ~0x1f);

    getTabEntry(e, 0x57, idx * 0x60, 0x60);
    if (e != NULL)
    {
        if (e->kind <= 2 || e->kind == 4)
        {
            (*gNewCloudsInterface)->updateEnvfxAct(a, b, e, d);
        }
        else if (e->kind == 3)
        {
            (*gSky2Interface)->updateEnvfxAct(a, b, e, d, idx);
        }
        else if (e->kind == 5)
        {
            (*gSkyInterface)->updateEnvfxAct(a, b, e, d);
        }
        else if (e->kind == 6)
        {
            (*gCloudActionInterface)->updateEnvfxAct(a, b, e, d, idx);
        }
    }
    return 0;
}

u8* modelRenderFn_80006744(u8* p, int count, ModelRenderInstrsState* state, int gap, u8 bw)
{
    int acc;
    int bitWidth = bw;
    int idx;
    int initialBit;
    int sh16;
    int shamt = bitWidth - 4;
    int hi = (*p >> 4) & 0xf;
    int i;

    if (shamt < 0)
    {
        shamt = 0;
    }
    hi = hi << shamt;
    acc = hi;
    {
        int lo = *(volatile u8*)p;
        p = p + 1;
        idx = (lo & 0xf) << 3;
    }
    initialBit = modelRenderInstrsState_getBit(state);
    gap = gap - bitWidth;
    sh16 = 0x10 - bitWidth;

    for (i = count / 2; i > 0; i--)
    {
        MODEL_DECODE_NIBBLE(*p & 0xf);
        MODEL_DECODE_NIBBLE((*p++ >> 4) & 0xf);
    }
    if (count & 1)
    {
        MODEL_DECODE_NIBBLE_TAIL(*p++ & 0xf);
    }
    if (gap != 0)
    {
        modelRenderInstrsState_setBit(state, initialBit + bitWidth);
    }
    return p;
}

#pragma scheduling off
int fn_80006B1C(ModelRenderInstrsState* src, ModelRenderInstrsState* dst, int count, int gap, u8 bitWidth)
{
    int startBit = modelRenderInstrsState_getBit(dst);
    int bw = bitWidth;
    u32 mask = ~(-1 << bw);
    int sh16 = 0x10 - bw;
    int i;
    for (i = 0; i < count; i++)
    {
        int sbit = src->bit;
        int sByte = sbit >> 3;
        u8* sp = (u8*)src->instrs + sByte;
        u8* dp;
        u32 val;
        int curBit;
        u32 packed;
        val = sp[0] << 16;
        val = val | (sp[1] << 8);
        val = val | sp[2];
        src->bit = sbit + bw;
        packed = mask & (val >> (sbit & 7));
        curBit = dst->bit;
        sByte = curBit >> 3;
        packed = packed << ((8 - (curBit & 7)) + sh16);
        dp = (u8*)dst->instrs;
        dp[sByte] |= (packed >> 16) & 0xff;
        dp = (u8*)dst->instrs;
        dp[sByte + 1] |= (packed >> 8) & 0xff;
        dp = (u8*)dst->instrs;
        dp[sByte + 2] |= packed & 0xff;
        dst->bit += bw;
        dst->bit += gap;
    }
    modelRenderInstrsState_setBit(dst, startBit + bw);
    {
        u8* base = (u8*)src->instrs;
        return base[(src->bit >> 3) + 1];
    }
}
#pragma scheduling reset

/* Refill the two parallel 64-bit bitstream windows from the next
   byte-aligned position once the consumed bit count overruns 64. */
#define RENDER_BITS_REFILL(nb)                       \
    bitpos -= (nb);                                  \
    bufA = bitpos >> 3;                              \
    posA += bufA;                                    \
    addrB = bufA + curB;                             \
    curB = addrB;                                    \
    bitpos &= 7;                                     \
    render_copyPackedU64Head(&bufA, posA);           \
    render_copyPackedU64Tail(&bufA, posA + 7);       \
    render_copyPackedU64Head(&bufB, addrB);          \
    render_copyPackedU64Tail(&bufB, addrB + 7);      \
    bufA <<= (bitpos & 0xFFFFFFFF);                  \
    bufB <<= (bitpos & 0xFFFFFFFF);                  \
    bitpos += (nb);

void fn_80007F78(u8* anim, u16* dst, u16* out)
{
    f32 t = *(f32*)(anim + 0x4);
    u64 outPos = (u32)out;
    int curB = *(u16*)(anim + 0x4c);
    u64 posA = *(u32*)(anim + 0x2c);
    u64 tp = *(u32*)(anim + 0x34) + 4;
    u64 end;
    u64 bufA;
    u64 bufB;
    s64 tmp;
    s64* q = &tmp;
    u64 bitpos;
    u64 vA;
    u32 addrB;
    u64 maskConst = 0xFFF0;
    int i;
    union { s64 v; int w[2]; } frac;

    addrB = posA + curB;
    curB = addrB;
    end = (u32)(dst + 3);
    t = t - floorf(t);
    t = t * lbl_803DE544;
    frac.v = (int)t;

    render_copyPackedU64Head(&bufA, posA);
    render_copyPackedU64Tail(&bufA, posA + 7);
    render_copyPackedU64Head(&bufB, addrB);
    render_copyPackedU64Tail(&bufB, addrB + 7);
    bitpos = 0;

    do
    {
        u64 sample = 0;
        u64 h = *(u16*)(u32)tp;
        u64 nib = h & 0xf;
        u32 hw = h;
        u64 masked = h & maskConst;

        if (nib != 0)
        {
            bitpos += nib;
            if ((s64)bitpos > 64)
            {
                RENDER_BITS_REFILL(nib)
            }
            tmp = 64 - nib;
            vA = bufA >> (tmp & 0xFFFFFFFF);
            tmp = bufB >> (tmp & 0xFFFFFFFF);
            tmp = tmp - vA;
            tmp = tmp << 50;
            for (i = 50; i != 0; i--)
            {
                *q /= 2;
            }
            tmp = tmp * frac.v;
            for (i = 14; i != 0; i--)
            {
                *q /= 2;
            }
            sample = masked + ((vA + tmp) << 2);
            bufA <<= (nib & 0xFFFFFFFF);
            bufB <<= (nib & 0xFFFFFFFF);
        }
        tp += 2;
        *(u16*)(u32)outPos = sample;
        outPos += 2;

        sample = 0;
        if (hw & 0x10)
        {
            u64 h2 = *(u16*)(u32)tp;
            u64 nib3;

            if ((h2 & 0x10) != 0)
            {
                u64 nib2 = h2 & 0xf;
                if (nib2 != 0)
                {
                    bitpos += nib2;
                    if ((s64)bitpos > 64)
                    {
                        RENDER_BITS_REFILL(nib2)
                    }
                    bufA <<= (nib2 & 0xFFFFFFFF);
                    bufB <<= (nib2 & 0xFFFFFFFF);
                }
                tp += 2;
                if (!((u32)h2 & 0x20))
                {
                    goto storeSecond;
                }
                h2 = *(u16*)(u32)tp;
            }
            nib3 = h2 & 0xf;
            if (nib3 != 0)
            {
                u64 masked2 = h2 & 0xFFF0;
                bitpos += nib3;
                if ((s64)bitpos > 64)
                {
                    RENDER_BITS_REFILL(nib3)
                }
                tmp = 64 - nib3;
                vA = bufA >> (tmp & 0xFFFFFFFF);
                tmp = bufB >> (tmp & 0xFFFFFFFF);
                tmp = tmp - vA;
                tmp = tmp * frac.v;
                for (i = 14; i != 0; i--)
                {
                    *q /= 2;
                }
                sample = masked2 + (vA + tmp);
                bufA <<= (nib3 & 0xFFFFFFFF);
                bufB <<= (nib3 & 0xFFFFFFFF);
            }
            tp += 2;
        }
    storeSecond:
        *dst = sample;
        dst++;
    }
    while ((u64)(u32)
    dst != end
    )
    ;
}

int return0xFFFF_80008B6C(void) { return -0x1; }

s16 renderModeSetOrGet(int mode)
{
    if (mode != -1)
    {
        gRenderMode = mode;
        return mode;
    }
    return gRenderMode;
}
