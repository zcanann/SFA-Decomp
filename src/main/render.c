#include "ghidra_import.h"
#include "main/engine_shared.h"

#pragma scheduling off
#pragma peephole off
int getLActions(int a, int b, u16 idx)
{
    void* buf = mmAlloc(0x28, -1, NULL);
    getTabEntry(buf, 0xc, idx * 0x28, 0x28);
    mm_free(buf);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void fn_8000881C(u64 *dst, u32 packed)
{
    u64 src = *(u64 *)(packed & ~7);

    switch (packed & 7) {
    case 0: *dst = src; break;
    case 1: *dst = (src >> 8) | (*dst & 0xff00000000000000ULL); break;
    case 2: *dst = (src >> 16) | (*dst & 0xffff000000000000ULL); break;
    case 3: *dst = (src >> 24) | (*dst & 0xffffff0000000000ULL); break;
    case 4: *dst = (src >> 32) | (*dst & 0xffffffff00000000ULL); break;
    case 5: *dst = (src >> 40) | (*dst & 0xffffffffff000000ULL); break;
    case 6: *dst = (src >> 48) | (*dst & 0xffffffffffff0000ULL); break;
    case 7: *dst = (src >> 56) | (*dst & 0xffffffffffffff00ULL); break;
    }
}
#pragma scheduling reset

#pragma scheduling off
void fn_800089AC(u64 *dst, u32 packed)
{
    u64 src = *(u64 *)(packed & ~7);

    switch (packed & 7) {
    case 0: *dst = src; break;
    case 1: *dst = (src << 8) | (*dst & 0xffULL); break;
    case 2: *dst = (src << 16) | (*dst & 0xffffULL); break;
    case 3: *dst = (src << 24) | (*dst & 0xffffffULL); break;
    case 4: *dst = (src << 32) | (*dst & 0xffffffffULL); break;
    case 5: *dst = (src << 40) | (*dst & 0xffffffffffULL); break;
    case 6: *dst = (src << 48) | (*dst & 0xffffffffffffULL); break;
    case 7: *dst = (src << 56) | (*dst & 0xffffffffffffffULL); break;
    }
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int getEnvfxActImmediately(int a, int b, u16 idx, int d)
{
    u8 raw[0x80];
    EnvfxActEntry *e = (EnvfxActEntry *)(((u32)raw + 0x1f) & ~0x1f);

    getTabEntry(e, 0x57, idx * 0x60, 0x60);
    if (e != NULL) {
        if (e->kind <= 2 || e->kind == 4) {
            (*(void (*)(int, int, EnvfxActEntry *, int))(*(int *)(*gNewCloudsInterface + 0x4)))(a, b, e, d);
        } else if (e->kind == 3) {
            e->field_2a = 0;
            (*(void (*)(int, int, EnvfxActEntry *, int, u16))(*(int *)(*gSky2Interface + 0x4)))(a, b, e, d, idx);
        } else if (e->kind == 5) {
            e->field_2a = 0;
            (*(void (*)(int, int, EnvfxActEntry *, int))(*(int *)(*gSHthorntailAnimationInterface + 0x4)))(a, b, e, d);
        } else if (e->kind == 6) {
            (*(void (*)(int, int, EnvfxActEntry *, int, u16))(*(int *)(*gCloudActionInterface + 0x4)))(a, b, e, d, idx);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int getEnvfxAct(int a, int b, u16 idx, int d)
{
    u8 raw[0x80];
    EnvfxActEntry *e = (EnvfxActEntry *)(((u32)raw + 0x1f) & ~0x1f);

    getTabEntry(e, 0x57, idx * 0x60, 0x60);
    if (e != NULL) {
        if (e->kind <= 2 || e->kind == 4) {
            (*(void (*)(int, int, EnvfxActEntry *, int))(*(int *)(*gNewCloudsInterface + 0x4)))(a, b, e, d);
        } else if (e->kind == 3) {
            (*(void (*)(int, int, EnvfxActEntry *, int, u16))(*(int *)(*gSky2Interface + 0x4)))(a, b, e, d, idx);
        } else if (e->kind == 5) {
            (*(void (*)(int, int, EnvfxActEntry *, int))(*(int *)(*gSHthorntailAnimationInterface + 0x4)))(a, b, e, d);
        } else if (e->kind == 6) {
            (*(void (*)(int, int, EnvfxActEntry *, int, u16))(*(int *)(*gCloudActionInterface + 0x4)))(a, b, e, d, idx);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
u8 *modelRenderFn_80006744(u8 *p, int count, ModelRenderInstrsState *state, int stride, u8 bitWidth)
{
    int acc;
    int idx;
    u8 *cur;
    int initialBit;
    int gap;
    int sh16;
    int shamt = bitWidth - 4;
    int hi = (*p >> 4) & 0xf;
    int i;

    if (shamt < 0) {
        shamt = 0;
    }
    acc = hi << shamt;
    idx = (*p & 0xf) << 3;
    cur = p + 1;
    initialBit = modelRenderInstrsState_getBit(state);
    gap = stride - bitWidth;
    sh16 = 0x10 - bitWidth;

    for (i = count / 2; i > 0; i--) {
        MODEL_DECODE_NIBBLE(*cur & 0xf);
        MODEL_DECODE_NIBBLE((*cur >> 4) & 0xf);
        cur++;
    }
    if (count & 1) {
        MODEL_DECODE_NIBBLE(*cur & 0xf);
        cur++;
    }
    if (gap != 0) {
        modelRenderInstrsState_setBit(state, initialBit + bitWidth);
    }
    return cur;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80006B1C(ModelRenderInstrsState *src, ModelRenderInstrsState *dst, int count, int gap, u8 bitWidth)
{
    int startBit = modelRenderInstrsState_getBit(dst);
    int bw = bitWidth;
    u32 mask = ~(-1 << bw);
    int sh16 = 0x10 - bw;
    int i;
    for (i = 0; i < count; i++) {
        int sbit = src->bit;
        int sByte = sbit >> 3;
        u8 *sp = (u8 *)src->instrs + sByte;
        u32 val;
        int curBit;
        int bo;
        u32 packed;
        u32 bits;
        val = sp[0] << 16;
        val = val | (sp[1] << 8);
        val = val | sp[2];
        src->bit = sbit + bitWidth;
        bits = mask & (val >> (sbit & 7));
        curBit = dst->bit;
        bo = curBit >> 3;
        packed = bits << ((8 - (curBit & 7)) + sh16);
        ((u8 *)dst->instrs)[bo] |= (packed >> 16) & 0xff;
        ((u8 *)dst->instrs)[bo + 1] |= (packed >> 8) & 0xff;
        ((u8 *)dst->instrs)[bo + 2] |= packed & 0xff;
        dst->bit += bitWidth;
        dst->bit += gap;
    }
    modelRenderInstrsState_setBit(dst, startBit + bitWidth);
    return ((u8 *)src->instrs)[(src->bit >> 3) + 1];
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int return0xFFFF_80008B6C(void) { return -0x1; }
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
s16 renderModeSetOrGet(int mode)
{
    if (mode != -1) {
        gRenderMode = mode;
        return mode;
    }
    return gRenderMode;
}
#pragma peephole reset
#pragma scheduling reset
