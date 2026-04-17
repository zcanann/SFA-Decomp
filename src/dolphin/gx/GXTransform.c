#include <dolphin/gx.h>
#include <dolphin/mtx.h>
#include <dolphin/os.h>

#include "dolphin/gx/__gx.h"

#define gx __GXData

extern u32 __cvt_fp2unsigned(f64 d);

void GXSetProjection(const Mtx44 mtx, GXProjectionType type) {
    u32 reg;

    CHECK_GXBEGIN(295, "GXSetProjection");

    gx->projType = type;
    gx->projMtx[0] = mtx[0][0];
    gx->projMtx[2] = mtx[1][1];
    gx->projMtx[4] = mtx[2][2];
    gx->projMtx[5] = mtx[2][3];
    if (type == GX_ORTHOGRAPHIC) {
        gx->projMtx[1] = mtx[0][3];
        gx->projMtx[3] = mtx[1][3];
    } else {
        gx->projMtx[1] = mtx[0][2];
        gx->projMtx[3] = mtx[1][2];
    }

    reg = 0x00061020;
    GX_WRITE_U8(0x10);
    GX_WRITE_U32(reg);
    GX_WRITE_F32(gx->projMtx[0]);
    GX_WRITE_F32(gx->projMtx[1]);
    GX_WRITE_F32(gx->projMtx[2]);
    GX_WRITE_F32(gx->projMtx[3]);
    GX_WRITE_F32(gx->projMtx[4]);
    GX_WRITE_F32(gx->projMtx[5]);
    GX_WRITE_U32(gx->projType);
    gx->bpSentNot = 1;
}

#define qr0 0

static asm void WriteMTXPS4x3(register const f32 mtx[3][4], register volatile f32* dest) {
    psq_l f0, 0x00(mtx), 0, qr0
    psq_l f1, 0x08(mtx), 0, qr0
    psq_l f2, 0x10(mtx), 0, qr0
    psq_l f3, 0x18(mtx), 0, qr0
    psq_l f4, 0x20(mtx), 0, qr0
    psq_l f5, 0x28(mtx), 0, qr0
    psq_st f0, 0(dest), 0, qr0
    psq_st f1, 0(dest), 0, qr0
    psq_st f2, 0(dest), 0, qr0
    psq_st f3, 0(dest), 0, qr0
    psq_st f4, 0(dest), 0, qr0
    psq_st f5, 0(dest), 0, qr0
}

static asm void WriteMTXPS3x3from3x4(register const f32 mtx[3][4], register volatile f32* dest) {
    psq_l f0, 0x00(mtx), 0, qr0
    lfs   f1, 0x08(mtx)
    psq_l f2, 0x10(mtx), 0, qr0
    lfs   f3, 0x18(mtx)
    psq_l f4, 0x20(mtx), 0, qr0
    lfs   f5, 0x28(mtx)
    psq_st f0, 0(dest), 0, qr0
    stfs  f1, 0(dest)
    psq_st f2, 0(dest), 0, qr0
    stfs  f3, 0(dest)
    psq_st f4, 0(dest), 0, qr0
    stfs  f5, 0(dest)
}

static asm void WriteMTXPS4x2(register const f32 mtx[2][4], register volatile f32* dest) {
    psq_l f0, 0x00(mtx), 0, qr0
    psq_l f1, 0x08(mtx), 0, qr0
    psq_l f2, 0x10(mtx), 0, qr0
    psq_l f3, 0x18(mtx), 0, qr0
    psq_st f0, 0(dest), 0, qr0
    psq_st f1, 0(dest), 0, qr0
    psq_st f2, 0(dest), 0, qr0
    psq_st f3, 0(dest), 0, qr0
}

#define GX_WRITE_MTX_ELEM(addr, value) \
do { \
    f32 xfData = (value); \
    GX_WRITE_F32(value); \
    VERIF_MTXLIGHT((addr), *(u32*)&xfData); \
} while (0)

void GXLoadPosMtxImm(const Mtx mtx, u32 id) {
    u32 reg;
    u32 addr;

    CHECK_GXBEGIN(507, "GXLoadPosMtxImm");

    addr = id * 4;
    reg = addr | 0xB0000;

    GX_WRITE_U8(0x10);
    GX_WRITE_U32(reg);
#if DEBUG
    GX_WRITE_MTX_ELEM(addr + 0, mtx[0][0]);
    GX_WRITE_MTX_ELEM(addr + 1, mtx[0][1]);
    GX_WRITE_MTX_ELEM(addr + 2, mtx[0][2]);
    GX_WRITE_MTX_ELEM(addr + 3, mtx[0][3]);
    GX_WRITE_MTX_ELEM(addr + 4, mtx[1][0]);
    GX_WRITE_MTX_ELEM(addr + 5, mtx[1][1]);
    GX_WRITE_MTX_ELEM(addr + 6, mtx[1][2]);
    GX_WRITE_MTX_ELEM(addr + 7, mtx[1][3]);
    GX_WRITE_MTX_ELEM(addr + 8, mtx[2][0]);
    GX_WRITE_MTX_ELEM(addr + 9, mtx[2][1]);
    GX_WRITE_MTX_ELEM(addr + 10, mtx[2][2]);
    GX_WRITE_MTX_ELEM(addr + 11, mtx[2][3]);
#else
    WriteMTXPS4x3(mtx, &GXWGFifo.f32);
#endif
}

void GXLoadNrmMtxImm(const Mtx mtx, u32 id) {
    u32 reg;
    u32 addr;

    CHECK_GXBEGIN(588, "GXLoadNrmMtxImm");

    addr = id * 3 + 0x400;
    reg = addr | 0x80000;

    GX_WRITE_U8(0x10);
    GX_WRITE_U32(reg);
#if DEBUG
    GX_WRITE_MTX_ELEM(addr + 0, mtx[0][0]);
    GX_WRITE_MTX_ELEM(addr + 1, mtx[0][1]);
    GX_WRITE_MTX_ELEM(addr + 2, mtx[0][2]);
    GX_WRITE_MTX_ELEM(addr + 3, mtx[1][0]);
    GX_WRITE_MTX_ELEM(addr + 4, mtx[1][1]);
    GX_WRITE_MTX_ELEM(addr + 5, mtx[1][2]);
    GX_WRITE_MTX_ELEM(addr + 6, mtx[2][0]);
    GX_WRITE_MTX_ELEM(addr + 7, mtx[2][1]);
    GX_WRITE_MTX_ELEM(addr + 8, mtx[2][2]);
#else
    WriteMTXPS3x3from3x4(mtx, &GXWGFifo.f32);
#endif
}

void GXSetCurrentMtx(u32 id) {
    CHECK_GXBEGIN(708, "GXSetCurrentMtx");
    SET_REG_FIELD(708, gx->matIdxA, 6, 0, id);
    __GXSetMatrixIndex(GX_VA_PNMTXIDX);
}

void GXLoadTexMtxImm(const f32 mtx[][4], u32 id, GXTexMtxType type) {
    u32 reg;
    u32 addr;
    u32 count;

    CHECK_GXBEGIN(741, "GXLoadTexMtxImm");

    if (id >= GX_PTTEXMTX0) {
        addr = (id - GX_PTTEXMTX0) * 4 + 0x500;
        ASSERTMSGLINE(751, type == GX_MTX3x4, "GXLoadTexMtx: Invalid matrix type");
    } else {
        addr = id * 4;
    }
    count = (type == GX_MTX2x4) ? 8 : 12;
    reg = addr | ((count - 1) << 16);

    GX_WRITE_U8(0x10);
    GX_WRITE_U32(reg);
#if DEBUG
    GX_WRITE_MTX_ELEM(addr + 0, mtx[0][0]);
    GX_WRITE_MTX_ELEM(addr + 1, mtx[0][1]);
    GX_WRITE_MTX_ELEM(addr + 2, mtx[0][2]);
    GX_WRITE_MTX_ELEM(addr + 3, mtx[0][3]);
    GX_WRITE_MTX_ELEM(addr + 4, mtx[1][0]);
    GX_WRITE_MTX_ELEM(addr + 5, mtx[1][1]);
    GX_WRITE_MTX_ELEM(addr + 6, mtx[1][2]);
    GX_WRITE_MTX_ELEM(addr + 7, mtx[1][3]);
    if (type == GX_MTX3x4) {
        GX_WRITE_MTX_ELEM(addr + 8, mtx[2][0]);
        GX_WRITE_MTX_ELEM(addr + 9, mtx[2][1]);
        GX_WRITE_MTX_ELEM(addr + 10, mtx[2][2]);
        GX_WRITE_MTX_ELEM(addr + 11, mtx[2][3]);
    }
#else
    if (type == GX_MTX3x4) {
        WriteMTXPS4x3(mtx, &GXWGFifo.f32);
    } else {
        WriteMTXPS4x2(mtx, &GXWGFifo.f32);
    }
#endif
}

#pragma dont_inline on
/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
void GXSetViewportJitter(f32 left, f32 top, f32 wd, f32 ht, f32 nearz, f32 farz, u32 field) {
    f32 sx;
    f32 sy;
    f32 sz;
    f32 ox;
    f32 oy;
    f32 oz;
    f32 zmin;
    f32 zmax;
    u32 reg;

    CHECK_GXBEGIN(903, "GXSetViewport");  // not the correct function name

    if (field == 0) {
        top -= 0.5f;
    }

    sx = wd / 2.0f;
    sy = -ht / 2.0f;
    ox = 342.0f + (left + (wd / 2.0f));
    oy = 342.0f + (top + (ht / 2.0f));
    zmin = 1.6777215e7f * nearz;
    zmax = 1.6777215e7f * farz;
    sz = zmax - zmin;
    oz = zmax;
    __GXData->vpLeft = left;
    __GXData->vpTop = top;
    __GXData->vpWd = wd;
    __GXData->vpHt = ht;
    __GXData->vpNearz = nearz;
    __GXData->vpFarz = farz;

    if (__GXData->fgRange != 0) {
        __GXSetRange(nearz, __GXData->fgSideX);
    }

    reg = 0x5101A;
    GX_WRITE_U8(0x10);
    GX_WRITE_U32(reg);
    GX_WRITE_XF_REG_F(26, sx);
    GX_WRITE_XF_REG_F(27, sy);
    GX_WRITE_XF_REG_F(28, sz);
    GX_WRITE_XF_REG_F(29, ox);
    GX_WRITE_XF_REG_F(30, oy);
    GX_WRITE_XF_REG_F(31, oz);
    __GXData->bpSentNot = 1;
}

#pragma dont_inline reset

void GXSetViewport(f32 left, f32 top, f32 wd, f32 ht, f32 nearz, f32 farz) {
    GXSetViewportJitter(left, top, wd, ht, nearz, farz, 1);
}

void GXSetScissor(u32 left, u32 top, u32 wd, u32 ht) {
    u32 topOrigin;
    u32 leftOrigin;
    u32 bottom;
    u32 right;

    CHECK_GXBEGIN(1048, "GXSetScissor");
    ASSERTMSGLINE(1049, left < 1706, "GXSetScissor: Left origin > 1708");
    ASSERTMSGLINE(1050, top < 1706, "GXSetScissor: top origin > 1708");
    ASSERTMSGLINE(1051, left + wd < 1706, "GXSetScissor: right edge > 1708");
    ASSERTMSGLINE(1052, top + ht < 1706, "GXSetScissor: bottom edge > 1708");

    leftOrigin = left + 0x156;
    topOrigin = top + 0x156;
    right = (leftOrigin + wd) - 1;
    bottom = (topOrigin + ht) - 1;

    __GXData->suScis0 = (__GXData->suScis0 & 0xFFFFF800) | topOrigin;
    __GXData->suScis0 = (__GXData->suScis0 & 0xFF800FFF) | (leftOrigin << 12);
    __GXData->suScis1 = (__GXData->suScis1 & 0xFFFFF800) | bottom;
    __GXData->suScis1 = (__GXData->suScis1 & 0xFF800FFF) | (right << 12);

    GX_WRITE_RAS_REG(__GXData->suScis0);
    GX_WRITE_RAS_REG(__GXData->suScis1);
    __GXData->bpSentNot = 0;
}

void GXGetScissor(u32* left, u32* top, u32* wd, u32* ht) {
    u32 suScis0;
    u32 suScis1;
    u32 topOrigin;
    u32 leftOrigin;
    u32 bottom;
    u32 right;

    suScis0 = __GXData->suScis0;
    suScis1 = __GXData->suScis1;

    topOrigin = suScis0 & 0x7FF;
    leftOrigin = (suScis0 >> 12) & 0x7FF;
    bottom = suScis1 & 0x7FF;
    right = (suScis1 >> 12) & 0x7FF;

    *left = leftOrigin - 0x156;
    *top = topOrigin - 0x156;
    *wd = (right - leftOrigin) + 1;
    *ht = (bottom - topOrigin) + 1;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
void GXSetScissorBoxOffset(s32 x_off, s32 y_off) {
    u32 reg;

    CHECK_GXBEGIN(1119, "GXSetScissorBoxOffset");

    ASSERTMSGLINE(1122, (u32)(x_off + 342) < 2048, "GXSetScissorBoxOffset: Invalid X offset");
    ASSERTMSGLINE(1124, (u32)(y_off + 342) < 2048, "GXSetScissorBoxOffset: Invalid Y offset");

    x_off += 0x156;
    y_off += 0x156;
    x_off = ((u32)x_off >> 1) & 0xFFF003FF;
    y_off = (y_off << 9) & 0xFFFFFC00;
    reg = ((u32)x_off | (u32)y_off) & 0x00FFFFFF;
    reg |= 0x59000000;
    GX_WRITE_RAS_REG(reg);
    __GXData->bpSentNot = 0;
}

void GXSetClipMode(GXClipMode mode) {
    CHECK_GXBEGIN(1151, "GXSetClipMode");
    GX_WRITE_XF_REG(5, mode);
    __GXData->bpSentNot = 1;
}

void __GXSetMatrixIndex(GXAttr matIdxAttr) {
    if (matIdxAttr < GX_VA_TEX4MTXIDX) {
        GX_WRITE_SOME_REG4(8, 0x30, __GXData->matIdxA, -12);
        GX_WRITE_XF_REG(24, __GXData->matIdxA);
    } else {
        GX_WRITE_SOME_REG4(8, 0x40, __GXData->matIdxB, -12);
        GX_WRITE_XF_REG(25, __GXData->matIdxB);
    }

    __GXData->bpSentNot = GX_TRUE;
}
