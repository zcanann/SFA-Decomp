#include <stddef.h>
#include <dolphin/gx.h>
#include <dolphin/os.h>

#include "dolphin/gx/__gx.h"

void __GXSetDirtyState(void) {
    if (__GXData->dirtyState & 1) {
        __GXSetSUTexRegs();
    }
    if (__GXData->dirtyState & 2) {
        __GXUpdateBPMask();
    }
    if (__GXData->dirtyState & 4) {
        __GXSetGenMode();
    }
    if (__GXData->dirtyState & 8) {
        __GXSetVCD();
    }
    if (__GXData->dirtyState & 0x10) {
        __GXSetVAT();
    }
    if (__GXData->dirtyState & 0x18) {
        __GXCalculateVLim();
    }

    __GXData->dirtyState = 0;
}

void GXBegin(GXPrimitive type, GXVtxFmt vtxfmt, u16 nverts) {
    ASSERTMSGLINE(359, vtxfmt < GX_MAX_VTXFMT,   "GXBegin: Format Index is out of range");
    ASSERTMSGLINE(360, !__GXinBegin, "GXBegin: called inside another GXBegin/GXEnd");

    if (__GXData->dirtyState != 0) {
        __GXSetDirtyState();
    }

#if DEBUG
    if (!__GXData->inDispList) {
        __GXVerifyState(vtxfmt);
    }
    __GXinBegin = 1;
#endif

    if (*(u32*)&__GXData->vNumNot == 0) {  // checks both vNum and bpSentNot
        __GXSendFlushPrim();
    }
    GX_WRITE_U8(vtxfmt | type);
    GX_WRITE_U16(nverts);
}

void __GXSendFlushPrim(void) {
    u32 i;
    u32 numD = __GXData->vNum * __GXData->vLim;

    GX_WRITE_U8(0x98);
    GX_WRITE_U16(__GXData->vNum);
    for (i = 0; i < numD; i += 4) {
        GX_WRITE_U32(0);
    }
    __GXData->bpSentNot = 1;
}

void GXSetLineWidth(u8 width, GXTexOffset texOffsets) {
    GXData* data;

    CHECK_GXBEGIN(440, "GXSetLineWidth");
    data = __GXData;
    data->lpSize = (data->lpSize & 0xFFFFFF00) | ((u32)width & 0xFF);
    data->lpSize = (data->lpSize & 0xFFF8FFFF) | ((u32)texOffsets << 16);
    GX_WRITE_RAS_REG(data->lpSize);
    data->bpSentNot = 0;
}

#if DEBUG
void GXGetLineWidth(u8* width, GXTexOffset* texOffsets) {
    ASSERTMSGLINE(463, width != NULL && texOffsets != NULL, "GXGet*: invalid null pointer");

    *width      = GET_REG_FIELD(__GXData->lpSize, 8, 0);
    *texOffsets = GET_REG_FIELD(__GXData->lpSize, 3, 16);
}
#endif

void GXSetPointSize(u8 pointSize, GXTexOffset texOffsets) {
    GXData* data;

    CHECK_GXBEGIN(484, "GXSetPointSize");
    data = __GXData;
    data->lpSize = (data->lpSize & 0xFFFF00FF) | (((u32)pointSize & 0xFF) << 8);
    data->lpSize = (data->lpSize & 0xFFC7FFFF) | ((u32)texOffsets << 19);
    GX_WRITE_RAS_REG(data->lpSize);
    data->bpSentNot = 0;
}

#if DEBUG
void GXGetPointSize(u8* pointSize, GXTexOffset* texOffsets) {
    ASSERTMSGLINE(507, pointSize != NULL && texOffsets != NULL, "GXGet*: invalid null pointer");

    *pointSize  = (int)GET_REG_FIELD(__GXData->lpSize, 8, 8);
    *texOffsets = GET_REG_FIELD(__GXData->lpSize, 3, 19);
}
#endif

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
void GXEnableTexOffsets(GXTexCoordID coord, u8 line_enable, u8 point_enable) {
    CHECK_GXBEGIN(529, "GXEnableTexOffsets");

    ASSERTMSGLINE(531, coord < GX_MAX_TEXCOORD, "GXEnableTexOffsets: Invalid coordinate Id");
    __GXData->suTs0[coord] = (__GXData->suTs0[coord] & 0xFFFBFFFF) | (((u32)line_enable & 0xFF) << 18);
    __GXData->suTs0[coord] = (__GXData->suTs0[coord] & 0xFFF7FFFF) | (((u32)point_enable & 0xFF) << 19);
    GX_WRITE_RAS_REG(__GXData->suTs0[coord]);
    __GXData->bpSentNot = 0;
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
void GXSetCullMode(GXCullMode mode) {
    u32 reg;

    CHECK_GXBEGIN(557, "GXSetCullMode");
#if DEBUG
    GXCullMode hwMode;

    switch (mode) {
    case GX_CULL_FRONT: hwMode = GX_CULL_BACK;  break;
    case GX_CULL_BACK:  hwMode = GX_CULL_FRONT; break;
    default:            hwMode = mode;          break;
    }
    SET_REG_FIELD(570, __GXData->genMode, 2, 14, hwMode);
#else
    switch (mode) {
    case GX_CULL_FRONT:
        mode = GX_CULL_BACK;
        break;
    case GX_CULL_BACK:
        mode = GX_CULL_FRONT;
        break;
    default:
        break;
    }

    reg = __GXData->genMode;
    __GXData->genMode = (reg & 0xFFFF3FFF) | ((u32)mode << 14);
#endif
    __GXData->dirtyState |= 4;
}

#if DEBUG
void GXGetCullMode(GXCullMode* mode) {
    GXCullMode hwMode = GET_REG_FIELD(__GXData->genMode, 2, 14);

    switch (hwMode) {
    case GX_CULL_FRONT: *mode = GX_CULL_BACK;  break;
    case GX_CULL_BACK:  *mode = GX_CULL_FRONT; break;
    default:            *mode = hwMode;        break;
    }
}
#endif

void GXSetCoPlanar(GXBool enable) {
    u32 reg;

    CHECK_GXBEGIN(613, "GXSetCoPlanar");

    reg = __GXData->genMode;
    reg = (reg & 0xFFF7FFFF) | ((u32)enable << 19);
    __GXData->genMode = reg;
    reg = 0xFE080000;
    GX_WRITE_RAS_REG(reg);
    GX_WRITE_RAS_REG(__GXData->genMode);
}

void __GXSetGenMode(void) {
    GX_WRITE_RAS_REG(__GXData->genMode);
    __GXData->bpSentNot = 0;
}
