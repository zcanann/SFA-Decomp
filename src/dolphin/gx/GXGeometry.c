#include <dolphin/gx.h>
#include <dolphin/os.h>

#include "dolphin/gx/__gx.h"

#define gx __GXData

void __GXSetDirtyState(void) {
    if (gx->dirtyState & 1) {
        __GXSetSUTexRegs();
    }
    if (gx->dirtyState & 2) {
        __GXUpdateBPMask();
    }
    if (gx->dirtyState & 4) {
        __GXSetGenMode();
    }
    if (gx->dirtyState & 8) {
        __GXSetVCD();
    }
    if (gx->dirtyState & 0x10) {
        __GXSetVAT();
    }
    if (gx->dirtyState & 0x18) {
        __GXCalculateVLim();
    }

    gx->dirtyState = 0;
}

void GXBegin(GXPrimitive type, GXVtxFmt vtxfmt, u16 nverts) {
    if (gx->dirtyState != 0) {
        __GXSetDirtyState();
    }
#if DEBUG
    if (!__GXinBegin) {
        __GXVerifyState(vtxfmt);
    }
    __GXinBegin = GX_TRUE;
#endif
    if (*(u32*)&gx->vNumNot == 0) {
        __GXSendFlushPrim();
    }

    GX_WRITE_U8(vtxfmt | type);
    GX_WRITE_U16(nverts);
}

void __GXSendFlushPrim(void) {
    u32 i;
    u32 count = gx->vNum * gx->vLim;

    GX_WRITE_U8(0x98);
    GX_WRITE_U16(gx->vNum);
    for (i = 0; i < count; i += 4) {
        GX_WRITE_U32(0);
    }

    gx->bpSentNot = 1;
}

void GXSetLineWidth(u8 width, GXTexOffset texOffsets) {
    SET_REG_FIELD(425, gx->lpSize, 8, 0, width);
    SET_REG_FIELD(426, gx->lpSize, 3, 16, texOffsets);
    GX_WRITE_BP_REG(gx->lpSize);
    gx->bpSentNot = 0;
}

void GXSetPointSize(u8 pointSize, GXTexOffset texOffsets) {
    SET_REG_FIELD(469, gx->lpSize, 8, 8, pointSize);
    SET_REG_FIELD(470, gx->lpSize, 3, 19, texOffsets);
    GX_WRITE_BP_REG(gx->lpSize);
    gx->bpSentNot = 0;
}

void GXEnableTexOffsets(GXTexCoordID coord, u8 line_enable, u8 point_enable) {
    SET_REG_FIELD(514, gx->suTs0[coord], 1, 18, line_enable);
    SET_REG_FIELD(515, gx->suTs0[coord], 1, 19, point_enable);
    GX_WRITE_BP_REG(gx->suTs0[coord]);
    gx->bpSentNot = 0;
}

void GXSetCullMode(GXCullMode mode) {
    GXCullMode hwMode;

    switch (mode) {
    case GX_CULL_FRONT:
        hwMode = GX_CULL_BACK;
        break;
    case GX_CULL_BACK:
        hwMode = GX_CULL_FRONT;
        break;
    default:
        hwMode = mode;
        break;
    }

    SET_REG_FIELD(555, gx->genMode, 2, 14, hwMode);
    gx->dirtyState |= 4;
}

void GXSetCoPlanar(GXBool enable) {
    SET_REG_FIELD(611, gx->genMode, 1, 19, enable);
    GX_WRITE_BP_REG(0xFE080000);
    GX_WRITE_BP_REG(gx->genMode);
}

void __GXSetGenMode(void) {
    GX_WRITE_BP_REG(gx->genMode);
    gx->bpSentNot = 0;
}
