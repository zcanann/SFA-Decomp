#include "dolphin/card.h"
#include "main/effect_interfaces.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "dolphin/gx.h"
#include "dolphin/mtx.h"
#include "track/intersect.h"
#include "main/model.h"
#include "main/texture.h"
#include "main/dll/player_state.h"
#include "main/sky_interface.h"
#include "main/gameplay_runtime.h"
#include "main/camera.h"
#include "dolphin/gx/GXPixel.h"
#include "main/mm.h"
#include "main/pad.h"
#include "main/sfa_extern_decls.h"
#include "main/pi_dolphin.h"

/* Model render-op record (0x44 stride at ModelFileHeader.renderOps);
 * only the fields evidenced in this TU are typed. */
typedef struct ModelRenderOp {
    u8 pad00[0xc];
    u8 alpha;        /* 0x0c */
    u8 pad0D[0x34 - 0xd];
    s32 layer0TexId; /* 0x34 */
    u8 pad38[4];
    u32 flags;       /* 0x3c */
    u8 pad40[4];
} ModelRenderOp; /* size 0x44 */

typedef struct {
    f32 m[6];
} IndMtxInit;

/* Entry of gDepthReadPendingQueue/gDepthReadResults (0xC stride, 0x14 cap). */
typedef struct DepthReadRequest {
    u16 x;     /* 0x0 */
    u16 y;     /* 0x2 */
    s32 value; /* 0x4: completed GXPeekZ result */
    s32 key;   /* 0x8: opaque request key */
} DepthReadRequest;

extern Mtx lbl_803967C0;
extern Mtx lbl_80396820;
extern Mtx lbl_80396850;
extern f32 lbl_803DFB10;
extern f32 sqrtf(f32 x);

extern DepthReadRequest gDepthReadResults[0x14];
extern DepthReadRequest gDepthReadPendingQueue[0x14];
extern GXColor lbl_803DB6D0;
extern GXColor lbl_803DB6D4;
extern GXColor lbl_803DB6D8;
extern GXColor lbl_803DB6DC;
extern GXColor lbl_803DB6E0;
extern GXColor lbl_803DB6E4;
extern GXColor lbl_803DB6E8;
extern GXColor lbl_803DB6EC;
extern GXColor lbl_803DB6F0;
/* Narrow-typed aliases for sbss/sdata state vars touched by the small
 * helpers below. */
extern u8 hudOpacity;
extern volatile s32 lbl_803DB700;
extern u32 screenWidth;
extern u8 gGxZCompLocValid;
extern u8 gGxZModeValid;
extern GXColor gFogColor;
extern u8 gTevIndStageCount;
extern u8 gTevChanCount;
extern u8 gTevTexGenCount;
extern u8 gTevStageCount;
extern u32 gTevStageCursor;
extern u32 gTevTexCoordCursor;
extern u32 gTevTexMapCursor;
extern u8 lbl_803DD059;
extern u32 lbl_803DD048;
extern u32 gSaveCardSerialLo;
extern u32 lbl_803DD050;
extern u32 lbl_803DD054;
extern u8 gGxZCompLocCached;
extern f32 gFogEndZ;
extern f32 gFogStartZ;
extern f32 gFogFarZ;
extern f32 gFogNearZ;
extern u8 gWaterFxBank;
extern u8 gWaterRippleWriteIdx;
extern u8 gWaterQuadWriteIdx;
extern u16 gDepthReadPendingCount;
extern u16 gDepthReadResultCount;

void* fn_8006F388(u32 i)
{
    extern u8 lbl_8030E8B0[];
    u8* base = lbl_8030E8B0;
    switch (i) {
        case 0:  return base;
        case 1:  return base + 0x14;
        case 2:  return base + 0x3C;
        case 3:  return base + 0x64;
        case 4:  return base + 0x50;
        case 5:  return base + 0x78;
        case 6:  return base + 0x8C;
        case 7:  return base + 0xA0;
        case 10:
        case 8:  return base + 0x28;
        default: return base + 0x28;
    }
}

typedef struct {
    s16 id;
    s16 unk2;
    s16 unk4;
    f32 scale;
    Vec pos;
} SplashFxParams;

extern f32 Vachuff_803DEE20;
extern f32 __THPHuffmanBits_803DEE24;
extern f32 __THPHuffmanSizeTab_803DEE28;
extern u8 lbl_8030E8B0[];



void objAudioFn_8006ef38(u8 *obj, s8 *hits, u8 type, f32 *vecs, u8 *st, f32 unused, f32 scale)
{
    Vec v;
    SplashFxParams ps;
    u8 *tbl;
    u16 *sfxTab;
    u8 flags;
    u8 i;
    int sfx;
    u8 vecIdx;
    u8 j;
    u8 cnt;
    f32 *vec;
    s8 n;
    void *desc;

    tbl = lbl_8030E8B0;
    switch (type) {
        case 0:  sfxTab = (u16 *)tbl; break;
        case 1:  sfxTab = (u16 *)(tbl + 0x14); break;
        case 2:  sfxTab = (u16 *)(tbl + 0x3C); break;
        case 3:  sfxTab = (u16 *)(tbl + 0x64); break;
        case 4:  sfxTab = (u16 *)(tbl + 0x50); break;
        case 5:  sfxTab = (u16 *)(tbl + 0x78); break;
        case 6:  sfxTab = (u16 *)(tbl + 0x8C); break;
        case 7:  sfxTab = (u16 *)(tbl + 0xA0); break;
        case 10:
        case 8:  sfxTab = (u16 *)(tbl + 0x28); break;
        default: sfxTab = (u16 *)(tbl + 0x28); break;
    }
    flags = 0;
    i = 0;
    for (i = 0; i < hits[0x1b]; i++) {
        switch (hits[0x13 + i]) {
        case 1: flags |= 1; vecIdx = 0; break;
        case 2: flags |= 2; vecIdx = 1; break;
        case 3: flags |= 4; vecIdx = 2; break;
        case 4: flags |= 8; vecIdx = 3; break;
        }
    }
    if (flags == 0) {
        return;
    }
    if (!(((BaddieState *)st)->contactSfxFlags & 0x10) && ((BaddieState *)st)->contactSfxMuted != 0) {
        return;
    }
    n = ((BaddieState *)st)->surfaceSoundIndex;
    if (n < 0 || n >= 0x23) {
        sfx = 0;
    } else {
        sfx = tbl[0xb4 + n];
    }
    desc = ((BaddieState *)st)->contactObj;
    if (desc != NULL) {
        switch (((GameObject *)desc)->anim.seqId) {
        case 0x5d:
        case 0x99:
        case 0x1db:
        case 0x223:
            sfx = 4;
        }
    }
    if (sfxTab != NULL) {
        vec = vecs + vecIdx * 3;
        if (((BaddieState *)st)->waterDepth > Vachuff_803DEE20) {
            (*(void (**)(u8 *, int, f32 *, u8 *))((int)*gWaterfxInterface + 8))(obj, flags, vecs, st);
            sfx = 5;
        }
        if (obj == Obj_GetPlayerObject()) {
            if (*(s16 *)(*(u32 *)&((GameObject *)obj)->extra + 0x81a) == 1) {
                Sfx_PlayFromObject(0, 0x3c2);
            }
            Sfx_PlayFromObject(0, sfxTab[sfx]);
        } else {
            Sfx_PlayAtPositionFromObject(vec[0], vec[1], vec[2], (u32)obj, sfxTab[sfx]);
        }
    }
    if (i == 5) {
        return;
    }
    j = 0;
    scale = __THPHuffmanBits_803DEE24 * scale;
    while (flags != 0) {
        vec = vecs + j * 3;
        v.x = vec[0];
        v.y = vec[1];
        v.z = vec[2];
        if (flags & 1) {
            if (((GameObject *)obj)->anim.classId == 1 || ((GameObject *)obj)->anim.seqId == 0x416) {
                playerEarthWalkerAudioFn_8006f950(obj, (f32 *)&v, j & 1, sfx);
            }
            ps.pos.x = vec[0];
            ps.pos.y = vec[1];
            ps.pos.z = vec[2];
            ps.scale = scale;
            ps.id = sfx;
            ps.unk4 = 0;
            ps.unk2 = 0;
            v.x = __THPHuffmanSizeTab_803DEE28 * ((GameObject *)obj)->anim.velocityX;
            v.y = __THPHuffmanSizeTab_803DEE28 * ((GameObject *)obj)->anim.velocityY;
            v.z = __THPHuffmanSizeTab_803DEE28 * ((GameObject *)obj)->anim.velocityZ;
            if (sfx == 6 || sfx == 3) {
                cnt = randomGetRange(2, 4);
                while (cnt != 0) {
                    (*gPartfxInterface)->spawnObject(obj, 0x7e6, &ps, 0x200001, -1, &v);
                    cnt--;
                }
            } else if (sfx == 2) {
                cnt = randomGetRange(4, 8);
                while (cnt != 0) {
                    (*gPartfxInterface)->spawnObject(obj, 0x7e6, &ps, 0x200001, -1, &v);
                    cnt--;
                }
            }
        }
        flags = flags >> 1;
        j++;
    }
}

/* EN v1.0 Size: 256b. Per-iteration byte decrement of two parallel
 * arrays. */
#pragma opt_common_subs off
void timeFn_8006f400(f32 step)
{
    int i;
    u8* a;
    u8* b;
    extern u8 gWaterSplashQuads[];
    extern u8 gWaterRipples[];
    extern f32 Vachuff_803DEE20;

    a = gWaterSplashQuads;
    b = gWaterRipples;
    for (i = 0; i < 256; i++) {
        if (a[0x33] != 0) {
            if ((f32)(u32)a[0x33] - step <= Vachuff_803DEE20) {
                a[0x33] = 0;
            } else {
                a[0x33] = (f32)(u32)a[0x33] - step;
            }
        }
        if (b[0x0E] != 0) {
            if ((f32)(u32)b[0x0E] - step <= Vachuff_803DEE20) {
                b[0x0E] = 0;
            } else {
                b[0x0E] = (f32)(u32)b[0x0E] - step;
            }
        }
        a += 0x38;
        b += 0x10;
    }
}
#pragma opt_common_subs reset

void drawFn_8006f500(void)
{
    extern f32 playerMapOffsetX, playerMapOffsetZ;
    extern f32 Gbase;
    extern f32 lbl_803DEE38;
    extern f32 lbl_803DEE3C;
    extern f32 lbl_803DEE44;
    extern f32 lbl_803DEE48;
    extern void *gWaterFxTextures[];
    extern u8 gWaterSplashQuads[];
    extern f32 Vachuff_803DEE20;
    extern f32 __THPHuffmanBits_803DEE24;
    extern void selectTexture(void *tex, int slot);
    extern void fn_8000F9B4(void);

    extern void Camera_ApplyFullViewport(void);


    GXColor color;
    Mtx camTrans;
    Mtx posMtx;
    Mtx rot;
    Mtx trans;
    u8 *quad;
    f32 *view;
    int i;
    f32 tTop;
    f32 tBot;
    u8 alpha;

    if (Obj_GetPlayerObject() == NULL) {
        return;
    }
    fn_8000F9B4();
    GXSetCurrentMtx(0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(0, 1, 4, 0x1e, 0, 0x7d);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xf);
    GXSetTevKAlphaSel(0, 0x1c);
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetTevSwapMode(0, 0, 0);
    GXSetCullMode(0);
    GXSetBlendMode(1, 4, 5, 5);
    selectTexture(gWaterFxTextures[gWaterFxBank], 0);
    view = Camera_GetViewMatrix();
    PSMTXTrans(camTrans, -playerMapOffsetX, Vachuff_803DEE20, -playerMapOffsetZ);
    PSMTXConcat((MtxP)view, camTrans, posMtx);
    GXLoadPosMtxImm(posMtx, 0);
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    i = 0;
    for (; i < 0x100; i++) {
        quad = &gWaterSplashQuads[i * 0x38];
        alpha = quad[0x33];
        if (alpha != 0) {
            if (quad[0x32] == 1) {
                color.a = alpha >> 2;
            } else {
                color.a = alpha >> 1;
            }
            GXSetTevKColor(0, color);
            if (quad[0x34] != 0) {
                tTop = lbl_803DEE38;
                tBot = Vachuff_803DEE20;
                PSMTXRotRad(rot, 0x7a, lbl_803DEE3C * (Gbase * (f32)(int)(0x8000 - *(u16 *)(quad + 0x30))) / lbl_803DEE44);
            } else {
                tTop = Vachuff_803DEE20;
                tBot = lbl_803DEE38;
                PSMTXRotRad(rot, 0x7a, lbl_803DEE3C * (Gbase * (f32)(u32)*(u16 *)(quad + 0x30)) / lbl_803DEE44);
            }
            PSMTXTrans(trans, lbl_803DEE48, *(f32 *)&lbl_803DEE48, Vachuff_803DEE20);
            PSMTXConcat(rot, trans, rot);
            PSMTXTrans(trans, __THPHuffmanBits_803DEE24, __THPHuffmanBits_803DEE24, Vachuff_803DEE20);
            PSMTXConcat(trans, rot, rot);
            GXLoadTexMtxImm(rot, 0x1e, 1);
            GXBegin(0x80, 2, 4);
            GXPosition3f32(*(f32 *)(quad + 0x0), *(f32 *)(quad + 0x4), *(f32 *)(quad + 0x8));
            GXTexCoord2f32(Vachuff_803DEE20, tTop);
            GXPosition3f32(*(f32 *)(quad + 0xc), *(f32 *)(quad + 0x10), *(f32 *)(quad + 0x14));
            GXTexCoord2f32(lbl_803DEE38, tTop);
            GXPosition3f32(*(f32 *)(quad + 0x18), *(f32 *)(quad + 0x1c), *(f32 *)(quad + 0x20));
            GXTexCoord2f32(lbl_803DEE38, tBot);
            GXPosition3f32(*(f32 *)(quad + 0x24), *(f32 *)(quad + 0x28), *(f32 *)(quad + 0x2c));
            GXTexCoord2f32(Vachuff_803DEE20, tBot);
        }
    }
    Camera_ApplyFullViewport();
}

typedef struct {
    f32 x, y, z;
    u16 id;
    u8 alpha;
    u8 flip;
} RippleEntry;

typedef struct {
    f32 v[12];
    u16 angle;
    u8 type;
    u8 alpha;
    u8 flip;
    u8 pad[3];
} SplashQuad;

typedef struct {
    f32 scales[4];
    u8 pad[0x10];
    RippleEntry ripples[0x100];
    SplashQuad quads[0x100];
} WaterFxState;

void playerEarthWalkerAudioFn_8006f950(u8 *obj, f32 *pos, u8 flip, u8 type)
{
    extern f32 gWaterFxState[];
    extern f32 lbl_803DEE38;
    extern f32 lbl_803DEE3C;
    extern f32 lbl_803DEE58;
    extern int fn_80065768(u8 *obj, f32 x, f32 y, f32 z, f32 *outY, Vec *outNorm, int flag);

    WaterFxState *base;
    f32 ax, px;
    f32 x, y, z;
    f32 ay, py, az, pz;
    f32 xm, ym, zm;
    f32 groundY;
    Vec axis;
    Vec perp;
    Vec norm;
    f32 fscale;

    base = (WaterFxState *)gWaterFxState;
    if (((GameObject *)obj)->anim.classId == 1) {
        gWaterFxBank = *(u8 *)&((GameObject *)obj)->anim.bankIndex;
    } else if (((GameObject *)obj)->anim.seqId == 0x416) {
        gWaterFxBank = 3;
    }
    if (fn_80065768(obj, ((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY, ((GameObject *)obj)->anim.localPosZ, &groundY, &norm, 0) == 0) {
        if (type == 1) {
            base->ripples[gWaterRippleWriteIdx].x = pos[0];
            base->ripples[gWaterRippleWriteIdx].y = lbl_803DEE3C + pos[1];
            base->ripples[gWaterRippleWriteIdx].z = pos[2];
            base->ripples[gWaterRippleWriteIdx].id = *(s16 *)obj;
            base->ripples[gWaterRippleWriteIdx].alpha = 0xff;
            base->ripples[gWaterRippleWriteIdx].flip = flip;
            gWaterRippleWriteIdx++;
            if (gWaterRippleWriteIdx >= 0x100) {
                gWaterRippleWriteIdx = 0;
            }
        }
        PSVECNormalize(&norm, &norm);
        axis.x = lbl_803DEE38;
        axis.y = Vachuff_803DEE20;
        axis.z = Vachuff_803DEE20;
        if (__fabs(PSVECDotProduct(&norm, &axis)) >= lbl_803DEE58) {
            axis.x = Vachuff_803DEE20;
            axis.z = lbl_803DEE38;
        }
        PSVECCrossProduct(&norm, &axis, &perp);
        PSVECCrossProduct(&perp, &norm, &axis);
        PSVECNormalize(&axis, &axis);
        PSVECNormalize(&perp, &perp);
        fscale = base->scales[gWaterFxBank];
        PSVECScale(&axis, &axis, fscale);
        PSVECScale(&perp, &perp, fscale);
        x = pos[0];
        y = pos[1];
        z = pos[2];
        ax = axis.x;
        xm = x - ax;
        px = perp.x;
        base->quads[gWaterQuadWriteIdx].v[0] = xm - px;
        ay = axis.y;
        ym = y - ay;
        py = perp.y;
        base->quads[gWaterQuadWriteIdx].v[1] = ym - py;
        az = axis.z;
        zm = z - az;
        pz = perp.z;
        base->quads[gWaterQuadWriteIdx].v[2] = zm - pz;
        x += ax;
        base->quads[gWaterQuadWriteIdx].v[3] = x - px;
        y += ay;
        base->quads[gWaterQuadWriteIdx].v[4] = y - py;
        z += az;
        base->quads[gWaterQuadWriteIdx].v[5] = z - pz;
        base->quads[gWaterQuadWriteIdx].v[6] = px + x;
        base->quads[gWaterQuadWriteIdx].v[7] = py + y;
        base->quads[gWaterQuadWriteIdx].v[8] = pz + z;
        base->quads[gWaterQuadWriteIdx].v[9] = px + xm;
        base->quads[gWaterQuadWriteIdx].v[10] = py + ym;
        base->quads[gWaterQuadWriteIdx].v[11] = pz + zm;
        base->quads[gWaterQuadWriteIdx].angle = 0x10000 - *(s16 *)obj;
        base->quads[gWaterQuadWriteIdx].type = type;
        base->quads[gWaterQuadWriteIdx].alpha = 0xff;
        base->quads[gWaterQuadWriteIdx].flip = flip;
        gWaterQuadWriteIdx++;
        if (gWaterQuadWriteIdx >= 0x100) {
            gWaterQuadWriteIdx = 0;
        }
    }
}

void fn_8006FC00(int enable)
{
    int i;
    u8* a;
    u8* b;
    extern u8 gWaterSplashQuads[];
    extern u8 gWaterRipples[];
    extern u8 gWaterFxDisabled;

    gWaterFxDisabled = enable;
    if (enable != 0) {
        return;
    }
    a = gWaterSplashQuads;
    b = gWaterRipples;
    for (i = 0; i < 32; i++) {
        a[i * 0x1C0 + 0x033] = 0;  b[i * 0x80 + 0x0E] = 0;
        a[i * 0x1C0 + 0x06B] = 0;  b[i * 0x80 + 0x1E] = 0;
        a[i * 0x1C0 + 0x0A3] = 0;  b[i * 0x80 + 0x2E] = 0;
        a[i * 0x1C0 + 0x0DB] = 0;  b[i * 0x80 + 0x3E] = 0;
        a[i * 0x1C0 + 0x113] = 0;  b[i * 0x80 + 0x4E] = 0;
        a[i * 0x1C0 + 0x14B] = 0;  b[i * 0x80 + 0x5E] = 0;
        a[i * 0x1C0 + 0x183] = 0;  b[i * 0x80 + 0x6E] = 0;
        a[i * 0x1C0 + 0x1BB] = 0;  b[i * 0x80 + 0x7E] = 0;
    }
    gWaterQuadWriteIdx = 0;
    *(u8*)&gWaterRippleWriteIdx = 0;
}

void mapInitFn_8006fccc(void)
{
    extern u8 gWaterFxState[];
    extern f32 lbl_803DFADC, lbl_803DFAE0, lbl_803DFAE4;
    extern u32 fn_80054ED0(int);
    extern u32 lbl_803DCFF4;
    extern u8 gWaterRippleWriteIdx, gWaterQuadWriteIdx, gWaterFxDisabled;
    int i;
    u8* base = gWaterFxState;
    u8* a = base + 0x1020;
    u8* b = base + 0x0020;

    for (i = 0; i < 16; i++) {
        a[0x033] = 0; b[0x0E] = 0;
        a[0x06B] = 0; b[0x1E] = 0;
        a[0x0A3] = 0; b[0x2E] = 0;
        a[0x0DB] = 0; b[0x3E] = 0;
        a[0x113] = 0; b[0x4E] = 0;
        a[0x14B] = 0; b[0x5E] = 0;
        a[0x183] = 0; b[0x6E] = 0;
        a[0x1BB] = 0; b[0x7E] = 0;
        a[0x1F3] = 0; b[0x8E] = 0;
        a[0x22B] = 0; b[0x9E] = 0;
        a[0x263] = 0; b[0xAE] = 0;
        a[0x29B] = 0; b[0xBE] = 0;
        a[0x2D3] = 0; b[0xCE] = 0;
        a[0x30B] = 0; b[0xDE] = 0;
        a[0x343] = 0; b[0xEE] = 0;
        a[0x37B] = 0; b[0xFE] = 0;
        a += 0x380;
        b += 0x100;
    }
    *(u32*)(base + 0x10) = fn_80054ED0(0x19);
    *(u32*)(base + 0x14) = fn_80054ED0(0x18);
    *(u32*)(base + 0x18) = fn_80054ED0(0x1A);
    *(u32*)(base + 0x1C) = fn_80054ED0(0x646);
    *(f32*)(base + 0x00) = lbl_803DFADC;
    *(f32*)(base + 0x04) = lbl_803DFAE0;
    *(f32*)(base + 0x08) = lbl_803DFAE0;
    *(f32*)(base + 0x0C) = lbl_803DFAE4;
    gWaterFxDisabled = 0;
    gWaterQuadWriteIdx = 0;
    gWaterRippleWriteIdx = 0;
    lbl_803DCFF4 = 0;
}

/* Queues a GXPeekZ read at (x,y) tagged by an opaque requestKey (callers pass
 * any unique value - object ptrs, loop indices, even a function address) and
 * returns the previously completed result for that key, 0 until ready. */
int depthReadRequestPoll(int x, int y, int requestKey)
{
    bool ok;
    DepthReadRequest* p;
    int i;
    u32 n;

    ok = false;
    if (x >= 0 && x < 0x280 && y >= 0 && y < 0x1E0) {
        ok = true;
    }
    if (ok) {
        if (x < 0x10) x = 0x10;
        if (y < 6) y = 6;
        n = gDepthReadPendingCount;
        if (n < 0x14) {
            gDepthReadPendingQueue[n].x = x;
            gDepthReadPendingQueue[n].y = y;
            gDepthReadPendingQueue[n].key = requestKey;
            gDepthReadPendingCount++;
        }
        i = 0;
        p = gDepthReadResults;
        n = gDepthReadResultCount;
        for (; (u32)i < n; i++) {
            if (requestKey == p->key) {
                return gDepthReadResults[i].value;
            }
            p++;
        }
        return 0;
    }
    return 0;
}

u32 getScreenResolution(void)
{
    u32 v = screenWidth;
    if (v != 0) {
        return v | (v << 16);
    }
    return 0x01E00280;
}

void setScreenWidth(u32 width)
{
    screenWidth = width;
}

void clearScreenWidth(void)
{
    screenWidth = 0;
}

extern f32 gGxPi;
extern f32 lbl_803DEE6C;
extern f32 lbl_803DEE70;
extern f32 lbl_803DEE74;
extern f32 lbl_803DEE78;
extern f32 lbl_803DEE7C;
extern f32 Gq;
extern int lbl_803DD03C;
extern int lbl_803968C0[];
extern float mathSinf(float x);
extern float mathCosf(float x);

void matrixFn_8006ff0c(float *mat, short *out, f32 fov, f32 aspect, f32 near, f32 far,
                       f32 scale)
{
    f32 angle;
    f32 tan;
    int i;

    fn_80070234((f32 *)mat);

    angle = (f32)(s32)(lbl_803DEE6C * fov) * gGxPi / lbl_803DEE70;
    tan = mathCosf(angle) / mathSinf(angle);
    mat[0] = tan / aspect;
    mat[5] = tan;
    mat[10] = -near / (far - near);
    mat[11] = lbl_803DEE74;
    mat[14] = -near * far / (far - near);
    mat[15] = lbl_803DEE78;

    for (i = 0; i < 16; i++) {
        mat[i] *= scale;
    }

    if (out != NULL) {
        if ((f32)(near + far) <= lbl_803DEE7C) {
            *(u16*)out = 0xFFFF;
        } else {
            *(s16*)out = (s16)(Gq / (near + far));
            if (*(u16*)out == 0) {
                *out = 1;
            }
        }
    }
    gFogNearZ = __fabs(near);
    gFogFarZ = __fabs(far);
    C_MTXPerspective((void *)lbl_803968C0, fov, aspect, gFogNearZ, gFogFarZ);
    lbl_803DD03C = 0;
}

void normalize(f32* x, f32* y, f32* z)
{
    f32 scale;
    f32 len;

    len = sqrtf(*z * *z + (*x * *x + *y * *y));
    scale = lbl_803DFB10 / len;
    *x = *x * scale;
    *y = *y * scale;
    *z = *z * scale;
}

extern f32 lbl_803DEE98;
extern f32 lbl_803DEE9C;

/* EN v1.0 Size: 132b. 4x4 identity fill. */
void fn_80070234(f32* mat)
{
    int i = 0, j;
    f32 zero, one;
    one = lbl_803DEE98;
    zero = lbl_803DEE9C;
    for (; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            if (i == j) mat[j] = one; else mat[j] = zero;
        }
        mat += 4;
    }
}

#pragma peephole on
void gxSetPeControl_ZCompLoc_(u32 zCompLoc)
{
    extern void GXSetZCompLoc();
    if ((u32)gGxZCompLocCached != (zCompLoc & 0xff) || gGxZCompLocValid == 0) {
        GXSetZCompLoc(zCompLoc);
        gGxZCompLocCached = zCompLoc;
        gGxZCompLocValid = 1;
    }
}

void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable)
{
    extern void GXSetZMode();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    extern u8 gGxZModeValid;

    if ((u32)gGxZModeCompareEnable != (compareEnable & 0xff) ||
        gGxZModeCompareFunc != compareFunc ||
        gGxZModeUpdateEnable != (updateEnable & 0xff) ||
        gGxZModeValid == 0) {
        GXSetZMode(compareEnable, compareFunc, updateEnable);
        gGxZModeCompareEnable = compareEnable;
        gGxZModeCompareFunc = compareFunc;
        gGxZModeUpdateEnable = updateEnable;
        gGxZModeValid = 1;
    }
}

#pragma peephole off
void resetSomeGxFlags(void)
{
    gGxZModeValid = 0;
    gGxZCompLocValid = 0;
}

void setHudOpacity(u8 opacity)
{
    hudOpacity = opacity;
}

void _gxSetFogParams(void)
{
    GXColor c = gFogColor;
    GXSetFog(GX_FOG_PERSP_EXP, gFogStartZ, gFogEndZ, gFogNearZ, gFogFarZ, c);
}

void fogFn_80070404(f32 a, f32 b)
{
    extern f32 Camera_GetNearPlane(void);
    extern f32 Camera_GetFarPlane(void);
    extern f32 lbl_803DEED8;
    extern f32 lbl_803DEEDC;
    extern f32 gSynthFadeMask;
    extern f32 gFogEndZ, gFogStartZ, gFogFarZ, gFogNearZ;
    extern GXColor gFogColor;
    f32 xc, yc, x, y;
    GXColor c;

    gFogNearZ = Camera_GetNearPlane();
    gFogFarZ = Camera_GetFarPlane();

    x = lbl_803DEED8 * a;
    y = lbl_803DEED8 * b;

    xc = (x < lbl_803DEEDC) ? lbl_803DEEDC : ((x > gSynthFadeMask) ? gSynthFadeMask : x);
    yc = (y < *(f32 *)&lbl_803DEEDC) ? *(f32 *)&lbl_803DEEDC : ((y > gSynthFadeMask) ? gSynthFadeMask : y);

    gFogStartZ = xc * (gFogFarZ - gFogNearZ) + gFogNearZ;
    gFogEndZ = yc * (gFogFarZ - gFogNearZ) + gFogNearZ;
    c = gFogColor;
    GXSetFog(GX_FOG_PERSP_EXP, gFogStartZ, gFogEndZ, gFogNearZ, gFogFarZ, c);
}

void getColor803dd01c(u8* rgbOut)
{
    rgbOut[0] = gFogColor.r;
    rgbOut[1] = gFogColor.g;
    rgbOut[2] = gFogColor.b;
}

void fn_800704FC(u8 red, u8 green, u8 blue)
{
    extern GXColor gFogColor;
    gFogColor.r = red;
    gFogColor.g = green;
    gFogColor.b = blue;
}

int renderWhirlpool(void* obj_a, void** obj_b, int slot)
{
    extern f32 lbl_803DEEE4;
    extern u32 lbl_803DB6F4, lbl_803DB6F8;
    extern GXColor gFogColor;
    extern u8 lbl_803DB678;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern Mtx lbl_80396850;
    extern Mtx lbl_80396820;
    extern f32 lbl_8030EAA0[3][3];
    extern int ObjModel_GetRenderOp(void* model, int slot);
    extern int* Shader_getLayer(void* op, int slot);

    extern void selectTexture(void* tex, int slot);
    extern void selectReflectionTexture(int);
    extern void GXInitTexObj();
    extern void newshadows_getReflectionScrollOffsets(void* a, void* b);

    extern void* (*ObjModel_GetPostRenderCallback(void* obj_b))();
    extern int fn_8003BB74(void);
    extern void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    void* renderOp;
    void* tex2;
    void* model;
    int handle1;
    u8 ignoredLightColor;
    Mtx scaleMtx;
    f32 fA, fB;
    int wrapBit;
    void (*pcb)(void*, void**, int);

    model = obj_b[0];
    renderOp = (void*)ObjModel_GetRenderOp(model, slot);
    handle1 = *Shader_getLayer(renderOp, 0);
    selectTexture(textureIdxToPtr(handle1), 0);
    selectReflectionTexture(1);
    tex2 = textureIdxToPtr(((ModelRenderOp *)renderOp)->layer0TexId);
    wrapBit = (((Texture *)tex2)->maxLod - ((Texture *)tex2)->minLod > 0) ? 1 : 0;
    GXInitTexObj((void*)((u8*)tex2 + 0x20), (u8*)tex2 + 0x60,
                 ((Texture *)tex2)->width, ((Texture *)tex2)->height,
                 ((Texture *)tex2)->format, GX_REPEAT, GX_REPEAT, wrapBit);
    selectTexture(tex2, 2);
    GXLoadTexMtxImm(lbl_80396850, 0x52, 0);
    GXSetTexCoordGen2(0, 0, 0, 0, 0, 0x52);
    GXLoadTexMtxImm(lbl_80396820, 0x55, 0);
    GXSetTexCoordGen2(1, 0, 0, 0, 0, 0x55);
    newshadows_getReflectionScrollOffsets(&fA, &fB);
    PSMTXScale(scaleMtx, lbl_803DEEE4, lbl_803DEEE4, lbl_803DEEE4);
    scaleMtx[1][3] = -fA;
    GXLoadTexMtxImm(scaleMtx, 0x21, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x21, 0, 0x7d);
    GXSetTexCoordGen2(3, 1, 4, 0x21, 0, 0x7d);

    if (isHeavyFogEnabled() != 0) {
        ((u8*)&lbl_803DB6F4)[0] = ((u8*)&gFogColor)[0];
        ((u8*)&lbl_803DB6F4)[1] = ((u8*)&gFogColor)[1];
        ((u8*)&lbl_803DB6F4)[2] = ((u8*)&gFogColor)[2];
        ((u8*)&lbl_803DB6F4)[3] = 0x80;
    } else {
        (*gSkyInterface)->getCurrentAmbientAndLightColors(
            (u8*)&lbl_803DB6F4,
            (u8*)&lbl_803DB6F4 + 1,
            (u8*)&lbl_803DB6F4 + 2,
            &ignoredLightColor, &ignoredLightColor, &ignoredLightColor);
        ((u8*)&lbl_803DB6F4)[0] = (u8)((int)((u8*)&lbl_803DB6F4)[0] >> 3);
        ((u8*)&lbl_803DB6F4)[1] = (u8)((int)((u8*)&lbl_803DB6F4)[1] >> 3);
        ((u8*)&lbl_803DB6F4)[2] = (u8)((int)((u8*)&lbl_803DB6F4)[2] >> 3);
        ((u8*)&lbl_803DB6F4)[3] = lbl_803DB678;
    }
    GXSetTevColor(3, *(GXColor*)&lbl_803DB6F4);
    GXSetTevKColor(0, *(GXColor*)&lbl_803DB6F8);
    GXSetTevKColorSel(1, 0xC);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD2, GX_TEXMAP2);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, lbl_8030EAA0, -1);
    GXSetIndTexMtx(2, lbl_8030EAA0, -2);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevIndirect(1, 0, 0, 7, 2, 0, 0, 0, 0, 0);
    GXSetTevOrder(0, 0, 1, 0xff);
    GXSetTevColorIn(0, 6, 0xf, 0xf, 8);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    if (isHeavyFogEnabled() != 0) {
        GXSetTevColorOp(0, 0, 0, 3, 1, 0);
    } else {
        GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    }
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetTevOrder(1, 1, 1, 0xff);
    GXSetTevColorIn(1, 0, 8, 0xe, 0xf);
    GXSetTevAlphaIn(1, 7, 7, 7, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(2, 3, 0, 4);
    GXSetTevColorIn(2, 0, 8, 9, 0xf);
    GXSetTevAlphaIn(2, 7, 7, 7, 5);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumIndStages(1);
    GXSetNumChans(1);
    GXSetNumTexGens(4);
    GXSetNumTevStages(3);

    pcb = (void(*)(void*, void**, int))ObjModel_GetPostRenderCallback(obj_b);
    if (pcb != 0) {
        pcb(obj_a, obj_b, slot);
    } else {
        u8 zCompLoc = 1;
        if (((u8*)obj_a)[0x37] < 0xFF
            || (((ModelRenderOp *)renderOp)->flags & 0x40000000) != 0
            || ((ModelRenderOp *)renderOp)->alpha < 0xFF) {
            GXSetBlendMode(1, 4, 5, 5);
            if ((((ModelFileHeader *)model)->flags & 0x400) != 0) {
                if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 ||
                    gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
                    GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                    gGxZModeCompareEnable = 0;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 0;
                    gGxZModeValid = 1;
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            } else if ((((ModelFileHeader *)model)->flags & 0x2000) != 0) {
                zCompLoc = 0;
                if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
                    gGxZModeUpdateEnable != 1 || gGxZModeValid == 0) {
                    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                    gGxZModeCompareEnable = 1;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 1;
                    gGxZModeValid = 1;
                }
                {
                    int a = fn_8003BB74();
                    int b = fn_8003BB74();
                    GXSetAlphaCompare(4, b, 0, 4, a);
                }
            } else {
                if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
                    gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
                    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
                    gGxZModeCompareEnable = 1;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 0;
                    gGxZModeValid = 1;
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            }
        } else {
            if ((((ModelRenderOp *)renderOp)->flags & 0x400) != 0) {
                GXSetBlendMode(0, 1, 0, 5);
                if ((((ModelFileHeader *)model)->flags & 0x400) != 0) {
                    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 ||
                        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
                        GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                        gGxZModeCompareEnable = 0;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 0;
                        gGxZModeValid = 1;
                    }
                } else {
                    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
                        gGxZModeUpdateEnable != 1 || gGxZModeValid == 0) {
                        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                        gGxZModeCompareEnable = 1;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 1;
                        gGxZModeValid = 1;
                    }
                }
                GXSetAlphaCompare(4, 0xC0, 0, 4, 0xC0);
            } else {
                GXSetBlendMode(0, 1, 0, 5);
                if ((((ModelFileHeader *)model)->flags & 0x400) != 0) {
                    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 ||
                        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
                        GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                        gGxZModeCompareEnable = 0;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 0;
                        gGxZModeValid = 1;
                    }
                } else {
                    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
                        gGxZModeUpdateEnable != 1 || gGxZModeValid == 0) {
                        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                        gGxZModeCompareEnable = 1;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 1;
                        gGxZModeValid = 1;
                    }
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            }
        }
        if ((((ModelRenderOp *)renderOp)->flags & 0x400) != 0) {
            zCompLoc = 0;
        }
        if (gGxZCompLocCached != zCompLoc || gGxZCompLocValid == 0) {
            GXSetZCompLoc(zCompLoc);
            gGxZCompLocCached = zCompLoc;
            gGxZCompLocValid = 1;
        }
    }
    if ((((ModelRenderOp *)renderOp)->flags & 0x8) != 0) {
        GXSetCullMode(2);
    } else {
        GXSetCullMode(0);
    }
    return 1;
}

void screenImageDraw(u8 alpha)
{
    extern f32 lbl_803DEEE4, lbl_803DEEEC, lbl_803DEEF0;
    extern f32 lbl_803DEEE8;
    extern f32 lbl_8030EA70[3][3];
    extern f32 lbl_8030EA88[3][3];
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern void newshadows_getReflectionScrollOffsets(f32* a, f32* b);
    extern void getTextureFn_8006c5e4(int* out);

    extern void selectReflectionTexture(int);
    extern void selectTexture(int handle, int slot);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_60;
    Mtx mtx_30;
    int handle;
    f32 fA;
    f32 fB;

    newshadows_getReflectionScrollOffsets(&fA, &fB);
    getTextureFn_8006c5e4(&handle);
    updateReflectionTextures();
    selectReflectionTexture(0);
    selectTexture(handle, 1);
    lbl_803DB6E4.a = alpha;
    GXSetTevKColor(0, lbl_803DB6E4);
    GXSetTevKColor(1, lbl_803DB6E8);
    GXSetTevKColor(2, lbl_803DB6EC);
    GXSetTevKColor(3, lbl_803DB6F0);

    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);

    PSMTXScale(mtx_60, lbl_803DEEE8, *(f32 *)&lbl_803DEEE8, lbl_803DEEE4);
    mtx_60[1][3] = -fA;
    GXLoadTexMtxImm(mtx_60, 0x1e, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x1e, 0, 0x7d);

    PSMTXScale(mtx_60, lbl_803DEEEC, *(f32 *)&lbl_803DEEEC, lbl_803DEEE4);
    PSMTXRotRad(mtx_30, 'z', lbl_803DEEF0);
    PSMTXConcat(mtx_30, mtx_60, mtx_60);
    mtx_60[0][3] = fB;
    mtx_60[1][3] = fB;
    GXLoadTexMtxImm(mtx_60, 0x21, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x21, 0, 0x7d);

    GXSetTevOrder(0, 0xFF, 0xFF, 0xFF);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, lbl_8030EA70, -3);
    GXSetTevIndirect(1, 0, 0, 7, 1, 6, 6, 0, 0, 1);

    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD2, GX_TEXMAP1);
    GXSetIndTexCoordScale(1, 0, 0);
    GXSetIndTexMtx(2, lbl_8030EA88, -3);
    GXSetTevIndirect(2, 1, 0, 7, 2, 0, 0, 1, 0, 1);

    GXSetTevOrder(1, 0xFF, 0xFF, 8);
    GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(1, 7, 7, 7, 5);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);

    GXSetTevOrder(2, 0, 0, 8);
    GXSetTevColorIn(2, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(2, 0, 7, 7, 5);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 3, 1, 0);

    GXSetTevKColorSel(3, 0xC);
    GXSetTevKAlphaSel(3, 0x4);
    GXSetTevDirect(GX_TEVSTAGE3);
    GXSetTevOrder(3, 0xFF, 0xFF, 0xFF);
    GXSetTevColorIn(3, 0xF, 0xE, 0, 0xF);
    GXSetTevAlphaIn(3, 6, 7, 7, 0);
    GXSetTevSwapMode(3, 0, 0);
    GXSetTevColorOp(3, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(3, 1, 0, 1, 1, 1);

    GXSetTevKColorSel(4, 0xD);
    GXSetTevKAlphaSel(4, 0x4);
    GXSetTevDirect(GX_TEVSTAGE4);
    GXSetTevOrder(4, 0xFF, 0xFF, 0xFF);
    GXSetTevColorIn(4, 0xE, 0xF, 0, 2);
    GXSetTevAlphaIn(4, 0, 7, 7, 6);
    GXSetTevSwapMode(4, 0, 0);
    GXSetTevColorOp(4, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(4, 1, 0, 1, 1, 2);

    GXSetTevKColorSel(5, 0xE);
    GXSetTevOrder(5, 0xFF, 0xFF, 0xFF);
    GXSetTevDirect(GX_TEVSTAGE5);
    GXSetTevColorIn(5, 0xF, 0xE, 0, 0xF);
    GXSetTevAlphaIn(5, 1, 7, 7, 2);
    GXSetTevSwapMode(5, 0, 0);
    GXSetTevColorOp(5, 0, 0, 0, 1, 2);
    GXSetTevAlphaOp(5, 0, 0, 0, 1, 0);

    GXSetTevKColorSel(6, 0xF);
    GXSetTevKAlphaSel(6, 0x4);
    GXSetTevColor(3, lbl_803DB6E0);
    GXSetTevOrder(6, 0xFF, 0xFF, 0xFF);
    GXSetTevDirect(GX_TEVSTAGE6);
    GXSetTevColorIn(6, 0xE, 0xF, 0, 4);
    GXSetTevAlphaIn(6, 7, 7, 7, 0);
    GXSetTevSwapMode(6, 0, 0);
    GXSetTevColorOp(6, 0, 0, 0, 1, 2);
    GXSetTevAlphaOp(6, 0, 0, 0, 1, 0);

    GXSetTevKAlphaSel(7, 0x1C);
    GXSetTevDirect(GX_TEVSTAGE7);
    GXSetTevOrder(7, 0xFF, 0xFF, 0xFF);
    GXSetTevColorIn(7, 4, 2, 1, 0xF);
    GXSetTevAlphaIn(7, 7, 7, 7, 6);
    GXSetTevSwapMode(7, 0, 0);
    GXSetTevColorOp(7, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(7, 0, 0, 0, 1, 0);

    GXSetNumTexGens(3);
    GXSetNumIndStages(2);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTevStages(8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetCurrentMtx(0x3C);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
    GXSetCurrentMtx(0);
}

void doSpiritVisionFilter(void)
{
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;

    extern void selectReflectionTexture(int);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);

    updateReflectionTextures();
    selectReflectionTexture(0);
    GXSetTevSwapModeTable(GX_TEV_SWAP0, GX_CH_GREEN, GX_CH_BLUE, GX_CH_RED, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP2, GX_CH_GREEN, GX_CH_GREEN, GX_CH_GREEN, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_BLUE, GX_CH_BLUE, GX_CH_BLUE, GX_CH_ALPHA);

    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);

    GXSetTevKColor(0, lbl_803DB6D0);
    GXSetTevKColor(1, lbl_803DB6D4);
    GXSetTevKColor(2, lbl_803DB6D8);
    GXSetTevColor(1, lbl_803DB6DC);

    GXSetNumTexGens(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTevStages(4);

    GXSetTevKColorSel(0, 0xC);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 0xf, 8, 0xe, 2);
    GXSetTevAlphaIn(0, 7, 7, 7, 1);
    GXSetTevSwapMode(0, 0, 1);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetTevKColorSel(1, 0xD);
    GXSetTevKAlphaSel(1, 0x1D);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(1, 0, 0, 0xff);
    GXSetTevColorIn(1, 0xf, 8, 0xe, 0);
    GXSetTevAlphaIn(1, 7, 7, 7, 0);
    GXSetTevSwapMode(1, 0, 2);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 3);

    GXSetTevKColorSel(2, 0xE);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(2, 0, 0, 0xff);
    GXSetTevColorIn(2, 0xf, 8, 0xe, 0);
    GXSetTevAlphaIn(2, 7, 7, 7, 0);
    GXSetTevSwapMode(2, 0, 3);
    GXSetTevColorOp(2, 0, 0, 3, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);

    GXSetTevDirect(GX_TEVSTAGE3);
    GXSetTevOrder(3, 0, 0, 0xff);
    GXSetTevColorIn(3, 0, 0xf, 0xf, 8);
    GXSetTevAlphaIn(3, 7, 7, 7, 0);
    GXSetTevSwapMode(3, 0, 0);
    GXSetTevColorOp(3, 1, 0, 2, 1, 0);
    GXSetTevAlphaOp(3, 0, 0, 0, 1, 0);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(0, 1, 0, 5);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetCurrentMtx(0x3C);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
    GXSetTevSwapModeTable(GX_TEV_SWAP0, GX_CH_RED, GX_CH_GREEN, GX_CH_BLUE, GX_CH_ALPHA);
}

void doColorFilter(u8* mod)
{
    extern u32 lbl_803DEEC8, lbl_803DEECC, lbl_803DEED0, lbl_803DEED4;
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;

    extern void selectReflectionTexture(int);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    GXColor c0, c1, c2, c3;

    *(u32*)&c0 = lbl_803DEEC8;
    *(u32*)&c1 = lbl_803DEECC;
    *(u32*)&c2 = lbl_803DEED0;
    *(u32*)&c3 = lbl_803DEED4;
    {
        int s0, s1, s2;
        c0.r = (u8)(c0.r + (s0 = mod[0] >> 3));
        c0.g = (u8)(c0.g + (s1 = mod[1] >> 3));
        c0.b = (u8)(c0.b + (s2 = mod[2] >> 3));
        c1.r = (u8)(c1.r + s0);
        c1.g = (u8)(c1.g + s1);
        c1.b = (u8)(c1.b + s2);
        c2.r = (u8)(c2.r + s0);
        c2.g = (u8)(c2.g + s1);
        c2.b = (u8)(c2.b + s2);
    }

    updateReflectionTextures();
    selectReflectionTexture(0);
    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP2, GX_CH_GREEN, GX_CH_GREEN, GX_CH_GREEN, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_BLUE, GX_CH_BLUE, GX_CH_BLUE, GX_CH_ALPHA);

    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);

    GXSetTevKColor(0, c0);
    GXSetTevKColor(1, c1);
    GXSetTevKColor(2, c2);
    GXSetTevColor(1, c3);

    GXSetNumTexGens(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTevStages(3);

    GXSetTevKColorSel(0, 0xC);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 0xf, 8, 0xe, 2);
    GXSetTevAlphaIn(0, 7, 7, 7, 1);
    GXSetTevSwapMode(0, 0, 1);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetTevKColorSel(1, 0xD);
    GXSetTevKAlphaSel(1, 0x1D);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(1, 0, 0, 0xff);
    GXSetTevColorIn(1, 0xf, 8, 0xe, 0);
    GXSetTevAlphaIn(1, 7, 7, 7, 0);
    GXSetTevSwapMode(1, 0, 2);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 3);

    GXSetTevKColorSel(2, 0xE);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(2, 0, 0, 0xff);
    GXSetTevColorIn(2, 0xf, 8, 0xe, 0);
    GXSetTevAlphaIn(2, 7, 7, 7, 0);
    GXSetTevSwapMode(2, 0, 3);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(0, 1, 0, 5);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetCurrentMtx(0x3C);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
}

static inline float distortSqrtf(float x) {
    extern double lbl_803DEF10, lbl_803DEF18;
    volatile float y;
    double guess = __frsqrte((double)x);
    guess = lbl_803DEF10 * guess * (lbl_803DEF18 - guess * guess * x);
    guess = lbl_803DEF10 * guess * (lbl_803DEF18 - guess * guess * x);
    guess = lbl_803DEF10 * guess * (lbl_803DEF18 - guess * guess * x);
    y = (float)(x * guess);
    return y;
}

void doDistortionFilter(f32 radius, f32 angle, float* pos, u8* mod)
{
    extern f32 playerMapOffsetX, playerMapOffsetZ;
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern f32 lbl_803DEF08;
    extern f32 lbl_803DEF24;
    extern f32 lbl_803DB6C4, lbl_803DB6C8, lbl_803DB6CC;
    extern f32 gSynthDelayedActionWord0, gSynthFadeMask;
    extern f32 lbl_803DEF20;
    extern u32 lbl_803DEEB8, lbl_803DEEBC, lbl_803DEEC0, lbl_803DEEC4;
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern void selectReflectionTexture(int);
    extern void getReflectionTexture2(int* out);
    extern void fn_8006C540(int* out);
    extern void fn_8006C534(int* out);
    extern void selectTexture(int handle, int slot);
    extern void Camera_ProjectWorldSphere(f32* p0, f32* p1, f32* p2, f32* p3, f32* p4, f32* p5,
                                          double x, double y, double z, double r);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_d0;
    Mtx mtx_a0;
    Mtx mtx_70;
    f32 indMtx[6];
    int handle1;
    int handle2;
    f32 proj5, proj4, proj3, proj2, proj1, proj0;
    GXColor c0;
    GXColor c1;
    GXColor c2;
    GXColor c3;

    *(u32*)&c0 = lbl_803DEEB8;
    *(u32*)&c1 = lbl_803DEEBC;
    *(u32*)&c2 = lbl_803DEEC0;
    *(u32*)&c3 = lbl_803DEEC4;
    {
        int s0, s1, s2;
        c0.r = (u8)(c0.r + (s0 = mod[0] >> 2));
        c0.g = (u8)(c0.g + (s1 = mod[1] >> 2));
        c0.b = (u8)(c0.b + (s2 = mod[2] >> 2));
        c1.r = (u8)(c1.r + s0);
        c1.g = (u8)(c1.g + s1);
        c1.b = (u8)(c1.b + s2);
        c2.r = (u8)(c2.r + s0);
        c2.g = (u8)(c2.g + s1);
        c2.b = (u8)(c2.b + s2);
        c3.r = (u8)(c3.r + (mod[0] >> 3));
        c3.g = (u8)(c3.g + (mod[1] >> 3));
        c3.b = (u8)(c3.b + (mod[2] >> 3));
    }

    Camera_ProjectWorldSphere(&proj5, &proj4, &proj3, &proj2, &proj1, &proj0,
                              pos[0] - playerMapOffsetX, pos[1], pos[2] - playerMapOffsetZ, radius);
    proj3 = proj3 + lbl_803DEEE4;
    c0.a = (u8)(((u32)(lbl_803DEF08 * proj3) & 0x00FF0000) >> 16);

    selectReflectionTexture(0);
    getReflectionTexture2(&handle1);
    selectTexture(handle1, 1);
    fn_8006C540(&handle2);
    selectTexture(handle2, 2);

    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP2, GX_CH_GREEN, GX_CH_GREEN, GX_CH_GREEN, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_BLUE, GX_CH_BLUE, GX_CH_BLUE, GX_CH_ALPHA);

    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    GXSetTexCoordGen2(1, 1, 4, 0x3C, 0, 0x7D);

    PSMTXTrans(mtx_a0, gSynthDelayedActionWord0 * (-proj5) - gSynthDelayedActionWord0,
                       gSynthDelayedActionWord0 * proj4 - gSynthDelayedActionWord0,
                       lbl_803DEEDC);
    PSMTXScale(mtx_70, lbl_803DB6C4 / proj1, lbl_803DB6C4 / proj2, lbl_803DEEDC);
    PSMTXConcat(mtx_70, mtx_a0, mtx_d0);
    PSMTXTrans(mtx_a0, gSynthDelayedActionWord0, gSynthDelayedActionWord0, lbl_803DEEDC);
    PSMTXConcat(mtx_a0, mtx_d0, mtx_d0);
    GXLoadTexMtxImm(mtx_d0, 0x1e, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x1e, 0, 0x7d);

    {
        f32 r2 = lbl_803DB6C8 / radius;
        f32 sr;
        if (r2 > lbl_803DEEDC) {
            sr = distortSqrtf(r2);
        } else {
            sr = r2;
        }
        if (sr > lbl_803DEEE4) {
            c1.a = 0xFF;
        } else {
            c1.a = lbl_803DEF20 * sr;
        }
        sr = sr * gSynthFadeMask;
        if (sr > lbl_803DEEE4) sr = lbl_803DEEE4;
        c3.a = lbl_803DEF20 * sr;
    }

    GXSetTevKColor(0, c0);
    GXSetTevKColor(1, c1);
    GXSetTevKColor(2, c2);
    GXSetTevColor(1, c3);

    {
        int handle3;
        fn_8006C534(&handle3);
        selectTexture(handle3, 3);
    }

    {
        f32 ind_s = lbl_803DB6CC / radius;
        if (ind_s > gSynthDelayedActionWord0) ind_s = gSynthDelayedActionWord0;
        indMtx[0] = ind_s;
        indMtx[1] = lbl_803DEEDC;
        indMtx[2] = lbl_803DEEDC;
        indMtx[3] = lbl_803DEEDC;
        indMtx[4] = ind_s;
        indMtx[5] = lbl_803DEEDC;
    }

    PSMTXTrans(mtx_a0, gSynthDelayedActionWord0 * (-proj5) - gSynthDelayedActionWord0,
                       gSynthDelayedActionWord0 * proj4 - gSynthDelayedActionWord0,
                       lbl_803DEEDC);
    PSMTXScale(mtx_70, lbl_803DEF24, *(f32 *)&lbl_803DEF24, lbl_803DEEDC);
    PSMTXRotRad(mtx_d0, 'z', angle);
    PSMTXConcat(mtx_70, mtx_a0, mtx_70);
    PSMTXConcat(mtx_d0, mtx_70, mtx_d0);
    PSMTXTrans(mtx_a0, gSynthDelayedActionWord0, gSynthDelayedActionWord0, lbl_803DEEDC);
    PSMTXConcat(mtx_a0, mtx_d0, mtx_d0);
    GXLoadTexMtxImm(mtx_d0, 0x21, 1);
    GXSetTexCoordGen2(3, 1, 4, 0x21, 0, 0x7d);

    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD3, GX_TEXMAP3);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indMtx, 1);

    GXSetTevIndirect(2, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevIndirect(3, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevIndirect(4, 0, 0, 7, 1, 0, 0, 0, 0, 0);

    GXSetNumTexGens(4);
    GXSetNumIndStages(1);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTevStages(6);

    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(0, 1, 1, 0xFF);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(0, 4, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 1);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 1, 0, 2, 1, 3);

    GXSetTevKAlphaSel(1, 0x1C);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(1, 1, 1, 0xFF);
    GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(1, 6, 7, 7, 4);
    GXSetTevSwapMode(1, 0, 1);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 1, 0, 2, 1, 0);

    GXSetTevKColorSel(2, 0x0C);
    GXSetTevOrder(2, 0, 0, 0xFF);
    GXSetTevColorIn(2, 0xF, 0x8, 0xE, 0x2);
    GXSetTevAlphaIn(2, 7, 0, 1, 7);
    GXSetTevSwapMode(2, 0, 1);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 2, 1, 0);

    GXSetTevKColorSel(3, 0x0D);
    GXSetTevKAlphaSel(3, 0x1D);
    GXSetTevOrder(3, 0, 0, 0xFF);
    GXSetTevColorIn(3, 0xF, 0x8, 0xE, 0);
    GXSetTevAlphaIn(3, 7, 3, 6, 7);
    GXSetTevSwapMode(3, 0, 2);
    GXSetTevColorOp(3, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(3, 0, 0, 2, 1, 3);

    GXSetTevKColorSel(4, 0x0E);
    GXSetTevOrder(4, 0, 0, 0xFF);
    GXSetTevColorIn(4, 0xF, 0x8, 0xE, 0);
    GXSetTevAlphaIn(4, 3, 7, 7, 0);
    GXSetTevSwapMode(4, 0, 3);
    GXSetTevColorOp(4, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(4, 0, 0, 2, 1, 0);

    GXSetTevDirect(GX_TEVSTAGE5);
    GXSetTevOrder(5, 2, 2, 0xFF);
    GXSetTevColorIn(5, 0xF, 0xF, 0xF, 0);
    GXSetTevAlphaIn(5, 4, 7, 0, 7);
    GXSetTevSwapMode(5, 0, 0);
    GXSetTevColorOp(5, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(5, 0, 0, 0, 1, 0);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(1, 5, 4, 5);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetCurrentMtx(0x3C);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
}

void gxTextureFn_80072dfc(void* obj_a, void** obj_b, int slot)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern f32 lbl_803DB6B8, lbl_803DB6C0;
    extern u32 lbl_803DB6BC;
    extern f32 gSynthDelayedActionWord0;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern Mtx lbl_80396820;
    extern f32 lbl_8030EA58[3][3];
    extern int ObjModel_GetRenderOp(void* model, int slot);
    extern void* getTextureFn_8006c744(void);
    extern void selectReflectionTexture(int);
    extern void fn_8006C6A4(int);
    extern void selectTexture(void* tex, int slot);
    extern void* (*ObjModel_GetPostRenderCallback(void* obj_b))();
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_54;
    Mtx mtx_24;
    void* renderOp;
    void* tex;
    void* model;
    GXColor temp;
    void (*pcb)(void*, void**, int);
    int alpha_byte;

    model = obj_b[0];
    renderOp = (void*)ObjModel_GetRenderOp(model, slot);
    tex = getTextureFn_8006c744();
    selectReflectionTexture(0);
    selectTexture(tex, 1);
    fn_8006C6A4(2);

    GXLoadTexMtxImm(lbl_80396820, 0x55, 0);
    GXSetTexCoordGen2(1, 0, 0, 0, 0, 0x55);

    if (model == 0 || ((ModelFileHeader *)model)->normalCount != 0) {
        PSMTXScale(mtx_54, lbl_803DB6B8, lbl_803DB6B8, lbl_803DEEDC);
        mtx_54[2][3] = lbl_803DEEE4;
        PSMTXTrans(mtx_24, gSynthDelayedActionWord0, gSynthDelayedActionWord0, lbl_803DEEDC);
        PSMTXConcat(mtx_24, mtx_54, mtx_54);
    } else {
        PSMTXScale(mtx_54, lbl_803DEEDC, lbl_803DEEDC, lbl_803DEEDC);
        mtx_54[0][3] = gSynthDelayedActionWord0;
        mtx_54[1][3] = gSynthDelayedActionWord0;
        mtx_54[2][3] = lbl_803DEEE4;
    }
    GXLoadTexMtxImm(mtx_54, 0x52, 0);
    GXSetTexCoordGen2(0, 0, 1, 0x1e, 1, 0x52);

    PSMTXScale(mtx_54, lbl_803DB6C0, lbl_803DB6C0, lbl_803DEEDC);
    mtx_54[2][3] = lbl_803DEEE4;
    GXLoadTexMtxImm(mtx_54, 0x4f, 0);
    GXSetTexCoordGen2(2, 0, 4, 0x3c, 0, 0x4f);

    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, lbl_8030EA58, -1);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 8);
    GXSetTevAlphaIn(0, 7, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(1, 2, 2, 0xff);
    GXSetTevColorIn(1, 0, 8, 0xe, 0xf);
    GXSetTevAlphaIn(1, 7, 7, 7, 0);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);

    GXSetNumIndStages(1);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(3);
    GXSetNumTevStages(2);

    alpha_byte = (((ModelRenderOp *)renderOp)->alpha * ((u8*)obj_a)[0x37]) >> 8;
    ((u8*)&temp)[3] = alpha_byte;
    GXSetTevKColor(0, temp);
    GXSetTevKAlphaSel(0, 0x1c);
    GXSetTevKColor(1, *(GXColor*)&lbl_803DB6BC);
    GXSetTevKColorSel(1, 0xd);

    pcb = (void(*)(void*, void**, int))ObjModel_GetPostRenderCallback(obj_b);
    if (pcb != 0) {
        pcb(obj_a, obj_b, slot);
    } else {
        extern int fn_8003BB74(void);

        extern void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);
        u8 zCompLoc = 1;
        int ref0;
        int ref1;
        GXColor fogColor;
        if (((u8*)obj_a)[0x37] < 0xff
            || (((ModelRenderOp *)renderOp)->flags & 0x40000000) != 0
            || ((ModelRenderOp *)renderOp)->alpha < 0xff) {
            GXSetBlendMode(1, 4, 5, 5);
            if ((((ModelFileHeader *)model)->flags & 0x400) != 0) {
                if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 ||
                    gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
                    GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                    gGxZModeCompareEnable = 0;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 0;
                    gGxZModeValid = 1;
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            } else if ((((ModelFileHeader *)model)->flags & 0x2000) != 0) {
                zCompLoc = 0;
                if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
                    gGxZModeUpdateEnable != 1 || gGxZModeValid == 0) {
                    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                    gGxZModeCompareEnable = 1;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 1;
                    gGxZModeValid = 1;
                }
                ref0 = fn_8003BB74();
                ref1 = fn_8003BB74();
                GXSetAlphaCompare(4, ref1, 0, 4, ref0);
            } else {
                if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
                    gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
                    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
                    gGxZModeCompareEnable = 1;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 0;
                    gGxZModeValid = 1;
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            }
        } else {
            if ((((ModelRenderOp *)renderOp)->flags & 0x400) != 0) {
                GXSetBlendMode(0, 1, 0, 5);
                if ((((ModelFileHeader *)model)->flags & 0x400) != 0) {
                    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 ||
                        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
                        GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                        gGxZModeCompareEnable = 0;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 0;
                        gGxZModeValid = 1;
                    }
                } else {
                    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
                        gGxZModeUpdateEnable != 1 || gGxZModeValid == 0) {
                        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                        gGxZModeCompareEnable = 1;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 1;
                        gGxZModeValid = 1;
                    }
                }
                GXSetAlphaCompare(4, 192, 0, 4, 192);
            } else {
                GXSetBlendMode(0, 1, 0, 5);
                if ((((ModelFileHeader *)model)->flags & 0x400) != 0) {
                    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 ||
                        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
                        GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                        gGxZModeCompareEnable = 0;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 0;
                        gGxZModeValid = 1;
                    }
                } else {
                    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
                        gGxZModeUpdateEnable != 1 || gGxZModeValid == 0) {
                        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                        gGxZModeCompareEnable = 1;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 1;
                        gGxZModeValid = 1;
                    }
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            }
        }
        if ((((ModelRenderOp *)renderOp)->flags & 0x400) != 0) {
            zCompLoc = 0;
        }
        if (gGxZCompLocCached != zCompLoc || gGxZCompLocValid == 0) {
            GXSetZCompLoc(zCompLoc);
            gGxZCompLocCached = zCompLoc;
            gGxZCompLocValid = 1;
        }
        GXSetCullMode(0);
        if ((((ModelFileHeader *)model)->flags & 0x100) != 0) {
            fogColor = temp;
            GXSetFog(GX_FOG_NONE, lbl_803DEEDC, lbl_803DEEDC, lbl_803DEEDC, lbl_803DEEDC, fogColor);
        } else {
            fogColor = gFogColor;
            GXSetFog(GX_FOG_PERSP_EXP, gFogStartZ, gFogEndZ, gFogNearZ, gFogFarZ, fogColor);
        }
    }
}

/*
 * Three-tex-coord-gen ind+direct TEV setup. Loads the active env-mtx
 * (lbl_80396820) for tex0, scales tex1 by hudScale through a 3x4
 * matrix from PSMTXScale, and stamps an indirect tex matrix from local
 * stack data. Two TEV stages: stage 0 K-modulates the texture by alpha,
 * stage 1 modulates by the second texture. Uses ind tex stage 0 to warp
 * tex coord 0 by tex1.
 */
void quakeSpellTextureFn_8007366c(u8 alpha)
{
    extern Mtx lbl_80396820;
    extern f32 lbl_803DEF28;
    extern f32 hudScale;
    extern f32 lbl_803DEEDC;
    extern f32 lbl_803DEEE4;
    extern f32 lbl_803DEEEC;
    extern f32 lbl_803DEF30;
    extern f32 gSynthDelayedActionWord0;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;

    extern void selectReflectionTexture(int);
    extern void newshadows_getReflectionScrollOffsets(f32* a, f32* b);
    extern void getTextureFn_8006c5e4(int* out);
    extern void fn_8006C5CC(int* out);
    extern void selectTexture(int handle, int slot);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    int handle1;
    int handle2;
    f32 a;
    f32 b;
    GXColor c;
    f32 ind_mtx[2][3];
    Mtx tex_mtx;
    Mtx mtx;

    Camera_GetViewMatrix();
    selectReflectionTexture(0);
    GXLoadTexMtxImm(lbl_80396820, 0x52, 0);
    GXSetTexCoordGen2(0, 0, 0, 0, 0, 0x52);
    newshadows_getReflectionScrollOffsets(&a, &b);
    a = a * lbl_803DEF28;
    getTextureFn_8006c5e4(&handle1);
    selectTexture(handle1, 1);
    PSMTXScale((f32(*)[4])tex_mtx, hudScale, hudScale, hudScale);
    tex_mtx[0][3] = a;
    GXLoadTexMtxImm(tex_mtx, 0x21, 1);
    GXSetTexCoordGen2(1, 1, 0, 0x21, 0, 0x7D);
    ind_mtx[0][0] = gSynthDelayedActionWord0;
    ind_mtx[0][1] = lbl_803DEEDC;
    ind_mtx[0][2] = lbl_803DEEDC;
    ind_mtx[1][0] = lbl_803DEEDC;
    ind_mtx[1][1] = lbl_803DEEEC;
    ind_mtx[1][2] = lbl_803DEEDC;
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, ind_mtx, -3);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    mtx[0][0] = lbl_803DEF30;
    mtx[0][1] = lbl_803DEEDC;
    mtx[0][2] = lbl_803DEEDC;
    mtx[0][3] = *(f32*)&gSynthDelayedActionWord0;
    mtx[1][0] = lbl_803DEEDC;
    mtx[1][1] = lbl_803DEF30;
    mtx[1][2] = lbl_803DEEDC;
    mtx[1][3] = *(f32*)&gSynthDelayedActionWord0;
    mtx[2][0] = lbl_803DEEDC;
    mtx[2][1] = lbl_803DEEDC;
    mtx[2][2] = lbl_803DEEDC;
    mtx[2][3] = lbl_803DEEE4;
    GXLoadTexMtxImm(mtx, 0x55, 0);
    GXSetTexCoordGen2(2, 1, 1, 0x1E, 1, 0x55);
    fn_8006C5CC(&handle2);
    selectTexture(handle2, 2);
    c.a = alpha;
    GXSetTevKColor(0, c);
    GXSetTevKAlphaSel(1, 0x1C);
    GXSetNumIndStages(1);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(3);
    GXSetNumTevStages(2);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(1, 2, 2, 0xFF);
    GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0);
    GXSetTevAlphaIn(1, 7, 4, 6, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetCullMode(2);
}

void fn_80073AAC(void* texture, u32* colorA, u32* colorB)
{
    extern void fn_8004C460(void*, int);
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    fn_8004C460(texture, 0);
    GXSetTevKColor(0, *(GXColor*)colorA);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevColor(1, *(GXColor*)colorB);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevColorIn(0, 0xF, 8, 0xE, 2);
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetBlendMode(1, 4, 1, 5);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetCullMode(2);
}

int modelCb_80073d04(u8 *obj, int *objB)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4, lbl_803DEF34;
    extern f32 gSynthDelayedActionWord0;
    extern GXColor lbl_803DEEB4;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern int ObjModel_GetRenderOp(int model, int slot);
    extern int* Shader_getLayer(int op, int slot);
    extern int textureIdxToPtr(int idx);
    extern void selectTexture(int tex, int slot);
    extern void fn_8006C5CC(int* out);
    int handle;
    GXColor colorK;
    GXColor colorB;
    Mtx texMtx;
    int tex;
    int model;

    colorB = lbl_803DEEB4;
    model = objB[0];
    tex = textureIdxToPtr(*Shader_getLayer(ObjModel_GetRenderOp(model, 0), 0));
    texMtx[0][0] = lbl_803DEF34;
    texMtx[0][1] = lbl_803DEEDC;
    texMtx[0][2] = lbl_803DEEDC;
    texMtx[0][3] = *(f32*)&gSynthDelayedActionWord0;
    texMtx[1][0] = lbl_803DEEDC;
    texMtx[1][1] = lbl_803DEF34;
    texMtx[1][2] = lbl_803DEEDC;
    texMtx[1][3] = *(f32*)&gSynthDelayedActionWord0;
    texMtx[2][0] = lbl_803DEEDC;
    texMtx[2][1] = lbl_803DEEDC;
    texMtx[2][2] = lbl_803DEEDC;
    texMtx[2][3] = lbl_803DEEE4;
    GXLoadTexMtxImm(texMtx, 0x55, 0);
    GXSetTexCoordGen2(0, 1, 1, 0x1e, 1, 0x55);
    fn_8006C5CC(&handle);
    selectTexture(handle, 0);
    colorK.a = obj[0x37];
    GXSetTevKColor(0, colorK);
    GXSetTevKAlphaSel(1, 0x1c);
    GXSetTevColor(1, colorB);
    GXSetNumIndStages(0);
    GXSetNumTexGens(2);
    GXSetNumTevStages(2);
    GXSetTevDirect(GX_TEVSTAGE0);
    if (((ModelFileHeader *)model)->flags24 & 2) {
        GXSetNumChans(1);
        GXSetChanCtrl(4, 0, 0, 1, 0, 0, 2);
        GXSetTevOrder(0, 0, 0, 4);
        GXSetTevAlphaIn(0, 7, 4, 5, 5);
        GXSetBlendMode(1, 4, 1, 5);
    } else {
        GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
        GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
        GXSetNumChans(0);
        GXSetTevOrder(0, 0, 0, 0xff);
        GXSetTevAlphaIn(0, 4, 7, 7, 1);
        GXSetBlendMode(1, 4, 5, 5);
    }
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xf);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 1, 0, 0, 1, 0);
    GXSetTexCoordGen2(1, 1, 4, 0x3c, 0, 0x7d);
    selectTexture(tex, 1);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(1, 1, 1, 0xff);
    GXSetTevColorIn(1, 2, 0xf, 0xf, 8);
    GXSetTevAlphaIn(1, 7, 0, 6, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetCullMode(2);
    return 1;
}

int moonFxCb_80074110(u8 *obj, int *objB, int slot)
{
    extern f32 lbl_803DEEDC, lbl_803DEF38;
    extern u8 lbl_803DD010;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern int ObjModel_GetRenderOp(int model, int slot);
    extern int* Shader_getLayer(int op, int slot);
    extern int textureIdxToPtr(int idx);
    extern void selectTexture(int tex, int slot);
    GXColor colorK;
    GXColor colorFog;
    Mtx mtx;
    int op;
    int tex;
    f32 tx;

    op = ObjModel_GetRenderOp(objB[0], slot);
    tex = textureIdxToPtr(*Shader_getLayer(op, 0));
    GXSetTexCoordGen2(0, 1, 4, 0x3c, 0, 0x7d);
    lbl_803DD010 = GameBit_Get(0x2ba);
    tx = lbl_803DD010 / lbl_803DEF38;
    PSMTXTrans(mtx, tx, lbl_803DEEDC, *(f32 *)&lbl_803DEEDC);
    GXLoadTexMtxImm(mtx, 0x1e, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x1e, 0, 0x7d);
    GXSetNumTexGens(2);
    GXSetNumTevStages(3);
    GXSetNumIndStages(0);
    selectTexture(tex, 0);
    colorK.a = (((ModelRenderOp *)op)->alpha * obj[0x37]) >> 8;
    GXSetTevKColor(0, colorK);
    GXSetTevKAlphaSel(0, 0x1c);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 8);
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    colorFog.a = 0x3e;
    GXSetTevKColor(1, colorFog);
    GXSetTevKAlphaSel(1, 0x1d);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(1, 1, 0, 0xff);
    GXSetTevColorIn(1, 0xf, 0xf, 0xf, 0);
    GXSetTevAlphaIn(1, 7, 6, 4, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 2, 1, 1);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(2, 0xff, 0xff, 0xff);
    GXSetTevColorIn(2, 0xf, 0xf, 0xf, 0);
    GXSetTevAlphaIn(2, 0, 7, 1, 7);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetCullMode(0);
    GXSetFog(GX_FOG_NONE, lbl_803DEEDC, lbl_803DEEDC, lbl_803DEEDC, lbl_803DEEDC, colorFog);
    return 1;
}

int modelCb_80074518(void* obj_a, void** obj_b, int slot)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern f32 lbl_803DB6B0, lbl_803DB6B4;
    extern f32 gSynthDelayedActionWord0;
    extern f32 lbl_802C1F68[6];
    extern Mtx lbl_80396820;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern int ObjModel_GetRenderOp(void* model, int slot);
    extern int* Shader_getLayer(void* op, int slot);
    extern void* textureIdxToPtr(int idx);
    extern void selectTexture(void* tex, int slot);
    extern void* (*ObjModel_GetPostRenderCallback(void* obj_b))();
    extern int fn_8003BB74(void);
    extern void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_90;
    Mtx mtx_60;
    Mtx mtx_30;
    f32 indMtx[6];
    void* renderOp;
    void* tex;
    void* model;
    GXColor temp;
    int alpha_byte;
    void (*pcb)(void*, void**, int);

    *(IndMtxInit *)indMtx = *(IndMtxInit *)lbl_802C1F68;

    model = obj_b[0];
    renderOp = (void*)ObjModel_GetRenderOp(model, slot);
    tex = textureIdxToPtr(*Shader_getLayer(renderOp, 0));

    PSMTXScale(mtx_60, lbl_803DB6B4, lbl_803DB6B4, lbl_803DEEDC);
    mtx_60[2][3] = lbl_803DEEE4;
    GXLoadTexMtxImm(mtx_60, 0x55, 0);
    GXSetTexCoordGen2(0, 0, 1, 0x1e, 1, 0x55);
    GXSetNumTexGens(2);
    GXSetNumTevStages(2);
    GXSetNumIndStages(2);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD0, GX_TEXMAP2);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indMtx, 0);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    selectTexture(tex, 0);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xc);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD0, GX_TEXMAP2);
    GXSetIndTexCoordScale(1, 0, 0);
    GXSetTevIndirect(1, 1, 0, 7, 1, 0, 0, 1, 0, 0);
    PSMTXScale(mtx_30, lbl_803DB6B0, lbl_803DB6B0, lbl_803DEEE4);
    PSMTXConcat(mtx_30, lbl_80396820, mtx_90);
    PSMTXTrans(mtx_30,
               gSynthDelayedActionWord0 * (lbl_803DEEE4 - lbl_803DB6B0),
               gSynthDelayedActionWord0 * (lbl_803DEEE4 - lbl_803DB6B0),
               lbl_803DEEDC);
    PSMTXConcat(mtx_30, mtx_90, mtx_90);
    GXLoadTexMtxImm(mtx_90, 0x52, 0);
    GXSetTexCoordGen2(1, 0, 0, 0, 1, 0x52);

    alpha_byte = (((ModelRenderOp *)renderOp)->alpha * ((u8*)obj_a)[0x37]) >> 8;
    ((u8*)&temp)[3] = alpha_byte;
    GXSetTevKColor(0, temp);
    GXSetTevKAlphaSel(1, 0x1c);
    GXSetTevOrder(1, 1, 0, 4);
    GXSetTevColorIn(1, 0xf, 0xa, 8, 0xf);
    GXSetTevAlphaIn(1, 7, 7, 7, 6);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);

    pcb = (void(*)(void*, void**, int))ObjModel_GetPostRenderCallback(obj_b);
    if (pcb != 0) {
        pcb(obj_a, obj_b, slot);
    } else {
        u8 zCompLoc = 1;
        if (((u8*)obj_a)[0x37] < 0xff
            || (((ModelRenderOp *)renderOp)->flags & 0x40000000) != 0
            || ((ModelRenderOp *)renderOp)->alpha < 0xff) {
            GXSetBlendMode(1, 4, 5, 5);
            if ((((ModelFileHeader *)model)->flags & 0x400) != 0) {
                if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 ||
                    gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
                    GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                    gGxZModeCompareEnable = 0;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 0;
                    gGxZModeValid = 1;
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            } else if ((((ModelFileHeader *)model)->flags & 0x2000) != 0) {
                zCompLoc = 0;
                if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
                    gGxZModeUpdateEnable != 1 || gGxZModeValid == 0) {
                    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                    gGxZModeCompareEnable = 1;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 1;
                    gGxZModeValid = 1;
                }
                {
                    int b;
                    alpha_byte = fn_8003BB74();
                    b = fn_8003BB74();
                    GXSetAlphaCompare(4, b, 0, 4, alpha_byte);
                }
            } else {
                if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
                    gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
                    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
                    gGxZModeCompareEnable = 1;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 0;
                    gGxZModeValid = 1;
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            }
        } else {
            if ((((ModelRenderOp *)renderOp)->flags & 0x400) != 0) {
                GXSetBlendMode(0, 1, 0, 5);
                if ((((ModelFileHeader *)model)->flags & 0x400) != 0) {
                    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 ||
                        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
                        GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                        gGxZModeCompareEnable = 0;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 0;
                        gGxZModeValid = 1;
                    }
                } else {
                    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
                        gGxZModeUpdateEnable != 1 || gGxZModeValid == 0) {
                        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                        gGxZModeCompareEnable = 1;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 1;
                        gGxZModeValid = 1;
                    }
                }
                GXSetAlphaCompare(4, 0xC0, 0, 4, 0xC0);
            } else {
                GXSetBlendMode(0, 1, 0, 5);
                if ((((ModelFileHeader *)model)->flags & 0x400) != 0) {
                    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 ||
                        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
                        GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                        gGxZModeCompareEnable = 0;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 0;
                        gGxZModeValid = 1;
                    }
                } else {
                    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
                        gGxZModeUpdateEnable != 1 || gGxZModeValid == 0) {
                        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                        gGxZModeCompareEnable = 1;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 1;
                        gGxZModeValid = 1;
                    }
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            }
        }
        if ((((ModelRenderOp *)renderOp)->flags & 0x400) != 0) {
            zCompLoc = 0;
        }
        if (gGxZCompLocCached != zCompLoc || gGxZCompLocValid == 0) {
            GXSetZCompLoc(zCompLoc);
            gGxZCompLocCached = zCompLoc;
            gGxZCompLocValid = 1;
        }
    }
    if ((((ModelRenderOp *)renderOp)->flags & 0x8) != 0) {
        GXSetCullMode(2);
    } else {
        GXSetCullMode(0);
    }
    return 1;
}

u32 objCallback_80074d04(int handle, void* model)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4, lbl_803DEEF0;
    extern f32 lbl_803DEF3C, lbl_803DEF40, lbl_803DEF44, lbl_803DEF48;
    extern f32 lbl_803DB6AC;
    extern f32 hudScale;
    extern f32 gSynthDelayedActionWord0;
    extern Mtx lbl_80396820;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;

    extern f32* ObjModel_GetJointMatrix(void* model, int joint);
    extern void selectReflectionTexture(int);
    extern void newshadows_getReflectionScrollOffsets(f32* a, f32* b);
    extern void getTextureFn_8006c5e4(int* out);
    extern void fn_8006C5CC(int* out);
    extern void selectTexture(int handle, int slot);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_ec;
    Mtx mtx_bc;
    Mtx mtx_8c;
    Mtx mtx_5c;
    f32 indMtx_44[6];
    f32 indMtx_2c[6];
    int handle1, handle2;
    f32 f1, f2;
    f32 f31_val;
    GXColor temp;
    f32* viewMtx;

    viewMtx = Camera_GetViewMatrix();
    if (model != 0) {
        f32* jm = ObjModel_GetJointMatrix(model, 0);
        f32 px, py, pz, dist;
        PSMTXConcat((f32(*)[4])viewMtx, (f32(*)[4])jm, mtx_8c);
        px = mtx_8c[0][3];
        py = mtx_8c[1][3];
        pz = mtx_8c[2][3];
        dist = px*px + py*py + pz*pz;
        if (dist > lbl_803DEEDC) {
            extern double lbl_803DEF10, lbl_803DEF18;
            volatile float vdist;
            double g = __frsqrte((double)dist);
            g = lbl_803DEF10 * g * (lbl_803DEF18 - g * g * dist);
            g = lbl_803DEF10 * g * (lbl_803DEF18 - g * g * dist);
            g = lbl_803DEF10 * g * (lbl_803DEF18 - g * g * dist);
            vdist = (float)(dist * g);
            dist = vdist;
        }
        f31_val = lbl_803DEF3C / dist;
        if (f31_val > lbl_803DEEE4) f31_val = lbl_803DEEE4;
    } else {
        f31_val = lbl_803DEEE4;
    }

    selectReflectionTexture(0);
    GXLoadTexMtxImm(lbl_80396820, 0x52, 0);
    GXSetTexCoordGen2(0, 0, 0, 0, 0, 0x52);
    newshadows_getReflectionScrollOffsets(&f1, &f2);
    f1 *= hudScale;
    f2 *= hudScale;
    getTextureFn_8006c5e4(&handle1);
    selectTexture(handle1, 1);

    PSMTXScale(mtx_ec, hudScale, hudScale, hudScale);
    mtx_ec[0][3] = f1;
    GXLoadTexMtxImm(mtx_ec, 0x21, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x21, 0, 0x7d);

    {
        f32 v = gSynthDelayedActionWord0 * f31_val;
        indMtx_44[0] = v;
        indMtx_44[1] = lbl_803DEEDC;
        indMtx_44[2] = lbl_803DEEDC;
        indMtx_44[3] = lbl_803DEEDC;
        indMtx_44[4] = v;
        indMtx_44[5] = lbl_803DEEDC;
    }
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indMtx_44, -4);
    GXSetTevIndirect(0, 0, 0, 7, 1, 6, 6, 0, 0, 0);

    PSMTXScale(mtx_bc, lbl_803DEF40, lbl_803DEF40, lbl_803DEF40);
    PSMTXRotRad(mtx_5c, 'z', lbl_803DEEF0);
    PSMTXConcat(mtx_5c, mtx_bc, mtx_bc);
    mtx_bc[0][3] = f2;
    mtx_bc[1][3] = f2;
    GXLoadTexMtxImm(mtx_bc, 0x24, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x24, 0, 0x7d);

    {
        f32 v44 = lbl_803DEF44 * f31_val;
        f32 v48 = lbl_803DEF48 * f31_val;
        indMtx_2c[0] = v44;
        indMtx_2c[1] = v44;
        indMtx_2c[2] = lbl_803DEEDC;
        indMtx_2c[3] = v48;
        indMtx_2c[4] = v44;
        indMtx_2c[5] = lbl_803DEEDC;
    }
    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD2, GX_TEXMAP1);
    GXSetIndTexCoordScale(1, 0, 0);
    GXSetIndTexMtx(2, (f32(*)[3])indMtx_2c, -4);
    GXSetTevIndirect(1, 1, 0, 7, 2, 0, 0, 1, 0, 0);

    ((f32*)mtx_8c)[0] = lbl_803DB6AC;
    ((f32*)mtx_8c)[1] = lbl_803DEEDC;
    ((f32*)mtx_8c)[2] = lbl_803DEEDC;
    ((f32*)mtx_8c)[3] = gSynthDelayedActionWord0;
    ((f32*)mtx_8c)[4] = lbl_803DEEDC;
    ((f32*)mtx_8c)[5] = lbl_803DB6AC;
    ((f32*)mtx_8c)[6] = lbl_803DEEDC;
    ((f32*)mtx_8c)[7] = gSynthDelayedActionWord0;
    ((f32*)mtx_8c)[8] = lbl_803DEEDC;
    ((f32*)mtx_8c)[9] = lbl_803DEEDC;
    ((f32*)mtx_8c)[10] = lbl_803DEEDC;
    ((f32*)mtx_8c)[11] = lbl_803DEEE4;
    GXLoadTexMtxImm((f32(*)[4])mtx_8c, 0x55, 0);
    GXSetTexCoordGen2(3, 0, 1, 0x1e, 0, 0x55);

    fn_8006C5CC(&handle2);
    selectTexture(handle2, 2);

    GXSetNumIndStages(2);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(4);
    GXSetNumTevStages(3);

    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xf);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetTevOrder(1, 0, 0, 0xff);
    GXSetTevColorIn(1, 0xf, 0xf, 0xf, 8);
    GXSetTevAlphaIn(1, 7, 7, 7, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);

    ((u8*)&temp)[3] = ((u8*)(int)handle)[0x37];
    GXSetTevKColor(0, temp);
    GXSetTevKAlphaSel(2, 0x1c);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(2, 3, 2, 0xff);
    GXSetTevColorIn(2, 0xf, 0xf, 0xf, 0);
    GXSetTevAlphaIn(2, 7, 4, 6, 7);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);

    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetCullMode(2);
    return 1;
}

void hudDrawRect(int x1, int y1, int x2, int y2, u8* color)
{
    extern void Camera_RebuildProjectionMatrix(void);
    extern Mtx hudMatrix;
    extern f32 lbl_803DEEDC;
    extern void GXSetZMode();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    extern u8 gHudTintAlpha;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    color[3] = (u8)(((s32)color[3] * gHudTintAlpha) >> 8);
    GXSetTevKColor(0, *(GXColor*)color);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevOrder(0, 0xFF, 0xFF, 4);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    GXSetTevAlphaIn(0, 7, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumChans(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1 << 2;
    GXWGFifo.s16 = y1 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2 << 2;
    GXWGFifo.s16 = y1 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2 << 2;
    GXWGFifo.s16 = y2 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1 << 2;
    GXWGFifo.s16 = y2 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    Camera_RebuildProjectionMatrix();
}

void drawViewFinderLine(u8* color, f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3, f32 x4, f32 y4)
{
    extern void Camera_RebuildProjectionMatrix(void);
    extern Mtx hudMatrix;
    extern f32 hudScale;
    extern f32 lbl_803DEEDC;
    extern void GXSetZMode();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    extern u8 gHudTintAlpha;
    f32 scale = hudScale;
    f32 fy4, fx4, fy3, fx3, fy2, fx2, fy1, fx1;
    fx1 = scale * x1;
    fy1 = scale * y1;
    fx2 = scale * x2;
    fy2 = scale * y2;
    fx3 = scale * x3;
    fy3 = scale * y3;
    fx4 = scale * x4;
    fy4 = scale * y4;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    color[3] = (u8)(((s32)color[3] * gHudTintAlpha) >> 8);
    GXSetTevKColor(0, *(GXColor*)color);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevOrder(0, 0xFF, 0xFF, 4);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    GXSetTevAlphaIn(0, 7, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumChans(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx1;
    GXWGFifo.s16 = fy1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx2;
    GXWGFifo.s16 = fy2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx3;
    GXWGFifo.s16 = fy3;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx4;
    GXWGFifo.s16 = fy4;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    Camera_RebuildProjectionMatrix();
}

void hudDrawTriangle(u8* color, f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3)
{
    extern void Camera_RebuildProjectionMatrix(void);
    extern Mtx hudMatrix;
    extern f32 hudScale;
    extern f32 lbl_803DEEDC;
    extern void GXSetZMode();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    extern u8 gHudTintAlpha;
    f32 scale = hudScale;
    f32 fy3, fx3, fy2, fx2, fy1, fx1;
    fx1 = scale * x1;
    fy1 = scale * y1;
    fx2 = scale * x2;
    fy2 = scale * y2;
    fx3 = scale * x3;
    fy3 = scale * y3;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    color[3] = (u8)(((s32)color[3] * gHudTintAlpha) >> 8);
    GXSetTevKColor(0, *(GXColor*)color);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevOrder(0, 0xFF, 0xFF, 4);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    GXSetTevAlphaIn(0, 7, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumChans(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXBegin(GX_TRIANGLES, GX_VTXFMT1, 3);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx1;
    GXWGFifo.s16 = fy1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx2;
    GXWGFifo.s16 = fy2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx3;
    GXWGFifo.s16 = fy3;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    Camera_RebuildProjectionMatrix();
}

void skyDrawFn_80075d5c(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2, int z)
{
    extern void Camera_RebuildProjectionMatrix(void);
    extern Mtx hudMatrix;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u2;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2;
    GXWGFifo.s16 = y2;
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u2;
    GXWGFifo.f32 = v2;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y2;
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v2;

    Camera_RebuildProjectionMatrix();
}

void textRenderChar(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2)
{
    extern void Camera_RebuildProjectionMatrix(void);
    extern Mtx hudMatrix;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u2;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2;
    GXWGFifo.s16 = y2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u2;
    GXWGFifo.f32 = v2;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v2;

    Camera_RebuildProjectionMatrix();
}

void drawPartialTexture(s16* obj, u8 alpha_mod, f32 sx, f32 sy, u16 scale, int width, int height, int u_offset, int v_offset)
{
    extern f32 hudScale;
    extern u8 gHudTintAlpha;
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern int gGxZModeCompareFunc;
    extern void textureFn_8004c264(s16* obj, int slot);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    GXColor c;
    s32 w;
    f32 u1, u0, v0, v1;

    c.r = 0xFF;
    c.g = 0xFF;
    c.b = 0xFF;
    c.a = (u8)(((s32)alpha_mod * gHudTintAlpha) >> 8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetTevKColor(0, c);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    if (((u32*)obj)[0x14] != 0) {
        GXSetTevKAlphaSel(1, 0x1C);
        GXSetTevOrder(1, 0, 1, 0xFF);
        GXSetTevDirect(GX_TEVSTAGE1);
        GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0);
        GXSetTevAlphaIn(1, 7, 4, 6, 7);
        GXSetTevSwapMode(1, 0, 0);
        GXSetTevColorOp(1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
        GXSetNumTevStages(2);
    } else {
        GXSetNumTevStages(1);
    }
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    textureFn_8004c264(obj, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    w = (s32)(((u32)(width << 2) * scale) >> 8);
    sx = hudScale * sx;
    sy = hudScale * sy;
    u0 = (f32)(u32)u_offset / (f32)((u16*)obj)[5];
    v0 = (f32)(u32)v_offset / (f32)((u16*)obj)[6];
    u1 = (f32)(u32)(width + u_offset) / (f32)((u16*)obj)[5];
    v1 = (f32)(u32)(height + v_offset) / (f32)((u16*)obj)[6];

    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)(((u32)(height << 2) * scale) >> 8));
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)(((u32)(height << 2) * scale) >> 8));
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;

    Camera_RebuildProjectionMatrix();
}

/*
 * Generic ortho-projected single-color quad blit. Sets the GX state up
 * fresh (no tex coords, color from constant K0, additive blend, fixed
 * 0x3C texmtx) then emits four GX_VTXFMT1 vertices at z=-0x18C with
 * width 4*size_x and height 4*size_y in screen pixels. Used as the
 * "draw fullscreen tint" primitive by the dialog code in cardShowLoadingMsg.
 */
void drawRect(f32 sx, f32 sy, int x, int y)
{
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern f32 hudScale;
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetColorUpdate(GX_FALSE);
    GXSetTevOrder(0, 0xFF, 0xFF, 4);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xC);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumChans(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 1 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_ALWAYS, GX_TRUE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 1;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 0 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_FALSE);
        gGxZCompLocCached = 0;
        gGxZCompLocValid = 1;
    }
    GXSetBlendMode(0, 1, 0, 5);
    GXSetCurrentMtx(0x3C);
    sx = hudScale * sx;
    sy = hudScale * sy;
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -0x18C;

    GXWGFifo.s16 = (s16)(sx + (f32)((u32)x * 4));
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -0x18C;

    GXWGFifo.s16 = (s16)(sx + (f32)((u32)x * 4));
    GXWGFifo.s16 = (s16)(sy + (f32)((u32)y * 4));
    GXWGFifo.s16 = -0x18C;

    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = (s16)(sy + (f32)((u32)y * 4));
    GXWGFifo.s16 = -0x18C;

    Camera_RebuildProjectionMatrix();
    GXSetColorUpdate(GX_TRUE);
}

void drawScaledTexture(s16* obj, u8 alpha_mod, f32 sx, f32 sy, u16 scale, int width, int height, u8 flags)
{
    extern f32 hudScale;
    extern f32 lbl_803DEEDC;
    extern u8 gHudTintAlpha;
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern int gGxZModeCompareFunc;
    extern void textureFn_8004c264(s16* obj, int slot);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    GXColor c;
    s32 w, h;
    f32 u0, u1, v0, v1;
    u8 fbits;

    c.r = 0xFF;
    c.g = 0xFF;
    c.b = 0xFF;
    c.a = (u8)(((s32)alpha_mod * gHudTintAlpha) >> 8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetTevKColor(0, c);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    if (((u32*)obj)[0x14] != 0) {
        GXSetTevKAlphaSel(1, 0x1C);
        GXSetTevOrder(1, 0, 1, 0xFF);
        GXSetTevDirect(GX_TEVSTAGE1);
        GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0);
        GXSetTevAlphaIn(1, 7, 4, 6, 7);
        GXSetTevSwapMode(1, 0, 0);
        GXSetTevColorOp(1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
        GXSetNumTevStages(2);
    } else {
        GXSetNumTevStages(1);
    }
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    textureFn_8004c264(obj, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    fbits = flags;
    if ((fbits & 4) != 0) {
        GXSetBlendMode(1, 4, 1, 5);
    } else {
        GXSetBlendMode(1, 4, 5, 5);
    }
    w = (s32)(((u32)(width << 2) * scale) >> 8);
    h = (s32)(((u32)(height << 2) * scale) >> 8);
    sx = hudScale * sx;
    sy = hudScale * sy;
    {
        f32 ur = (f32)(u32)width / (f32)(u16)((u16*)obj)[5];
        f32 vr = (f32)(u32)height / (f32)(u16)((u16*)obj)[6];
        if ((fbits & 1) != 0) {
            u0 = ur;
            u1 = lbl_803DEEDC;
        } else {
            u0 = lbl_803DEEDC;
            u1 = ur;
        }
        if ((fbits & 2) != 0) {
            v0 = vr;
            v1 = lbl_803DEEDC;
        } else {
            v0 = lbl_803DEEDC;
            v1 = vr;
        }
    }
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)h);
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)h);
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;

    Camera_RebuildProjectionMatrix();
}

/*
 * Caller-coloured asset blit. Same mechanic as drawTexture but the K0
 * color comes from a writable GXColor the caller passes in (we apply the
 * gHudTintAlpha alpha tint to it in place). The flag arg picks between
 * "raster passthrough" (TevColorIn 0xF/0xF/0xF/0xE) and "K-tint replace"
 * (TevColorIn 0xF/0xE/0x8/0xF).
 */
void hudDrawColored(s16* obj, int x, int y, GXColor* color, u16 scale, u8 flag)
{
    extern f32 hudScale;
    extern const f32 lbl_803DEEDC;
    extern const f32 lbl_803DEEE4;
    extern u8 gHudTintAlpha;
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern int gGxZModeCompareFunc;
    extern void textureFn_8004c264(s16* obj, int slot);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    color->a = (u8)(((s32)color->a * gHudTintAlpha) >> 8);
    GXSetTevKColor(0, *color);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(GX_TEVSTAGE0);
    if (flag != 0) {
        GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    } else {
        GXSetTevColorIn(0, 0xF, 0xE, 0x8, 0xF);
    }
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 2, 1, 0);
    if (((u32*)obj)[0x14] != 0) {
        GXSetTevKAlphaSel(1, 0x1C);
        GXSetTevOrder(0, 0, 1, 0xFF);
        GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0);
        GXSetTevAlphaIn(1, 7, 4, 6, 7);
        GXSetTevSwapMode(1, 0, 0);
        GXSetTevColorOp(1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(1, 0, 0, 2, 1, 0);
        GXSetNumTevStages(2);
    } else {
        GXSetNumTevStages(1);
    }
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    textureFn_8004c264(obj, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if (flag != 0) {
        GXSetBlendMode(1, 4, 1, 5);
    } else {
        GXSetBlendMode(1, 4, 5, 5);
    }
    {
        s32 w, h;
        w = ((((u16*)obj)[5] << 2) * scale) / 256;
        h = ((((u16*)obj)[6] << 2) * scale) / 256;
        GXBegin(GX_QUADS, GX_VTXFMT1, 4);

        GXWGFifo.u8 = 0x3C;
        GXWGFifo.s16 = (s16)(x << 2);
        GXWGFifo.s16 = (s16)(y << 2);
        GXWGFifo.s16 = -8;
        GXWGFifo.f32 = lbl_803DEEDC;
        GXWGFifo.f32 = lbl_803DEEDC;

        GXWGFifo.u8 = 0x3C;
        GXWGFifo.s16 = (s16)((x << 2) + w);
        GXWGFifo.s16 = (s16)(y << 2);
        GXWGFifo.s16 = -8;
        GXWGFifo.f32 = *(const f32*)&lbl_803DEEE4;
        GXWGFifo.f32 = lbl_803DEEDC;

        GXWGFifo.u8 = 0x3C;
        GXWGFifo.s16 = (s16)((x << 2) + w);
        GXWGFifo.s16 = (s16)((y << 2) + h);
        GXWGFifo.s16 = -8;
        GXWGFifo.f32 = lbl_803DEEE4;
        GXWGFifo.f32 = lbl_803DEEE4;

        GXWGFifo.u8 = 0x3C;
        GXWGFifo.s16 = (s16)(x << 2);
        GXWGFifo.s16 = (s16)((y << 2) + h);
        GXWGFifo.s16 = -8;
        GXWGFifo.f32 = lbl_803DEEDC;
        GXWGFifo.f32 = lbl_803DEEE4;
    }
    Camera_RebuildProjectionMatrix();
}

/*
 * Quad-from-asset blit: takes an "asset record" (with width at +0xA,
 * height at +0xC, and an optional second-stage flag at +0x50), a per-
 * call alpha multiplier, screen-pos (sx, sy), and a u16 size scale.
 * Composes K0 from RGB(255,255,255) plus the global alpha tint
 * (alpha * gHudTintAlpha >> 8); if the asset opts in, layers a second
 * tex stage that further K-multiplies by the texture. Final width and
 * height are 4 * asset_dim * scale >> 8 in screen pixels at z=-8.
 */
void drawTexture(s16* obj, u8 alpha_mod, f32 sx, f32 sy, u16 scale)
{
    extern f32 hudScale;
    extern f32 lbl_803DEEDC;
    extern f32 lbl_803DEEE4;
    extern u8 gHudTintAlpha;
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern int gGxZModeCompareFunc;
    extern void textureFn_8004c264(s16* obj, int slot);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    GXColor c;
    s32 w, h;

    c.r = 0xFF;
    c.g = 0xFF;
    c.b = 0xFF;
    c.a = (u8)(((s32)alpha_mod * gHudTintAlpha) >> 8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetTevKColor(0, c);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    if (((u32*)obj)[0x14] != 0) {
        GXSetTevKAlphaSel(1, 0x1C);
        GXSetTevOrder(1, 0, 1, 0xFF);
        GXSetTevDirect(GX_TEVSTAGE1);
        GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0);
        GXSetTevAlphaIn(1, 7, 4, 6, 7);
        GXSetTevSwapMode(1, 0, 0);
        GXSetTevColorOp(1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
        GXSetNumTevStages(2);
    } else {
        GXSetNumTevStages(1);
    }
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    textureFn_8004c264(obj, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    w = ((((u16*)obj)[5] << 2) * scale) / 256;
    h = ((((u16*)obj)[6] << 2) * scale) / 256;
    sx = hudScale * sx;
    sy = hudScale * sy;
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEE4;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)h);
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEE4;
    GXWGFifo.f32 = lbl_803DEEE4;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)h);
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEE4;

    Camera_RebuildProjectionMatrix();
}

void objectShadow_setupSwappedProjectedTexture(f32* obj, u32* colorPtr, Mtx mtx)
{
    extern void fn_8004C460(int, int);
    extern GXColor lbl_803DC308;
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    Mtx tmp;

    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_ALPHA, GX_CH_RED, GX_CH_ALPHA, GX_CH_RED);
    PSMTXConcat((float(*)[4])obj, mtx, tmp);
    GXLoadTexMtxImm(tmp, 0x1E, 1);
    GXSetTexCoordGen2(0, 1, 0, 0x1E, 0, 0x7D);
    fn_8004C460(*(int*)(obj + 0x18), 0);
    GXSetTevKColor(0, *(GXColor*)colorPtr);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevColor(2, lbl_803DC308);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    GXSetTevAlphaIn(0, 2, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 1);
    GXSetTevColorOp(0, 0, 0, 0, 0, 1);
    GXSetTevAlphaOp(0, 0xE, 0, 0, 1, 0);
    GXSetBlendMode(1, 4, 5, 5);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void objectShadow_setupProjectedTexture(f32* obj, u32* colorPtr, Mtx mtx)
{
    extern void fn_8004C460(int, int);
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    Mtx tmp;

    PSMTXConcat((float(*)[4])obj, mtx, tmp);
    GXLoadTexMtxImm(tmp, 0x1E, 1);
    GXSetTexCoordGen2(0, 1, 0, 0x1E, 0, 0x7D);
    fn_8004C460(*(int*)(obj + 0x18), 0);
    GXSetTevKColor(0, *(GXColor*)colorPtr);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetBlendMode(1, 4, 5, 5);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void fn_80077AD8(u8 *st, u8 *p2, f32 *m, f32 depth)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern f32 gFogEndZ, gFogStartZ, gFogFarZ, gFogNearZ;
    extern GXColor lbl_803E8454;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern void selectTexture(int tex, int slot);
    extern void fn_8006C5B8(int *out);
    Mtx m58;
    Mtx m28;
    Vec v;
    GXColor c;
    int handle;
    GXColor kc;
    f32 z;
    f32 d;
    f32 q;
    u8 t;

    kc = lbl_803E8454;
    PSMTXConcat((MtxP)st, (MtxP)m, m58);
    GXLoadTexMtxImm(m58, 0x1e, 1);
    GXSetTexCoordGen2(0, 1, 0, 0x1e, 0, 0x7d);
    selectTexture(*(int *)(st + 0x60), 0);
    t = p2[3];
    p2[3] = (t >> 1) + (t >> 2);
    c.r = p2[3];
    c.g = p2[3];
    c.b = p2[3];
    GXSetTevKColor(0, c);
    GXSetTevKColorSel(0, 0xc);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xf, 8, 0xe, 0xf);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    v.x = m[3];
    v.y = m[7];
    v.z = m[11];
    PSMTXMultVec((MtxP)(st + 0x30), &v, &v);
    z = -v.z;
    fn_8006C5B8(&handle);
    selectTexture(handle, 1);
    m58[0][0] = lbl_803DEEDC;
    m58[0][1] = lbl_803DEEDC;
    d = z - depth;
    m58[0][2] = lbl_803DEEE4 / (q = z - d);
    m58[0][3] = z / q;
    m58[1][0] = lbl_803DEEDC;
    m58[1][1] = lbl_803DEEDC;
    m58[1][2] = lbl_803DEEDC;
    m58[1][3] = lbl_803DEEDC;
    PSMTXConcat((MtxP)(st + 0x30), (MtxP)m, m28);
    PSMTXConcat(m58, m28, m28);
    GXLoadTexMtxImm(m28, 0x21, 1);
    GXSetTexCoordGen2(1, 1, 0, 0x21, 0, 0x7d);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevOrder(1, 1, 1, 0xff);
    GXSetTevColorIn(1, 0, 0xf, 8, 0xf);
    GXSetTevAlphaIn(1, 7, 7, 7, 7);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(2);
    GXSetNumTevStages(2);
    GXSetFog(GX_FOG_PERSP_EXP, gFogStartZ, gFogEndZ, gFogNearZ, gFogFarZ, kc);
    GXSetBlendMode(1, 0, 3, 5);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void fn_80077EF8(void* obj, u8* node, Mtx mtx, f32 scale)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern u32 lbl_803DEEAC;
    extern u8 lbl_803DEEB0;
    extern u8 lbl_803DEEB2;
    extern u32 lbl_803E8450;
    extern f32 gFogStartZ, gFogEndZ, gFogNearZ, gFogFarZ;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern u8 lbl_802C1EA8[0xC0];
    extern void selectTexture(int handle, int slot);
    extern void fn_8006C5B8(int* out);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    typedef struct { u32 w[7]; } Blk28;
    Mtx mtx_110;
    Mtx mtx_e0;
    Blk28 buf_c4;
    Blk28 buf_a8;
    Blk28 buf_8c;
    Blk28 buf_70;
    Blk28 buf_54;
    Blk28 buf_38;
    u32 stab1;
    u32 stab0;
    GXColor temp;
    GXColor color2;
    GXColor fog_var;
    f32 vec3[3];
    int handle;
    int stage_idx;
    u32 stage_count;
    int stage_base;
    f32 f31_val;

    buf_c4 = *(Blk28*)(lbl_802C1EA8 + 0x18);
    buf_a8 = *(Blk28*)(lbl_802C1EA8 + 0x34);
    buf_8c = *(Blk28*)(lbl_802C1EA8 + 0x50);
    buf_70 = *(Blk28*)(lbl_802C1EA8 + 0x6C);
    buf_54 = *(Blk28*)(lbl_802C1EA8 + 0x88);
    buf_38 = *(Blk28*)(lbl_802C1EA8 + 0xA4);
    stab0 = lbl_803DEEAC;
    *(u16*)((u8*)&stab1 + 0) = *(u16*)&lbl_803DEEB0;
    ((u8*)&stab1)[2] = lbl_803DEEB2;
    *(u32*)&fog_var = lbl_803E8450;

    PSMTXConcat((f32(*)[4])((u8*)lbl_802C1EA8 + 0xB8), mtx, mtx_110);
    GXLoadTexMtxImm(mtx_110, 0x1e, 1);
    GXSetTexCoordGen2(0, 1, 0, 0x1e, 0, 0x7d);

    selectTexture(*(int *)&((GameObject *)obj)->anim.eventTable, 0);

    if (((u8*)obj)[0x65] < 8) {
        GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_RED);
        stage_idx = ((u8*)obj)[0x65] - 1;
    } else if (((u8*)obj)[0x65] < 0x10) {
        GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_ALPHA, GX_CH_ALPHA, GX_CH_ALPHA, GX_CH_ALPHA);
        stage_idx = ((u8*)obj)[0x65] - 9;
    }
    if (stage_idx < 0) stage_idx = 0;

    ((u8*)&color2)[0] = 0x7F;
    ((u8*)&color2)[1] = 0x7F;
    ((u8*)&color2)[2] = 0x7F;
    GXSetTevColor(1, color2);

    node[3] = (u8)((node[3] >> 1) + (node[3] >> 2));
    ((u8*)&temp)[0] = node[3];
    ((u8*)&temp)[1] = node[3];
    ((u8*)&temp)[2] = node[3];
    GXSetTevKColor(0, temp);

    stage_base = 0;
    stage_count = ((u8*)&stab0)[stage_idx];
    if (stage_count != 0) {
        GXSetTevDirect(GX_TEVSTAGE0);
        GXSetTevSwapMode(0, 0, 1);
        GXSetTevOrder(0, 0, 0, 0xFF);
        GXSetTevColorIn(0, 0xF, 0x8, 0xC, buf_c4.w[stage_idx]);
        GXSetTevAlphaIn(0, 7, 7, 7, 7);
        GXSetTevColorOp(0, 0, 0, buf_a8.w[stage_idx], 0, 0);
        GXSetTevAlphaOp(0, 0, 0, 0, 0, 0);
        stage_base = 1;
    }

    if (stage_count > 1) {
        GXSetTevDirect(stage_base);
        GXSetTevSwapMode(stage_base, 0, 0);
        GXSetTevOrder(stage_base, 0xFF, 0xFF, 0xFF);
        GXSetTevColorIn(stage_base, 0xF, 0, 0xC, buf_8c.w[stage_idx]);
        GXSetTevAlphaIn(stage_base, 7, 7, 7, 7);
        GXSetTevColorOp(stage_base, 0, 0, buf_70.w[stage_idx], 0, 0);
        GXSetTevAlphaOp(stage_base, 0, 0, 0, 0, 0);
        stage_base++;
    }

    if (stage_count > 2) {
        GXSetTevDirect(stage_base);
        GXSetTevSwapMode(stage_base, 0, 0);
        GXSetTevOrder(stage_base, 0xFF, 0xFF, 0xFF);
        GXSetTevColorIn(stage_base, 0xF, 0, 0xC, buf_54.w[stage_idx]);
        GXSetTevAlphaIn(stage_base, 7, 7, 7, 7);
        GXSetTevColorOp(stage_base, 0, 0, buf_38.w[stage_idx], 0, 0);
        GXSetTevAlphaOp(stage_base, 0, 0, 0, 0, 0);
        stage_base++;
    }

    GXSetTevDirect(stage_base);
    GXSetTevSwapMode(stage_base, 0, 0);
    GXSetTevKColorSel(stage_base, 0xC);
    GXSetTevOrder(stage_base, 0xFF, 0xFF, 0xFF);
    if (stage_count == 0) {
        GXSetTevColorIn(stage_base, 8, 2, 0xE, 0xF);
    } else {
        GXSetTevColorIn(stage_base, 0, 2, 0xE, 0xF);
    }
    GXSetTevAlphaIn(stage_base, 7, 7, 7, 7);
    GXSetTevColorOp(stage_base, 8, 0, 0, 1, 0);
    GXSetTevAlphaOp(stage_base, 0, 0, 0, 1, 0);

    vec3[0] = mtx[0][3];
    vec3[1] = mtx[1][3];
    vec3[2] = mtx[2][3];
    PSMTXMultVec((f32(*)[4])((u8*)(int)obj + 0x30), (Vec*)vec3, (Vec*)vec3);
    f31_val = -vec3[2];

    fn_8006C5B8(&handle);
    selectTexture(handle, 1);

    {
        f32 d2;
        mtx_110[0][0] = lbl_803DEEDC;
        mtx_110[0][1] = lbl_803DEEDC;
        mtx_110[0][2] = lbl_803DEEE4 / (d2 = f31_val - (f31_val - scale));
        mtx_110[0][3] = f31_val / d2;
        mtx_110[1][0] = lbl_803DEEDC;
        mtx_110[1][1] = lbl_803DEEDC;
        mtx_110[1][2] = lbl_803DEEDC;
        mtx_110[1][3] = lbl_803DEEDC;
    }
    PSMTXConcat((f32(*)[4])((u8*)obj + 0x30), mtx, mtx_e0);
    PSMTXConcat(mtx_110, mtx_e0, mtx_e0);
    GXLoadTexMtxImm(mtx_e0, 0x21, 1);
    GXSetTexCoordGen2(1, 1, 0, 0x21, 0, 0x7d);

    GXSetTevDirect(stage_base + 1);
    GXSetTevSwapMode(stage_base + 1, 0, 0);
    GXSetTevOrder(stage_base + 1, 1, 1, 0xFF);
    GXSetTevColorIn(stage_base + 1, 0, 0xF, 8, 0xF);
    GXSetTevAlphaIn(stage_base + 1, 7, 7, 7, 7);
    GXSetTevColorOp(stage_base + 1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(stage_base + 1, 0, 0, 0, 1, 0);

    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(2);
    GXSetNumTevStages((u8)(stage_count + 2));

    GXSetFog(GX_FOG_PERSP_EXP, gFogStartZ, gFogEndZ, gFogNearZ, gFogFarZ, fog_var);
    GXSetBlendMode(1, 0, 3, 5);

    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void fn_80078740(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 1 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 1;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(0, 1, 0, 5);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void fn_8007880C(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(0, 1, 0, 5);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void fn_800788DC(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(1, 4, 1, 5);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void gxBlendFn_800789ac(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(1, 4, 1, 5);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void textBlendSetupFn_80078a7c(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void gxBlendFn_80078b4c(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void gxDebugTextureFn_80078c1c(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 gGxZModeUpdateEnable;
    extern int gGxZModeCompareFunc;
    extern u8 gGxZModeCompareEnable;
    GXSetCullMode(0);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(0, 0xF, 8, 2, 0xF);
    GXSetTevAlphaIn(0, 7, 7, 7, 4);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void fn_80078DFC(void)
{
    GXSetTevOrder(gTevStageCursor, 0xFF, 0xFF, 4);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, 0xF, 0, 10, 0xF);
    GXSetTevAlphaIn(gTevStageCursor, 7, 0, 5, 7);
    GXSetTevSwapMode(gTevStageCursor, 0, 0);
    GXSetTevColorOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(gTevStageCursor, 0, 0, 0, 1, 0);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevChanCount += 1;
}

void fn_80078ED0(void)
{
    GXSetTevOrder(gTevStageCursor, 0xFF, 0xFF, 4);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, 0xF, 10, 4, 0xF);
    GXSetTevAlphaIn(gTevStageCursor, 7, 5, 2, 7);
    GXSetTevSwapMode(gTevStageCursor, 0, 0);
    GXSetTevColorOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(gTevStageCursor, 0, 0, 0, 1, 0);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevChanCount += 1;
}

void textRenderSetup(void)
{
    GXSetTevOrder(gTevStageCursor, gTevTexCoordCursor, gTevTexMapCursor, 0xFF);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, 4, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(gTevStageCursor, 7, 2, 4, 7);
    GXSetTevSwapMode(gTevStageCursor, 0, 0);
    GXSetTevColorOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTexCoordGen2(gTevTexCoordCursor, 1, 4, 0x3C, 0, 0x7D);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevTexCoordCursor += 1;
    gTevTexGenCount += 1;
    gTevTexMapCursor += 1;
}

void fn_800790AC(void)
{
    GXSetTevOrder(gTevStageCursor, 0xFF, 0xFF, 4);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, 0xF, 0xF, 0xF, 4);
    GXSetTevAlphaIn(gTevStageCursor, 7, 7, 7, 2);
    GXSetTevSwapMode(gTevStageCursor, 0, 0);
    GXSetTevColorOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(gTevStageCursor, 0, 0, 0, 1, 0);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevChanCount += 1;
}

void fn_80079180(void)
{
    GXSetTevOrder(gTevStageCursor, 0xFF, 0xFF, 4);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, 0xF, 0xF, 0xF, 10);
    GXSetTevAlphaIn(gTevStageCursor, 7, 7, 7, 5);
    GXSetTevSwapMode(gTevStageCursor, 0, 0);
    GXSetTevColorOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(gTevStageCursor, 0, 0, 0, 1, 0);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevChanCount += 1;
}

void gxTexColorFn_80079254(void)
{
    GXSetTevOrder(gTevStageCursor, 0xFF, 0xFF, 4);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, 0xF, 0, 4, 0xF);
    GXSetTevAlphaIn(gTevStageCursor, 7, 0, 2, 7);
    GXSetTevSwapMode(gTevStageCursor, 0, 0);
    GXSetTevColorOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(gTevStageCursor, 0, 0, 0, 1, 0);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevChanCount += 1;
}

void gxTevAddTextureFrameBlendStages(void)
{
    GXSetTevOrder(gTevStageCursor, gTevTexCoordCursor, gTevTexMapCursor, 0xFF);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(gTevStageCursor, 7, 7, 7, 4);
    GXSetTevSwapMode(gTevStageCursor, 0, 0);
    GXSetTevColorOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(gTevStageCursor, 0, 0, 0, 1, 0);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevTexMapCursor += 1;
    GXSetTevOrder(gTevStageCursor, gTevTexCoordCursor, gTevTexMapCursor, 0xFF);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, 0, 8, 3, 0xF);
    GXSetTevAlphaIn(gTevStageCursor, 0, 4, 1, 7);
    GXSetTevSwapMode(gTevStageCursor, 0, 0);
    GXSetTevColorOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTexCoordGen2(gTevTexCoordCursor, 1, 4, 0x3C, 0, 0x7D);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevTexCoordCursor += 1;
    gTevTexGenCount += 1;
    gTevTexMapCursor += 1;
}

void gxTextureFn_800794e0(void)
{
    GXSetTevOrder(gTevStageCursor, gTevTexCoordCursor, gTevTexMapCursor, 0xFF);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, 0xF, 0xF, 0xF, 4);
    GXSetTevAlphaIn(gTevStageCursor, 7, 4, 2, 7);
    GXSetTevSwapMode(gTevStageCursor, 0, 0);
    GXSetTevColorOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTexCoordGen2(gTevTexCoordCursor, 1, 4, 0x3C, 0, 0x7D);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevTexMapCursor += 1;
    gTevTexCoordCursor += 1;
    gTevTexGenCount += 1;
}

void textRenderSetupFn_800795e8(void)
{
    GXSetTevOrder(gTevStageCursor, gTevTexCoordCursor, gTevTexMapCursor, 0xFF);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, 0xF, 8, 4, 0xF);
    GXSetTevAlphaIn(gTevStageCursor, 7, 4, 2, 7);
    GXSetTevSwapMode(gTevStageCursor, 0, 0);
    GXSetTevColorOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTexCoordGen2(gTevTexCoordCursor, 1, 4, 0x3C, 0, 0x7D);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevTexMapCursor += 1;
    gTevTexCoordCursor += 1;
    gTevTexGenCount += 1;
}

void geomDrawFn_800796f0(void)
{
    GXSetTevOrder(gTevStageCursor, gTevTexCoordCursor, gTevTexMapCursor, 4);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, 0xF, 8, 10, 0xF);
    GXSetTevAlphaIn(gTevStageCursor, 7, 4, 5, 7);
    GXSetTevSwapMode(gTevStageCursor, 0, 0);
    GXSetTevColorOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(gTevStageCursor, 0, 0, 0, 1, 0);
    GXSetTexCoordGen2(gTevTexCoordCursor, 1, 4, 0x3C, 0, 0x7D);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevTexMapCursor += 1;
    gTevTexCoordCursor += 1;
    gTevTexGenCount += 1;
    gTevChanCount += 1;
}

/*
 * Closes out the TEV pipeline configuration that drawViewFinderAperture etc. open:
 * pushes the current ind-stage / chan-ctrl / tex-gen counts in
 * gTevIndStageCount..00B back into GX, and if the global tint alpha
 * gHudTintAlpha isn't fully transparent (0xFF) appends one final TEV
 * stage that K-multiplies the tint over the existing color, advancing
 * gTevStageCursor (TEV stage cursor) and gTevStageCount (stage count).
 */
void textRenderSetupFn_80079804(void)
{
    extern u8 gTevIndStageCount, gTevChanCount, gTevTexGenCount, gTevStageCount;
    extern u8 gHudTintAlpha;
    extern u32 gTevStageCursor;
    GXColor c;

    GXSetNumIndStages(gTevIndStageCount);
    if (gTevChanCount != 0) {
        GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
        GXSetNumChans(1);
    } else {
        GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
        GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
        GXSetNumChans(0);
    }
    GXSetNumTexGens(gTevTexGenCount);
    if (gHudTintAlpha < 0xFF) {
        c.a = gHudTintAlpha;
        GXSetTevKColor(0, c);
        GXSetTevKAlphaSel(gTevStageCursor, 0x1C);
        GXSetTevOrder(gTevStageCursor, 0xFF, 0xFF, 0xFF);
        GXSetTevDirect(gTevStageCursor);
        GXSetTevColorIn(gTevStageCursor, 0xF, 0xF, 0xF, 0);
        GXSetTevAlphaIn(gTevStageCursor, 7, 0, 6, 7);
        GXSetTevSwapMode(gTevStageCursor, 0, 0);
        GXSetTevColorOp(gTevStageCursor, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(gTevStageCursor, 0, 0, 0, 1, 0);
        gTevStageCursor = gTevStageCursor + 1;
        gTevStageCount++;
    }
    GXSetNumTevStages(gTevStageCount);
    if (gTevChanCount != 0) {
        GXSetChanCtrl(4, 0, 0, 1, 0, 0, 2);
    }
}

void textureSetupFn_800799c0(void)
{
    gTevIndStageCount = 0;
    gTevChanCount = 0;
    gTevTexGenCount = 0;
    gTevStageCount = 0;
    gTevStageCursor = 0;
    gTevTexCoordCursor = 0;
    gTevTexMapCursor = 0;
}

void _gxSetTevColor2(u8 r, u8 g, u8 b, u8 a)
{
    GXColor c;
    c.r = r;
    c.g = g;
    c.b = b;
    c.a = a;
    GXSetTevColor(GX_TEVREG1, c);
}

void _gxSetTevColor1(u8 r, u8 g, u8 b, u8 a)
{
    GXColor c;
    c.r = r;
    c.g = g;
    c.b = b;
    c.a = a;
    GXSetTevColor(GX_TEVREG0, c);
}

/*
 * Fullscreen 640x480 texture-tinted quad with shape-controlled alpha:
 * `flag != 0` lights the screen with three pre-set GXColors stamped into
 * K0/T1/T2; `flag == 0` instead does a single K0 modulate where K0's
 * alpha is the caller's byte divided by 4. Builds a per-call 3x4 tex
 * coord matrix that scales the source texture by 1/sx and 1/sy with a
 * sub-pixel offset baked from lbl_803DEF4C/50.
 */
void drawViewFinderAperture(f32 sx, f32 sy, u8 a, u8 flag)
{
    extern u32 lbl_803DEEA0;
    extern u32 lbl_803DEEA4;
    extern u32 lbl_803DEEA8;
    extern f32 lbl_803DEEDC;
    extern f32 gSynthDelayedActionWord0;
    extern f32 lbl_803DEEE4;
    extern f32 lbl_803DEF4C;
    extern f32 lbl_803DEF50;
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern void fn_8006C540(int*);
    extern void selectTexture(int, int);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    int handle;
    GXColor c0, c1, c2;
    Mtx mtx;

    *(u32*)&c0 = lbl_803DEEA0;
    *(u32*)&c1 = lbl_803DEEA4;
    *(u32*)&c2 = lbl_803DEEA8;
    fn_8006C540(&handle);
    selectTexture(handle, 0);
    {
        f32 dec = *(f32*)&gSynthDelayedActionWord0;
        f32 zero = lbl_803DEEDC;
        f32 inv_sx = dec / sx;
        f32 inv_sy = dec / sy;
        mtx[0][0] = inv_sx;
        mtx[0][1] = zero;
        mtx[0][2] = zero;
        mtx[0][3] = lbl_803DEF4C * inv_sx + dec;
        mtx[1][0] = zero;
        mtx[1][1] = inv_sy;
        mtx[1][2] = zero;
        mtx[1][3] = lbl_803DEF50 * inv_sy + dec;
        mtx[2][0] = zero;
        mtx[2][1] = zero;
        mtx[2][2] = zero;
        mtx[2][3] = lbl_803DEEE4;
    }
    GXSetTexCoordGen2(0, 1, 0, 0x1E, 0, 0x7D);
    GXLoadTexMtxImm(mtx, 0x1E, 1);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    if (flag != 0) {
        c0.a = a;
        GXSetTevKColor(0, c0);
        GXSetTevColor(1, c1);
        GXSetTevColor(2, c2);
        GXSetTevAlphaIn(0, 4, 1, 2, 6);
        GXSetTevAlphaOp(0, 0xE, 0, 0, 1, 0);
    } else {
        c0.a = (u8)((s32)a >> 2);
        GXSetTevKColor(0, c0);
        GXSetTevAlphaIn(0, 4, 7, 7, 6);
        GXSetTevAlphaOp(0, 0, 0, 2, 1, 0);
    }
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXClearVtxDesc();
    GXSetCurrentMtx(0x3C);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(1, 5, 4, 5);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;

    Camera_RebuildProjectionMatrix();
    GXSetCurrentMtx(0);
}

void drawFn_80079e64(f32 s1, f32 s2, f32 s3, u8 mtxIdx, void* vec, u8 alpha0, u8 alpha1)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4, lbl_803DEEF4;
    extern f32 lbl_803DEF54, lbl_803DEF58, lbl_803DEF5C, lbl_803DEF60, lbl_803DEF64, lbl_803DEF68;
    extern f32 lbl_803DD00C;
    extern f32 gSynthFadeMask, gSynthDelayedActionWord0, timeDelta;
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern u16 fn_8000FA90(void);
    extern u16 fn_8000FA70(void);
    extern int getHudHiddenFrameCount(void);
    extern f32 fn_80292194(f32 v);
    extern f32 interpolate(f32 a, f32 t, f32 exp);
    extern void getReflectionTexture2(int* out);
    extern void fn_8006C4F8(int* out);
    extern void selectTexture(int handle, int slot);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_58;
    Mtx mtx_28;
    int handle1;
    int handle2;
    f32 ratio1;
    f32 angle;
    f32 ratio2;
    GXColor c_K2;
    GXColor c_K0;
    GXColor c_K1;

    c_K0.a = alpha0;
    c_K1.a = alpha1;
    ratio1 = ((f32)(u32)fn_8000FA90() - lbl_803DEF54) / lbl_803DEF58;
    ratio2 = ((f32)(u32)fn_8000FA70() - lbl_803DEF54) / lbl_803DEF58;
    if (getHudHiddenFrameCount() != 0) {
        angle = lbl_803DD00C;
    } else {
        f32 t = fn_80292194(((f32*)vec)[0] / ((f32*)vec)[1]);
        angle = lbl_803DD00C + interpolate(t - lbl_803DD00C, lbl_803DEF5C, timeDelta);
        lbl_803DD00C = angle;
    }
    c_K2.a = mtxIdx;

    getReflectionTexture2(&handle1);
    selectTexture(handle1, 0);
    fn_8006C4F8(&handle2);
    selectTexture(handle2, 1);

    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);

    PSMTXScale(mtx_58, lbl_803DEF60 * (f32)s2, lbl_803DEF60 * (f32)s2, lbl_803DEEDC);
    PSMTXTrans(mtx_28, ratio1 * (f32)s3, ratio2 * (f32)s3 + (f32)s1, lbl_803DEEDC);
    PSMTXConcat(mtx_28, mtx_58, mtx_58);
    PSMTXRotRad(mtx_28, 'z', angle);
    PSMTXConcat(mtx_58, mtx_28, mtx_58);
    PSMTXTrans(mtx_28, lbl_803DEEF4, *(f32 *)&lbl_803DEEF4, lbl_803DEEDC);
    PSMTXConcat(mtx_58, mtx_28, mtx_58);
    GXLoadTexMtxImm(mtx_58, 0x1e, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x1e, 0, 0x7d);

    PSMTXScale(mtx_58, lbl_803DEF64 * (f32)s2, lbl_803DEF64 * (f32)s2, lbl_803DEEDC);
    PSMTXTrans(mtx_28, gSynthFadeMask * ratio1 * (f32)s3,
                       lbl_803DEF68 * (f32)s1 + gSynthFadeMask * ratio2 * (f32)s3,
                       lbl_803DEEDC);
    PSMTXConcat(mtx_28, mtx_58, mtx_58);
    PSMTXRotRad(mtx_28, 'z', gSynthDelayedActionWord0 * angle);
    PSMTXConcat(mtx_58, mtx_28, mtx_58);
    PSMTXTrans(mtx_28, lbl_803DEEF4, *(f32 *)&lbl_803DEEF4, lbl_803DEEDC);
    PSMTXConcat(mtx_58, mtx_28, mtx_58);
    GXLoadTexMtxImm(mtx_58, 0x21, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x21, 0, 0x7d);

    GXSetTevKColor(0, c_K0);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(0, 6, 7, 7, 4);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 1, 0, 2, 1, 0);

    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(1, 1, 1, 0xFF);
    GXSetTevColorIn(1, 8, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(1, 7, 0, 4, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 1, 1, 0);

    GXSetTevKColor(1, c_K1);
    GXSetTevKAlphaSel(2, 0x1D);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(2, 0, 0, 0xFF);
    GXSetTevColorIn(2, 0xF, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(2, 6, 7, 7, 4);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(2, 1, 0, 2, 1, 1);

    GXSetTevDirect(GX_TEVSTAGE3);
    GXSetTevOrder(3, 2, 1, 0xFF);
    GXSetTevColorIn(3, 8, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(3, 7, 1, 4, 7);
    GXSetTevSwapMode(3, 0, 0);
    GXSetTevColorOp(3, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(3, 0, 0, 2, 1, 1);

    GXSetTevKAlphaSel(4, 0);
    GXSetTevDirect(GX_TEVSTAGE4);
    GXSetTevOrder(4, 0xFF, 0xFF, 0xFF);
    GXSetTevColorIn(4, 0, 2, 3, 0xF);
    GXSetTevAlphaIn(4, 0, 6, 1, 7);
    GXSetTevSwapMode(4, 0, 0);
    GXSetTevColorOp(4, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(4, 0, 0, 0, 1, 0);

    GXSetTevKColor(2, c_K2);
    GXSetTevKAlphaSel(5, 0x1E);
    GXSetTevDirect(GX_TEVSTAGE5);
    GXSetTevOrder(5, 0xFF, 0xFF, 0xFF);
    GXSetTevColorIn(5, 0xF, 0xF, 0xF, 0);
    GXSetTevAlphaIn(5, 7, 0, 6, 7);
    GXSetTevSwapMode(5, 0, 0);
    GXSetTevColorOp(5, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(5, 0, 0, 0, 1, 0);

    GXSetNumTexGens(3);
    GXSetNumTevStages(6);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);

    GXClearVtxDesc();
    GXSetCurrentMtx(0x3C);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 1 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LESS, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 1;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
    GXSetCurrentMtx(0);
}

void doHeatEffect(u8 alpha)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern f32 lbl_803DEF6C, lbl_803DEF70, lbl_803DEF74;
    extern f32 gSynthDelayedActionWord0;
    extern GXColor lbl_803DB6A4;
    extern u8 lbl_802C1EA8[];
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern s16 fn_8000FA70(void);
    extern void selectReflectionTexture(int);
    extern void getReflectionTexture2(int* out);
    extern void getTextureFn_8006c5e4(int* out);
    extern void newshadows_getReflectionScrollOffsets(f32* a, f32* b);
    extern void fn_80293C64(f32* a, f32* b, f32 c);
    extern void selectTexture(int handle, int slot);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    extern Mtx hudMatrix;
    extern void Camera_RebuildProjectionMatrix(void);
    Mtx mtx_44;
    f32 indMtx[6];
    int handle2;
    int handle1;
    f32 fA;
    f32 fB;
    f32 mulY;
    f32 mulX;
    s16 v;
    u8 k;
    u8 a2;
    u8 a1;

    *(IndMtxInit *)indMtx = *(IndMtxInit *)lbl_802C1EA8;
    v = fn_8000FA70();
    if (v < 0) {
        k = (((u16)(int)v >> 8) - 0xc0) << 2;
    } else {
        k = 0xff;
    }
    a1 = (alpha * 0xff) >> 8;
    a2 = (k * alpha) >> 8;

    selectReflectionTexture(0);
    getReflectionTexture2(&handle1);
    selectTexture(handle1, 1);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);

    newshadows_getReflectionScrollOffsets(&fA, &fB);
    fA *= lbl_803DEF6C;
    fB *= lbl_803DEF6C;
    getTextureFn_8006c5e4(&handle2);
    selectTexture(handle2, 2);

    fn_80293C64(&mulX, &mulY, lbl_803DEF70 * fA);
    mulY *= gSynthDelayedActionWord0;
    mulX *= gSynthDelayedActionWord0;

    indMtx[0] = mulY;
    indMtx[1] = mulX;
    indMtx[3] = -mulX;
    indMtx[4] = mulY;

    PSMTXScale(mtx_44, lbl_803DEF74, *(f32 *)&lbl_803DEF74, lbl_803DEEE4);
    mtx_44[0][3] = fA;
    mtx_44[1][3] = -fB;
    GXLoadTexMtxImm(mtx_44, 0x40, 0);
    GXSetTexCoordGen2(1, 0, 4, 0x3C, 0, 0x40);

    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP2);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indMtx, -6);
    GXSetTevIndirect(1, 0, 0, 7, 1, 0, 0, 0, 0, 0);

    GXSetTevKColor(0, lbl_803DB6A4);
    GXSetTevKAlphaSel(0, 0x1c);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(0, 0, 1, 0xff);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xf);
    GXSetTevAlphaIn(0, 6, 7, 7, 4);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 1, 0, 2, 1, 0);

    GXSetTevOrder(1, 0, 0, 0xff);
    GXSetTevColorIn(1, 8, 0xf, 0xf, 0xf);
    GXSetTevAlphaIn(1, 7, 7, 7, 0);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 2, 1, 0);

    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(2, 0xff, 0xff, 4);
    GXSetTevColorIn(2, 0xf, 0xf, 0xf, 0);
    GXSetTevAlphaIn(2, 7, 0, 5, 7);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 2, 1, 0);

    GXSetNumTexGens(2);
    GXSetNumTevStages(3);
    GXSetNumIndStages(1);
    GXSetNumChans(1);
    GXClearVtxDesc();
    GXSetCurrentMtx(0x3c);
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xb, 1);
    GXSetVtxDesc(0xd, 1);
    GXSetCullMode(0);
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 1 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LESS, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 1;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, 1);
    GXSetChanCtrl(4, 0, 0, 1, 0, 0, 2);
    GXBegin(0x80, 0, 4);
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = a2;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = a2;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1e0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = a1;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1e0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = a1;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;
    Camera_RebuildProjectionMatrix();
    GXSetCurrentMtx(0);
}

/*
 * Fullscreen 640x480 textured quad with caller-supplied alpha. The alpha
 * is multiplied by lbl_803DEF20 (a 0..255 scale), converted to int and
 * stamped into byte 3 of the K0 GXColor cache (lbl_803DB6A0). Sets up
 * one TEV stage that K-multiplies the texture by alpha; uses fixed UVs
 * 0..0x80 so the texture maps once across the screen. Used when fading
 * the screen to texture (e.g. boot logo / "now loading").
 */
void renderMotionBlur(f32 alpha)
{
    extern f32 lbl_803DEF20;
    extern GXColor lbl_803DB6A0;
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern void selectReflectionTexture(int);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx;

    lbl_803DB6A0.a = lbl_803DEF20 * alpha;
    selectReflectionTexture(0);
    GXSetTevKColor(0, lbl_803DB6A0);
    GXSetTevKAlphaSel(0, 0x1C);
    PSMTXIdentity(mtx);
    GXLoadTexMtxImm(mtx, 0x24, 1);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(0, 0, 0, 6);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(0, 7, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
}

void doBlurFilter(f32 wx, f32 wy, f32 wz, u8 param4, u8 param5)
{
    extern f32 playerMapOffsetX, playerMapOffsetZ;
    extern f32 lbl_803DEEE4;
    extern f32 lbl_803DEF08;
    extern f32 lbl_803DEF78, lbl_803DEF7C, lbl_803DEF80;
    extern u32 lbl_803DB69C;
    extern Mtx hudMatrix;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern void selectReflectionTexture(int);
    extern void getReflectionTexture2(int* out);
    extern void selectTexture(int handle, int slot);
    extern void Camera_ProjectWorldPoint(f32* out_x, f32* out_y, f32* out_z, f32* out_w, double x, double y, double z);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_27;
    Mtx mtx_24;
    Mtx mtx_2A;
    Mtx mtx_2D;
    Mtx mtx_30;
    GXColor c1;
    GXColor c0;
    int handle;
    f32 pz, px, py, pw;
    int stage_base;

    wx = wx - playerMapOffsetX;
    wz = wz - playerMapOffsetZ;
    Camera_ProjectWorldPoint(&px, &py, &pz, &pw, wx, wy, wz);
    pz = pz + lbl_803DEEE4;
    c0.a = (u8)(((u32)(lbl_803DEF08 * pz) & 0x00FF0000) >> 16);
    selectReflectionTexture(0);
    getReflectionTexture2(&handle);
    selectTexture(handle, 1);
    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_GREEN);

    PSMTXIdentity(mtx_24);
    mtx_24[1][3] = lbl_803DEF78;
    GXLoadTexMtxImm(mtx_24, 0x24, 1);
    GXSetTexCoordGen2(0, 1, 4, 0x24, 0, 0x7D);

    PSMTXIdentity(mtx_2A);
    mtx_2A[1][3] = lbl_803DEF78;
    GXLoadTexMtxImm(mtx_2A, 0x2A, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x2A, 0, 0x7D);

    PSMTXIdentity(mtx_2D);
    mtx_2D[0][3] = lbl_803DEF7C;
    GXLoadTexMtxImm(mtx_2D, 0x2D, 1);
    GXSetTexCoordGen2(3, 1, 4, 0x2D, 0, 0x7D);

    PSMTXIdentity(mtx_30);
    mtx_30[0][3] = lbl_803DEF80;
    GXLoadTexMtxImm(mtx_30, 0x30, 1);
    GXSetTexCoordGen2(4, 1, 4, 0x30, 0, 0x7D);

    GXSetTexCoordGen2(5, 1, 4, 0x3C, 0, 0x7D);

    PSMTXIdentity(mtx_27);
    GXLoadTexMtxImm(mtx_27, 0x27, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x27, 0, 0x7D);

    GXSetTevKColor(0, c0);
    GXSetTevKAlphaSel(0, 0x1C);
    c1 = *(GXColor*)&lbl_803DB69C;
    GXSetTevKColor(1, c1);

    GXSetNumTexGens(6);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);

    stage_base = 0;
    if (param5 == 0) {
        if (param4 == 0) {
            GXSetTevKAlphaSel(1, 0x1C);
            GXSetNumTevStages(7);

            GXSetTevDirect(GX_TEVSTAGE0);
            GXSetTevOrder(0, 1, 1, 0xFF);
            GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xF);
            GXSetTevAlphaIn(0, 4, 7, 7, 6);
            GXSetTevSwapMode(0, 0, 0);
            GXSetTevColorOp(0, 0, 0, 0, 1, 3);
            GXSetTevAlphaOp(0, 1, 0, 3, 1, 3);
            stage_base = 1;
        } else {
            GXSetNumTevStages(6);
        }

        GXSetTevDirect(stage_base);
        GXSetTevOrder(stage_base, 1, 1, 0xFF);
        GXSetTevColorIn(stage_base, 0xF, 0xF, 0xF, 0xF);
        GXSetTevAlphaIn(stage_base, 6, 7, 7, 4);
        GXSetTevSwapMode(stage_base, 0, 0);
        GXSetTevColorOp(stage_base, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(stage_base, 1, 0, 3, 1, 0);

        GXSetTevKColorSel(stage_base + 1, 0xD);
        GXSetTevDirect(stage_base + 1);
        GXSetTevOrder(stage_base + 1, 0, 0, 0xFF);
        GXSetTevColorIn(stage_base + 1, 0xF, 0x8, 0xE, 0xF);
        if (param4 == 0) {
            GXSetTevAlphaIn(stage_base + 1, 0, 7, 7, 3);
        } else {
            GXSetTevAlphaIn(stage_base + 1, 7, 7, 7, 0);
        }
        GXSetTevSwapMode(stage_base + 1, 0, 0);
        GXSetTevColorOp(stage_base + 1, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(stage_base + 1, 0, 0, 3, 1, 0);

        GXSetTevKColorSel(stage_base + 2, 0xD);
        GXSetTevDirect(stage_base + 2);
        GXSetTevOrder(stage_base + 2, 2, 0, 0xFF);
        GXSetTevColorIn(stage_base + 2, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(stage_base + 2, 7, 7, 7, 0);
        GXSetTevSwapMode(stage_base + 2, 0, 0);
        GXSetTevColorOp(stage_base + 2, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(stage_base + 2, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(stage_base + 3, 0xD);
        GXSetTevDirect(stage_base + 3);
        GXSetTevOrder(stage_base + 3, 3, 0, 0xFF);
        GXSetTevColorIn(stage_base + 3, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(stage_base + 3, 7, 7, 7, 0);
        GXSetTevSwapMode(stage_base + 3, 0, 0);
        GXSetTevColorOp(stage_base + 3, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(stage_base + 3, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(stage_base + 4, 0xD);
        GXSetTevDirect(stage_base + 4);
        GXSetTevOrder(stage_base + 4, 4, 0, 0xFF);
        GXSetTevColorIn(stage_base + 4, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(stage_base + 4, 7, 7, 7, 0);
        GXSetTevSwapMode(stage_base + 4, 0, 0);
        GXSetTevColorOp(stage_base + 4, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(stage_base + 4, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(stage_base + 5, 0xD);
        GXSetTevDirect(stage_base + 5);
        GXSetTevOrder(stage_base + 5, 5, 0, 0xFF);
        GXSetTevColorIn(stage_base + 5, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(stage_base + 5, 7, 7, 7, 0);
        GXSetTevSwapMode(stage_base + 5, 0, 0);
        GXSetTevColorOp(stage_base + 5, 0, 0, 3, 1, 0);
        GXSetTevAlphaOp(stage_base + 5, 0, 0, 2, 1, 0);
    } else {
        GXSetTevKAlphaSel(1, 0x1C);
        GXSetNumTevStages(7);

        GXSetTevDirect(GX_TEVSTAGE0);
        GXSetTevOrder(0, 1, 1, 0xFF);
        GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xF);
        GXSetTevAlphaIn(0, 4, 7, 7, 6);
        GXSetTevSwapMode(0, 0, 0);
        GXSetTevColorOp(0, 0, 0, 0, 1, 3);
        GXSetTevAlphaOp(0, 1, 0, 0, 1, 3);

        GXSetTevDirect(GX_TEVSTAGE1);
        GXSetTevOrder(1, 1, 1, 0xFF);
        GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0xF);
        GXSetTevAlphaIn(1, 6, 7, 7, 4);
        GXSetTevSwapMode(1, 0, 0);
        GXSetTevColorOp(1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(1, 1, 0, 0, 1, 0);

        GXSetTevKColorSel(2, 0xD);
        GXSetTevDirect(GX_TEVSTAGE2);
        GXSetTevOrder(2, 0, 0, 0xFF);
        GXSetTevColorIn(2, 0xF, 0x8, 0xE, 0xF);
        GXSetTevAlphaIn(2, 0, 7, 7, 3);
        GXSetTevSwapMode(2, 0, 0);
        GXSetTevColorOp(2, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(2, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(3, 0xD);
        GXSetTevDirect(GX_TEVSTAGE3);
        GXSetTevOrder(3, 2, 0, 0xFF);
        GXSetTevColorIn(3, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(3, 7, 7, 7, 0);
        GXSetTevSwapMode(3, 0, 0);
        GXSetTevColorOp(3, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(3, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(4, 0xD);
        GXSetTevDirect(GX_TEVSTAGE4);
        GXSetTevOrder(4, 3, 0, 0xFF);
        GXSetTevColorIn(4, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(4, 7, 7, 7, 0);
        GXSetTevSwapMode(4, 0, 0);
        GXSetTevColorOp(4, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(4, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(5, 0xD);
        GXSetTevDirect(GX_TEVSTAGE5);
        GXSetTevOrder(5, 4, 0, 0xFF);
        GXSetTevColorIn(5, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(5, 7, 7, 7, 0);
        GXSetTevSwapMode(5, 0, 0);
        GXSetTevColorOp(5, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(5, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(6, 0xD);
        GXSetTevDirect(GX_TEVSTAGE6);
        GXSetTevOrder(6, 5, 0, 0xFF);
        GXSetTevColorIn(6, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(6, 7, 7, 7, 0);
        GXSetTevSwapMode(6, 0, 0);
        GXSetTevColorOp(6, 0, 0, 3, 1, 0);
        GXSetTevAlphaOp(6, 0, 0, 0, 1, 0);
    }

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
}

void fn_8007BD8C(int handle1, int handle2)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern f32 lbl_803DEF64;
    extern u32 lbl_803DB690, lbl_803DB694, lbl_803DB698;
    extern GXColor gFogColor;
    extern Mtx lbl_80396820;
    extern f32 lbl_8030EA10[3][3];
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern void selectReflectionTexture(int);

    extern void selectTexture(int handle, int slot);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_30;
    GXColor temp;
    GXColor temp2;
    u8* indBase = (u8*)lbl_8030EA10;

    selectReflectionTexture(0);
    selectTexture(handle1, 1);
    selectTexture(handle2, 2);

    GXSetTexCoordGen2(1, 1, 4, 0x3C, 0, 0x7D);
    GXLoadTexMtxImm(lbl_80396820, 0x55, 0);
    GXSetTexCoordGen2(0, 0, 0, 0, 0, 0x55);
    PSMTXScale(mtx_30, lbl_803DEF64, lbl_803DEEE4, lbl_803DEEDC);
    GXLoadTexMtxImm(mtx_30, 0x1e, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x1e, 0, 0x7d);
    GXSetChanCtrl(4, 0, 0, 1, 0, 0, 2);

    if (isHeavyFogEnabled() != 0) {
        ((u8*)&temp)[0] = ((u8*)&gFogColor)[0];
        ((u8*)&temp)[1] = ((u8*)&gFogColor)[1];
        ((u8*)&temp)[2] = ((u8*)&gFogColor)[2];
    } else {
        u8 ignoredLightColor;
        (*gSkyInterface)->getCurrentAmbientAndLightColors(
            &((u8*)&temp)[0],
            &((u8*)&temp)[1],
            &((u8*)&temp)[2],
            &ignoredLightColor, &ignoredLightColor, &ignoredLightColor);
    }

    GXSetTevKColor(0, *(GXColor*)&lbl_803DB690);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevKColor(1, *(GXColor*)&lbl_803DB694);
    GXSetTevKColorSel(1, 0xD);
    GXSetTevKColor(2, *(GXColor*)&lbl_803DB698);
    GXSetTevKColorSel(2, 0xE);

    ((u8*)&temp)[0] = (u8)((int)((u8*)&temp)[0] >> 2);
    ((u8*)&temp)[1] = (u8)((int)((u8*)&temp)[1] >> 2);
    ((u8*)&temp)[2] = (u8)((int)((u8*)&temp)[2] >> 2);
    GXSetTevColor(1, temp);

    ((u8*)&temp2)[0] = (u8)(((u8*)&temp)[0] + 0xC0);
    ((u8*)&temp2)[1] = (u8)(((u8*)&temp)[1] + 0xC0);
    ((u8*)&temp2)[2] = (u8)(((u8*)&temp)[2] + 0xC0);
    GXSetTevColor(2, temp2);

    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indBase, -1);
    GXSetIndTexMtx(2, (f32(*)[3])(indBase + 0x18), -1);
    GXSetIndTexMtx(3, (f32(*)[3])(indBase + 0x30), -1);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevIndirect(1, 0, 0, 7, 2, 0, 0, 0, 0, 1);
    GXSetTevIndirect(2, 0, 0, 7, 3, 0, 0, 0, 0, 0);
    GXSetNumIndStages(1);
    GXSetNumTexGens(3);
    GXSetNumTevStages(4);
    GXSetNumChans(1);

    GXSetTevOrder(0, 0, 0, 4);
    GXSetTevColorIn(0, 0xF, 0x8, 0xE, 2);
    GXSetTevAlphaIn(0, 7, 7, 7, 5);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetTevOrder(1, 0, 0, 8);
    GXSetTevColorIn(1, 0xF, 8, 0xE, 0);
    GXSetTevAlphaIn(1, 7, 5, 0, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);

    GXSetTevOrder(2, 0, 0, 0xff);
    GXSetTevColorIn(2, 0xF, 8, 0xE, 0);
    GXSetTevAlphaIn(2, 7, 7, 7, 0);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);

    GXSetTevDirect(GX_TEVSTAGE3);
    GXSetTevOrder(3, 2, 2, 0xff);
    GXSetTevColorIn(3, 0, 4, 9, 0xF);
    GXSetTevAlphaIn(3, 7, 7, 7, 0);
    GXSetTevSwapMode(3, 0, 0);
    GXSetTevColorOp(3, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(3, 0, 0, 0, 1, 0);

    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void setupReflectionIndirectTev(u8 flag)
{
    extern f32 lbl_803DEEDC;
    extern f32 gSynthDelayedActionWord0;
    extern void selectReflectionTexture(int);
    f32 mtx[6];

    selectReflectionTexture(1);
    GXSetTexCoordGen2(1, 0, 0, 0x24, 0, 0x7D);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    mtx[0] = lbl_803DEEDC;
    mtx[1] = *(f32*)&gSynthDelayedActionWord0;
    mtx[2] = lbl_803DEEDC;
    mtx[3] = lbl_803DEEDC;
    mtx[4] = lbl_803DEEDC;
    mtx[5] = *(f32*)&gSynthDelayedActionWord0;
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD0, GX_TEXMAP0);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (void*)mtx, -2);
    GXSetTevIndirect(1, 0, 0, 7, 1, 0, 0, 0, 0, 1);
    GXSetNumIndStages(1);
    GXSetNumTexGens(2);
    GXSetNumTevStages(2);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumChans(1);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(0, 0xFF, 0xFF, 4);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xA);
    GXSetTevAlphaIn(0, 7, 7, 7, 5);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    if (flag != 0) {
        GXSetTevColorIn(1, 8, 0xF, 0xF, 0);
    } else {
        GXSetTevColorIn(1, 0xF, 8, 0, 0xF);
    }
    GXSetTevOrder(1, 1, 1, 8);
    GXSetTevAlphaIn(1, 7, 5, 0, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
}

void fn_8007C664(int texHandle)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern f32 gSynthDelayedActionWord0;
    extern GXColor lbl_803DB688;
    extern GXColor lbl_803DB68C;
    extern u8 lbl_803DB678;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern void newshadows_getReflectionScrollOffsets(f32* a, f32* b);
    extern void selectReflectionTexture(int);

    extern void selectTexture(int handle, int slot);
    u8 ignoredLightColor;
    f32 sOff;
    f32 tOff;
    f32 indMtx[6];
    Mtx scaleMtx;

    selectReflectionTexture(0);
    selectTexture(texHandle, 1);
    newshadows_getReflectionScrollOffsets(&sOff, &tOff);
    GXSetTexCoordGen2(0, 0, 0, 0x1e, 0, 0x7d);
    GXSetTexCoordGen2(2, 0, 0, 0x24, 0, 0x7d);
    PSMTXScale(scaleMtx, 1.0f, 1.0f, 1.0f);
    GXLoadTexMtxImm(scaleMtx, 0x21, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x21, 0, 0x7d);
    indMtx[0] = lbl_803DEEDC;
    indMtx[1] = *(f32*)&gSynthDelayedActionWord0;
    indMtx[2] = lbl_803DEEDC;
    indMtx[3] = lbl_803DEEDC;
    indMtx[4] = lbl_803DEEDC;
    indMtx[5] = *(f32*)&gSynthDelayedActionWord0;
    if (isHeavyFogEnabled()) {
        lbl_803DB688.r = gFogColor.r;
        lbl_803DB688.g = gFogColor.g;
        lbl_803DB688.b = gFogColor.b;
        lbl_803DB688.a = 0x80;
    } else {
        (*gSkyInterface)->getCurrentAmbientAndLightColors(
            &lbl_803DB688.r, &lbl_803DB688.g, &lbl_803DB688.b,
            &ignoredLightColor, &ignoredLightColor, &ignoredLightColor);
        lbl_803DB688.r = lbl_803DB688.r >> 3;
        lbl_803DB688.g = lbl_803DB688.g >> 3;
        lbl_803DB688.b = lbl_803DB688.b >> 3;
        lbl_803DB688.a = lbl_803DB678;
    }
    GXSetTevColor(3, lbl_803DB688);
    GXSetTevKColor(0, lbl_803DB68C);
    GXSetTevKColorSel(1, 0xc);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indMtx, -1);
    GXSetIndTexMtx(2, (f32(*)[3])indMtx, -2);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevIndirect(1, 0, 0, 7, 2, 0, 0, 0, 0, 1);
    GXSetNumIndStages(1);
    GXSetNumChans(1);
    GXSetNumTexGens(3);
    GXSetNumTevStages(2);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 6, 0xf, 0xf, 8);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    if (isHeavyFogEnabled()) {
        GXSetTevColorOp(0, 0, 0, 3, 1, 0);
    } else {
        GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    }
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetTevOrder(1, 2, 0, 8);
    GXSetTevColorIn(1, 0, 8, 0xe, 0xf);
    GXSetTevAlphaIn(1, 7, 2, 5, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void fn_8007CAF4(void)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4, lbl_803DEEEC;
    extern GXColor lbl_803DB680;
    extern GXColor lbl_803DB684;
    extern u8 lbl_803DB678;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern void newshadows_getReflectionScrollOffsets(f32* a, f32* b);
    extern void selectReflectionTexture(int);

    extern void fn_8006C678(int);
    u8 ignoredLightColor;
    f32 sOff;
    f32 tOff;
    f32 indMtx[6];
    Mtx scaleMtx;

    selectReflectionTexture(0);
    fn_8006C678(1);
    newshadows_getReflectionScrollOffsets(&sOff, &tOff);
    GXSetTexCoordGen2(0, 0, 0, 0x1e, 0, 0x7d);
    GXSetTexCoordGen2(2, 0, 0, 0x24, 0, 0x7d);
    PSMTXScale(scaleMtx, 1.0f, 1.0f, 1.0f);
    GXLoadTexMtxImm(scaleMtx, 0x21, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x21, 0, 0x7d);
    indMtx[0] = lbl_803DEEEC;
    indMtx[1] = lbl_803DEEDC;
    indMtx[2] = lbl_803DEEDC;
    indMtx[3] = lbl_803DEEDC;
    indMtx[4] = lbl_803DEEEC;
    indMtx[5] = lbl_803DEEDC;
    if (isHeavyFogEnabled()) {
        lbl_803DB680.r = gFogColor.r;
        lbl_803DB680.g = gFogColor.g;
        lbl_803DB680.b = gFogColor.b;
        lbl_803DB680.a = 0x80;
    } else {
        (*gSkyInterface)->getCurrentAmbientAndLightColors(
            &lbl_803DB680.r, &lbl_803DB680.g, &lbl_803DB680.b,
            &ignoredLightColor, &ignoredLightColor, &ignoredLightColor);
        lbl_803DB680.r = lbl_803DB680.r >> 3;
        lbl_803DB680.g = lbl_803DB680.g >> 3;
        lbl_803DB680.b = lbl_803DB680.b >> 3;
        lbl_803DB680.a = lbl_803DB678;
    }
    GXSetTevColor(3, lbl_803DB680);
    GXSetTevKColor(0, lbl_803DB684);
    GXSetTevKColorSel(1, 0xc);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indMtx, -1);
    GXSetIndTexMtx(2, (f32(*)[3])indMtx, -2);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevIndirect(1, 0, 0, 7, 2, 0, 0, 0, 0, 3);
    GXSetNumIndStages(1);
    GXSetNumChans(1);
    GXSetNumTexGens(3);
    GXSetNumTevStages(2);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 6, 0xf, 0xf, 8);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    if (isHeavyFogEnabled()) {
        GXSetTevColorOp(0, 0, 0, 3, 1, 0);
    } else {
        GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    }
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetTevOrder(1, 2, 0, 8);
    GXSetTevColorIn(1, 0, 8, 0xe, 0xf);
    GXSetTevAlphaIn(1, 7, 2, 5, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void gxTextureSetupFn_8007cf7c(void)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4, lbl_803DEEF0, lbl_803DEEF4;
    extern f32 lbl_803DEF40, lbl_803DEF88;
    extern f32 lbl_803DEF84;
    extern u32 lbl_803DB67C;
    extern GXColor gFogColor;
    extern u8 lbl_803DB678;
    extern f32 gSynthDelayedActionWord0;
    extern u8 gGxZModeUpdateEnable, gGxZModeCompareEnable, gGxZModeValid;
    extern u8 gGxZCompLocCached, gGxZCompLocValid;
    extern int gGxZModeCompareFunc;
    extern void newshadows_getReflectionScrollOffsets(f32* a, f32* b);
    extern void getTextureFn_8006c5e4(int* out);
    extern void selectReflectionTexture(int);

    extern void selectTexture(int handle, int slot);
    Mtx mtx_cc;
    Mtx mtx_9c;
    Mtx mtx_6c;
    f32 indMtx_54[6];
    f32 indMtx_3c[6];
    f32 indMtx_24[6];
    int handle1;
    f32 fA, fB;
    GXColor temp;

    newshadows_getReflectionScrollOffsets(&fA, &fB);
    selectReflectionTexture(0);
    GXSetTexCoordGen2(0, 0, 0, 0x1e, 0, 0x7d);
    getTextureFn_8006c5e4(&handle1);
    selectTexture(handle1, 1);

    PSMTXScale(mtx_cc, lbl_803DEEE4, lbl_803DEEE4, lbl_803DEEE4);
    mtx_cc[1][3] = fA;
    GXLoadTexMtxImm(mtx_cc, 0x27, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x27, 0, 0x7d);

    indMtx_54[0] = gSynthDelayedActionWord0;
    indMtx_54[1] = lbl_803DEEDC;
    indMtx_54[2] = lbl_803DEEDC;
    indMtx_54[3] = lbl_803DEEDC;
    indMtx_54[4] = gSynthDelayedActionWord0;
    indMtx_54[5] = lbl_803DEEDC;
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indMtx_54, -2);
    GXSetTevIndirect(0, 0, 0, 7, 1, 6, 6, 0, 0, 0);

    PSMTXScale(mtx_9c, lbl_803DEF40, lbl_803DEF40, lbl_803DEF40);
    PSMTXRotRad(mtx_6c, 'z', lbl_803DEEF0);
    PSMTXConcat(mtx_6c, mtx_9c, mtx_9c);
    mtx_9c[1][3] = fB;
    mtx_9c[2][3] = fB;
    GXLoadTexMtxImm(mtx_9c, 0x2a, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x2a, 0, 0x7d);

    indMtx_3c[0] = lbl_803DEF84;
    indMtx_3c[1] = lbl_803DEF84;
    indMtx_3c[2] = lbl_803DEEDC;
    indMtx_3c[3] = lbl_803DEF88;
    indMtx_3c[4] = lbl_803DEF84;
    indMtx_3c[5] = lbl_803DEEDC;
    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD2, GX_TEXMAP1);
    GXSetIndTexCoordScale(1, 0, 0);
    GXSetIndTexMtx(2, (f32(*)[3])indMtx_3c, -4);
    GXSetTevIndirect(1, 1, 0, 7, 2, 0, 0, 1, 0, 0);

    if (isHeavyFogEnabled() != 0) {
        ((u8*)&lbl_803DB67C)[0] = ((u8*)&gFogColor)[0];
        ((u8*)&lbl_803DB67C)[1] = ((u8*)&gFogColor)[1];
        ((u8*)&lbl_803DB67C)[2] = ((u8*)&gFogColor)[2];
        ((u8*)&lbl_803DB67C)[3] = 0x80;
    } else {
        u8 ignoredLightColor;
        (*gSkyInterface)->getCurrentAmbientAndLightColors(
            (u8*)&lbl_803DB67C,
            (u8*)&lbl_803DB67C + 1,
            (u8*)&lbl_803DB67C + 2,
            &ignoredLightColor, &ignoredLightColor, &ignoredLightColor);
        ((u8*)&lbl_803DB67C)[0] = (u8)(((u8*)&lbl_803DB67C)[0] >> 3);
        ((u8*)&lbl_803DB67C)[1] = (u8)(((u8*)&lbl_803DB67C)[1] >> 3);
        ((u8*)&lbl_803DB67C)[2] = (u8)(((u8*)&lbl_803DB67C)[2] >> 3);
        ((u8*)&lbl_803DB67C)[3] = lbl_803DB678;
    }
    temp = *(GXColor*)&lbl_803DB67C;
    GXSetTevKColor(0, temp);
    GXSetTevKAlphaSel(1, 0x1c);
    GXSetTevKColorSel(1, 0xc);

    GXSetNumIndStages(2);
    GXSetNumChans(1);
    GXSetNumTexGens(4);
    GXSetNumTevStages(4);

    GXSetTevOrder(0, 0xff, 0xff, 0xff);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xf);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetTevOrder(1, 0, 0, 0xff);
    GXSetTevColorIn(1, 0xe, 0xf, 0xf, 8);
    GXSetTevAlphaIn(1, 7, 7, 7, 6);
    GXSetTevSwapMode(1, 0, 0);
    if (isHeavyFogEnabled() != 0) {
        GXSetTevColorOp(1, 0, 0, 3, 1, 1);
    } else {
        GXSetTevColorOp(1, 0, 0, 0, 1, 1);
    }
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 1);

    indMtx_24[0] = lbl_803DEEDC;
    indMtx_24[1] = gSynthDelayedActionWord0;
    indMtx_24[2] = lbl_803DEEDC;
    indMtx_24[3] = lbl_803DEEF4;
    indMtx_24[4] = lbl_803DEEDC;
    indMtx_24[5] = lbl_803DEEDC;
    GXSetIndTexMtx(3, (f32(*)[3])indMtx_24, -5);
    GXSetTevIndirect(2, 0, 0, 7, 2, 6, 6, 0, 0, 0);
    GXSetTevIndirect(3, 1, 0, 7, 3, 0, 0, 1, 0, 0);
    GXSetTexCoordGen2(3, 0, 0, 0x21, 0, 0x7d);

    GXSetTevOrder(2, 0xff, 0xff, 4);
    GXSetTevColorIn(2, 0xf, 0xf, 0xf, 0xf);
    GXSetTevAlphaIn(2, 7, 7, 7, 7);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);

    GXSetTevOrder(3, 3, 0, 4);
    GXSetTevColorIn(3, 8, 2, 3, 0xf);
    GXSetTevAlphaIn(3, 7, 7, 7, 5);
    GXSetTevSwapMode(3, 0, 0);
    GXSetTevColorOp(3, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(3, 0, 0, 0, 1, 0);

    GXSetBlendMode(1, 4, 5, 5);
    GXSetCullMode(0);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 ||
        gGxZModeUpdateEnable != 0 || gGxZModeValid == 0) {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0) {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

/* EN v1.0 Size: 108b. */
void fn_8007D670(void)
{
    f32* base = (f32*)&lbl_803967C0;
    Mtx tmp;
    PSMTXConcat((void*)(base + 36), (void*)(int)base, tmp);
    GXLoadTexMtxImm(tmp, 0x1E, GX_MTX3x4);
    PSMTXConcat((void*)(base + 24), (void*)(int)base, tmp);
    GXLoadTexMtxImm(tmp, 0x24, GX_MTX3x4);
}

/*
 * Retail ships a locally-defined empty OSReport that disables debug
 * output.
 */
void OSReport(const char* msg, ...)
{
}

/*
 * Card init / serial-no validation. Mounts slot 0; if the mount comes back
 * "no card filesystem" (-13) it remembers we need to format. On a check
 * error (-6) it runs CARDCheck; if that also returns -6 it formats. On a
 * clean mount (or after the recovery path) it reads the card serial and
 * compares against the cached pair (lbl_803DD048/04C). If the cached pair
 * is zero, or doesn't match the live card, the cache is rejected with a
 * "wrong card" error code (-0x55, lbl_803DB700 = 11). Otherwise CARDFormat
 * if we still owe one, else success: clear the cache, set state 13,
 * unmount, return 1.
 */
int cardLoadFn_8007d72c(void)
{
    extern int cardProbe(int);


    extern void cardSetStatusNoCard2(void);
    extern void* lbl_803DD040;
    extern volatile s32 lbl_803DB700;
    extern u32 lbl_803DD048, gSaveCardSerialLo, lbl_803DD050, lbl_803DD054;
    int need_format;
    int res;
    u64 serial;
    int ok;

    need_format = 0;
    if (cardProbe(0) == 0) {
        ok = 0;
    } else {
        lbl_803DD040 = mmAlloc(0xA000, -1, 0);
        if (lbl_803DD040 == 0) {
            lbl_803DB700 = 8;
            ok = 0;
        } else {
            ok = 1;
        }
    }
    if (ok == 0) {
        return 0;
    }
    lbl_803DB700 = 0;
    res = CARDMount(0, lbl_803DD040, (void*)cardSetStatusNoCard2);
    if (res == -13) {
        need_format = 1;
    }
    if (res == -6) {
        res = CARDCheck(0);
        if (res == -6) {
            res = CARDFormat(0);
        }
    } else if (res == -13 || res == 0) {
        res = CARDGetSerialNo(0, &serial);
        if (res == 0) {
            u64 cache = gSaveCardSerialLo | (u64)lbl_803DD048 << 32;
            if (cache == 0 || cache != serial) {
                res = -0x55;
                lbl_803DB700 = 0xB;
            } else if (need_format) {
                res = CARDFormat(0);
            } else {
                CARDUnmount(0);
                mm_free(lbl_803DD040);
                lbl_803DD040 = 0;
                lbl_803DB700 = 0xD;
                return 1;
            }
        }
    }
    CARDUnmount(0);
    mm_free(lbl_803DD040);
    lbl_803DD040 = 0;
    switch (res) {
        case -2:
            lbl_803DB700 = 1;
            break;
        case -3:
            if (lbl_803DB700 != 3) lbl_803DB700 = 2;
            break;
        case -5:
            lbl_803DB700 = 4;
            break;
        case 0:
            lbl_803DB700 = 0xD;
            gSaveCardSerialLo = 0;
            lbl_803DD048 = 0;
            lbl_803DD054 = 0;
            lbl_803DD050 = 0;
            return 1;
        default:
            break;
    }
    return 0;
}

void saveFn_8007d960(u32 enable)
{
    u8 v = enable;
    lbl_803DD059 = v;
    if (v != 0) {
        return;
    }
    gSaveCardSerialLo = 0;
    lbl_803DD048 = 0;
    lbl_803DD054 = 0;
    lbl_803DD050 = 0;
}

void cardSetStatusNeedInit(void)
{
    lbl_803DB700 = 0xd;
}

s32 saveGameGetStatus(void)
{
    return lbl_803DB700;
}

extern int saveGame_prepareAndWrite(int, int, int, int, int, void*);
extern void saveCb_8007e77c(void);
extern u8 gSaveCardRetry;

int cardDeleteFn_8007d99c(void)
{

    extern s32 CARDMount();
    extern s32 CARDCheck();
    extern s32 CARDDelete();
    extern void CARDUnmount();

    extern void cardSetStatusNoCard2();
    extern void* lbl_803DD040;
    extern const char* sMemoryCardFileName;
    extern volatile s32 lbl_803DB700;
    int res;
    int ok;

    gSaveCardRetry = 0;

    do {
        if (cardProbe(0) == 0) {
            ok = 0;
        } else {
            lbl_803DD040 = mmAlloc(0xA000, -1, 0);
            if (lbl_803DD040 == 0) {
                lbl_803DB700 = 8;
                ok = 0;
            } else {
                ok = 1;
            }
        }
        if (ok == 0) {
            return 0;
        }
        lbl_803DB700 = 0;
        res = CARDMount(0, lbl_803DD040, cardSetStatusNoCard2);
        if (res == 0 || res == -6) {
            res = CARDCheck(0);
        }
        if (res == 0) {
            res = CARDDelete(0, sMemoryCardFileName);
        }
        CARDUnmount(0);
        mm_free(lbl_803DD040);
        lbl_803DD040 = 0;

        switch (res + 13) {
            case 11: lbl_803DB700 = 1; break;
            case 10:
                if (lbl_803DB700 != 3) lbl_803DB700 = 2;
                break;
            case 0:  lbl_803DB700 = 6; break;
            case 8:  lbl_803DB700 = 4; break;
            case 13:
                lbl_803DB700 = 13;
                return 1;
        }
        showMemCardError(0);
    } while (gSaveCardRetry != 0);
    return 0;
}

int _saveGame(int a, int b, int c)
{
    int ret;
    gSaveCardRetry = 0;
    cardShowLoadingMsg(1);
    do {
        ret = saveGame_prepareAndWrite(0, a, 0, b, c, cardCb_8007e6d4);
        showMemCardError(0);
        if (gSaveCardRetry != 0) {
            cardShowLoadingMsg(1);
        }
    } while (gSaveCardRetry != 0);
    return ret;
}

int maybeTryLoadSave(int a)
{
    int ret;
    gSaveCardRetry = 0;
    cardShowLoadingMsg(0);
    do {
        ret = saveGame_prepareAndWrite(1, 0, 0, a, 0, saveCb_8007e748);
        showMemCardError(1);
        if (gSaveCardRetry != 0) {
            cardShowLoadingMsg(0);
        }
    } while (gSaveCardRetry != 0);
    return ret;
}

int loadSaveGame(int a, int b)
{
    int ret;
    gSaveCardRetry = 0;
    cardShowLoadingMsg(0);
    do {
        ret = saveGame_prepareAndWrite(1, a, 0, b, 0, saveCb_8007e77c);
        showMemCardError(0);
        if (gSaveCardRetry != 0) {
            cardShowLoadingMsg(0);
        }
    } while (gSaveCardRetry != 0);
    return ret;
}

void showMemCardError(u8 err)
{
    extern f32 lbl_803DEF90, lbl_803DEF94;
    extern u8 lbl_803DB424;
    extern u8 gSaveCardRetry;
    extern int lbl_803DB708;
    extern void checkReset(void);
    extern void padUpdate(void);
    extern void mmFreeTick(int arg);
    extern void waitNextFrame(void);
    extern int getLastRenderedFrame(void);
    extern void hudDrawColored(int, int, int, void*, int, int);
    extern void gameTextSetColor(int, int, int, int);
    extern void* gameTextGet(int textId);
    extern void gameTextShowStr(int str, int x, int y, int yPos);
    extern void gameTextRun(void);
    extern int GXFlush_(u8 visible, int unused);
    extern char padGetStickY(int port);
    extern char padGetCY(int port);

    extern void setGameState(int state);
    extern f32 fn_80293AC4(int v);

    int opts[8];
    int msgs[8];
    int count;
    int saved;
    int sel;
    u8 submenu;
    int timer;
    u8 held;
    int y;
    int i;
    int j;
    int yy;
    char *t;
    int v;

    sel = 0;
    submenu = 0;
    timer = 0;
    held = 0;
    gSaveCardRetry = 0;
    if (lbl_803DB700 == 0xd) {
        return;
    }
    if (err != 0) {
        if (lbl_803DB700 == 0xc) {
            return;
        }
    }
    do {
        checkReset();
        padUpdate();
        mmFreeTick(0);
        timer += 0x3e8;
        waitNextFrame();
        saved = lbl_803DB708;
        hudDrawColored(getLastRenderedFrame(), 0, 0, &saved, 0x200, 0);
        if (submenu != 0) {
            opts[0] = 6;
            opts[1] = 5;
            msgs[0] = 0x327;
            msgs[1] = 0x321;
            msgs[2] = 0x320;
            count = 2;
        } else {
            cardGetMessage((u32 *)opts, (u32 *)msgs, (u32 *)&count);
        }
        gameTextSetColor(0xff, 0xc0, 0x40, 0xff);
        y = 0x64;
        for (i = 0; i < count + 1; i++) {
            t = (char *)gameTextGet(msgs[i]);
            yy = y + ((i > 0) ? 0x64 : 0);
            for (j = 0; j < *(u16 *)(t + 2); j++) {
                gameTextShowStr((*(int **)(t + 8))[j], 0, 0, yy);
                yy += 0x18;
            }
            if (i == sel) {
                v = (int)(lbl_803DEF94 * fn_80293AC4(timer) + lbl_803DEF90);
                gameTextSetColor(v, v, v, 0xff);
            } else {
                gameTextSetColor(0xa0, 0xa0, 0xa0, 0xff);
            }
            y += 0x14;
        }
        gameTextRun();
        GXFlush_(1, 0);
        if (padGetStickY(0) < 0 || padGetCY(0) < 0) {
            if (held == 0) {
                sel++;
                held = 1;
            }
        } else if (padGetStickY(0) > 0 || padGetCY(0) > 0) {
            if (held == 0) {
                sel--;
                held = 1;
            }
        } else {
            held = 0;
        }
        if (sel < 0) {
            sel = 0;
        } else if (sel > count - 1) {
            sel = count - 1;
        }
        if (getButtonsJustPressed(0) & 0x100) {
            switch (opts[sel]) {
            case 0:
                submenu = 1;
                sel = 0;
                break;
            case 1:
                lbl_803DB700 = 0xd;
                gSaveCardRetry = 1;
                break;
            case 2:
                lbl_803DB424 = 0;
                lbl_803DB700 = 0xd;
                break;
            case 3:
                setGameState(6);
                lbl_803DB424 = 0;
                lbl_803DB700 = 0xd;
                break;
            case 4:
                cardDeleteFn_8007d99c();
                memCardFn_8007dd04(0);
                if (lbl_803DB700 == 0xd) {
                    gSaveCardRetry = 1;
                }
                break;
            case 5:
                submenu = 0;
                if (cardLoadFn_8007d72c() != 0) {
                    memCardFn_8007dd04(0);
                }
                if (lbl_803DB700 == 0xd) {
                    gSaveCardRetry = 1;
                }
                break;
            case 6:
                submenu = 0;
                break;
            default:
                lbl_803DB700 = 0xd;
            }
        }
    } while (lbl_803DB700 != 0xd);
}

int memCardFn_8007dd04(u8 retry)
{
    extern int saveGame(int);
    extern void CARDClose(void*);
    extern void CARDUnmount(s32);

    extern u8 lbl_80396900[];
    extern void* lbl_803DD040;
    extern u8 lbl_803DD05A;
    extern volatile s32 lbl_803DB700;
    int ret;

    if (retry != 0) {
        gSaveCardRetry = 0;
        cardShowLoadingMsg(2);
    }
    do {
        ret = saveGame(0);
        if (ret != 0) {
            if (lbl_803DD05A != 0) {
                lbl_803DD05A = 0;
                CARDClose(lbl_80396900);
            }
            CARDUnmount(0);
            mm_free(lbl_803DD040);
            lbl_803DD040 = 0;
            lbl_803DB700 = 13;
            if (ret == 2) {
                ret = saveGame_prepareAndWrite(0, 0, 0, 0, 0, 0);
            }
        }
        if (retry != 0) {
            showMemCardError(0);
        }
        if (gSaveCardRetry != 0) {
            cardShowLoadingMsg(2);
        }
    } while (gSaveCardRetry != 0 && retry != 0);
    return ret;
}

int cardProbe(u8 retry)
{

    extern volatile s32 lbl_803DB700;
    s32 memSize;
    s32 sectorSize;
    s32 res;

    if (retry != 0) {
        gSaveCardRetry = 0;
    }
    do {
        res = -1;
        while (res == -1) {
            res = CARDProbeEx(0, &memSize, &sectorSize);
        }
        if (res == 0) {
            if (sectorSize == 0x2000) {
                lbl_803DB700 = 13;
                return 1;
            }
            lbl_803DB700 = 7;
        } else if (res == -3) {
            lbl_803DB700 = 2;
        } else if (res == -2) {
            lbl_803DB700 = 1;
        } else {
            lbl_803DB700 = 0;
        }
        if (retry != 0) {
            showMemCardError(0);
        }
    } while (gSaveCardRetry != 0 && retry != 0);
    return 0;
}

void _initCardAndDsp(void)
{
    CARDInit();
}

void cardGetMessage(u32* buttons, u32* texts, u32* count)
{
    extern u8 lbl_803DD059;
    if (lbl_803DD059 != 0 && (lbl_803DB700 == 7 || lbl_803DB700 == 9)) {
        lbl_803DB700 = 11;
    }
    switch (lbl_803DB700) {
        case 0:
            *count = 0;
            lbl_803DB700 = 13;
            return;
        case 1:
            buttons[0] = 1;
            buttons[1] = 2;
            texts[0] = 0x325;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            *count = 2;
            return;
        case 2:
            buttons[0] = 1;
            buttons[1] = 2;
            texts[0] = 0x51A;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            *count = 2;
            return;
        case 3:
            buttons[0] = 1;
            buttons[1] = 2;
            texts[0] = 0x51A;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            *count = 2;
            return;
        case 4:
            buttons[0] = 1;
            buttons[1] = 2;
            texts[0] = 0x329;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            *count = 2;
            return;
        case 5:
            buttons[0] = 1;
            buttons[1] = 2;
            buttons[2] = 0;
            texts[0] = 0x51F;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            texts[3] = 0x326;
            *count = 3;
            return;
        case 6:
            buttons[0] = 1;
            buttons[1] = 2;
            buttons[2] = 0;
            texts[0] = 0x51E;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            texts[3] = 0x326;
            *count = 3;
            return;
        case 7:
            buttons[0] = 1;
            buttons[1] = 2;
            texts[0] = 0x51C;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            *count = 2;
            return;
        case 8:
            *count = 0;
            return;
        case 9:
            buttons[0] = 1;
            buttons[1] = 2;
            buttons[2] = 3;
            texts[0] = 0x32A;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            texts[3] = 0x520;
            *count = 3;
            return;
        case 10:
            buttons[0] = 2;
            buttons[1] = 4;
            texts[0] = 0x497;
            texts[1] = 0x51B;
            texts[2] = 0x522;
            *count = 2;
            return;
        case 11:
        case 12:
            buttons[0] = 1;
            buttons[1] = 2;
            texts[0] = 0x521;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            *count = 2;
            return;
        case 13:
        default:
            *count = 0;
            lbl_803DB700 = 13;
            return;
    }
}

/*
 * Per-frame "blocking" dialog renderer driven by the card-write retry
 * loops in _saveGame/DBC0/DC5C/DD04. Pumps 60 frames of the GX/dialog
 * pipeline; on each frame either lets the active controller draw its own
 * popup (gScreenTransitionInterface[0]->vtbl[1]) or falls back to hudDrawColored over the
 * cached prompt id in lbl_803DB708, then routes the OK/Cancel/back text
 * to gameTextFn_80016810 based on the dialog kind passed in.
 */
void cardShowLoadingMsg(u8 kind)
{
    extern void gameTextSetWindow(int);
    extern void padUpdate(void);
    extern void mmFreeTick(int arg);
    extern void waitNextFrame(void);
    extern int getButtonObjects(int**);
    extern void** gScreenTransitionInterface;
    extern f32 lbl_803DEF98;
    extern f32 lbl_803DEF9C;

    extern int objRenderFn_8003b8f4(int, int, int, int, int, f32);
    extern void curUiDllDraw(int, int, int, int);
    extern int lbl_803DB708;
    extern int getLastRenderedFrame(void);
    extern void hudDrawColored(int, int, int, void*, int, int);
    extern void gameTextSetColor(int, int, int, int);
    extern void gameTextFn_80016810(int a, int b, int c);
    extern void gameTextRun(void);
    extern int GXFlush_(u8 visible, int unused);

    int* buttons;
    int saved;
    int frame;
    int j;
    int count;
    f32 rectAlpha;
    void (*draw)(int, int, int);
    u8 mode = kind;

    gameTextSetWindow(0);
    for (frame = 0; frame < 0x3C; frame++) {
        padUpdate();
        mmFreeTick(0);
        waitNextFrame();
        count = getButtonObjects(&buttons) & 0xFF;
        if ((u32)count != 0) {
            draw = (void (*)(int, int, int))((void**)*gScreenTransitionInterface)[1];
            draw(0, 0, 0);
            rectAlpha = lbl_803DEF98;
            drawRect(rectAlpha, rectAlpha, 0x280, 0x1E0);
            for (j = 0; j < count; j++) {
                objRenderFn_8003b8f4(buttons[j], 0, 0, 0, 0, lbl_803DEF9C);
            }
            curUiDllDraw(0, 0, 0, 0);
        } else {
            saved = lbl_803DB708;
            hudDrawColored(getLastRenderedFrame(), 0, 0, &saved, 0x200, 0);
        }
        gameTextSetColor(0xFF, 0xFF, 0xFF, 0xFF);
        if (mode == 1) {
            gameTextFn_80016810(0x323, 0, 0xC8);
        } else if (mode == 2) {
            gameTextFn_80016810(0x573, 0, 0xC8);
        } else {
            gameTextFn_80016810(0x56C, 0, 0xC8);
        }
        gameTextRun();
        GXFlush_(1, 0);
    }
}

/*
 * Card-write callback dispatched through saveGame_prepareAndWrite from _saveGame.
 * Stages a per-slot 0x6EC-byte block plus the shared 0xE4-byte trailer
 * into the card-IO buffer (lbl_803DD044), then asks saveGame_doWrite(2) to
 * commit; if that fails it falls back to saveGame_doWrite(1).
 */
int cardCb_8007e6d4(u8 slot, int unused, void* src1, void* src2)
{
    extern char* lbl_803DD044;
    extern int saveGame_doWrite(int);
    int ret;
    memcpy(lbl_803DD044 + slot * 0x6EC + 0xA50, src1, 0x6EC);
    memcpy(lbl_803DD044 + 0x1F14, src2, 0xE4);
    ret = saveGame_doWrite(2);
    if (ret == 0) {
        ret = saveGame_doWrite(1);
    }
    return ret;
}

/*
 * Card-write callback dispatched through saveGame_prepareAndWrite from maybeTryLoadSave.
 * Copies the 0xE4-byte block at offset 0x1F14 in the card buffer (held in
 * lbl_803DD044) into the caller-supplied destination.
 */
int saveCb_8007e748(int param_1, int param_2, void* dst)
{
    extern char* lbl_803DD044;
    memcpy(dst, lbl_803DD044 + 0x1F14, 0xE4);
    return 0;
}
