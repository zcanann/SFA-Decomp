#include "global.h"
#include "dolphin/mtx.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/curves_collision_state.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/waterfx_interface.h"
#include "sys/objects.h"
#include "track/intersect.h"
#include "dolphin/card.h"
#include "track/intersect_card_api.h"
#include "track/intersect_depth_read_api.h"
#include "main/model_engine.h"
#include "main/texture.h"
#include "main/dll/player_state.h"
#include "main/sky_interface.h"
#include "main/textrender_api.h"
#include "main/gametext_color_api.h"
#include "main/gameloop_api.h"
#include "main/frame_timing.h"
#include "main/trig.h"
#include "main/camera.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "main/object_render.h"
#include "main/screen_transition.h"
#include "dolphin/gx/GXPixel.h"
#include "main/mm.h"
#include "main/newshadows.h"
#include "main/maketex_api.h"
#include "main/pad.h"
#include "main/pi_dolphin.h"
#include "main/shader_api.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/mtx/vec.h"
#include "main/newshadows_audio_api.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_internal.h"

typedef struct
{
    s16 id;
    s16 unk2;
    s16 unk4;
    f32 scale;
    Vec pos;
} SplashFxParams;


typedef void (*GXSetAlphaCompareIntFn)(int comp0, int ref0, int op, int comp1, int ref1);

void objAudioDispatchAnimEvents(GameObject* obj, ObjAnimEventList* events, u8 type, void* points,
                                CurvesCollisionState* collision, f32 speed, f32 scale) {
    Vec v;
    SplashFxParams ps;
    u8* tbl;
    u16* sfxTab;
    u8 flags;
    u8 i;
    int sfx;
    u8 vecIdx;
    u8 cnt;
    f32* vec;
    int n;
    GameObject* desc;

    tbl = gSurfaceSfxTable;
    switch (type) {
    case 1:
        sfxTab = (u16*)tbl;
        break;
    case 3:
        sfxTab = (u16*)(tbl + 0x14);
        break;
    case 4:
        sfxTab = (u16*)(tbl + 0x3C);
        break;
    case 5:
        sfxTab = (u16*)(tbl + 0x64);
        break;
    case 6:
        sfxTab = (u16*)(tbl + 0x50);
        break;
    case 8:
        sfxTab = (u16*)(tbl + 0x78);
        break;
    case 10:
        sfxTab = (u16*)(tbl + 0x8C);
        break;
    case 9:
        sfxTab = (u16*)(tbl + 0xA0);
        break;
    case 7:
        sfxTab = (u16*)(tbl + 0x28);
        break;
    default:
        sfxTab = (u16*)(tbl + 0x28);
        break;
    }
    flags = 0;
    for (i = 0; i < events->triggerCount; i++) {
        switch (events->triggeredIds[i]) {
        case 1:
            flags |= 1;
            vecIdx = 0;
            break;
        case 2:
            flags |= 2;
            vecIdx = 1;
            break;
        case 3:
            flags |= 4;
            vecIdx = 2;
            break;
        case 4:
            flags |= 8;
            vecIdx = 3;
            break;
        }
    }
    if (flags == 0) {
        return;
    }
    if (!(collision->surfaceFlags & 0x10) && collision->subtype != CURVES_COLLISION_SUBTYPE_NONE) {
        return;
    }
    n = collision->segmentHits.surfaceTypes[0];
    if (n < 0 || n >= 0x23) {
        n = 0;
    } else {
        n = tbl[0xb4 + n];
    }
    sfx = n;
    desc = collision->segmentHits.objects[0];
    if (desc != NULL) {
        switch (desc->anim.romDefNo) {
        case 0x5d:
        case 0x99:
        case 0x1db:
        case 0x223:
            sfx = 4;
        }
    }
    if (sfxTab != NULL) {
        vec = (f32*)points + vecIdx * 3;
        if (collision->resultWaterDepth > 0.0f) {
            (*gWaterfxInterface)->spawnImpactSurface((u8*)obj, flags, (f32*)points, collision, speed);
            sfx = 5;
        }
        if (obj == Obj_GetPlayerObject()) {
            if (((PlayerState*)obj->extra)->characterId == 1) {
                Sfx_PlayFromObject(0, SFXTRIG_foot_ice_scuff);
            }
            Sfx_PlayFromObject(0, sfxTab[sfx]);
        } else {
            Sfx_PlayAtPositionFromObject(obj, vec[0], vec[1], vec[2], sfxTab[sfx]);
        }
    }
    if (i == 5) {
        return;
    }
    i = 0;
    scale = 0.5f * scale;
    while (flags != 0) {
        vec = (f32*)points + i * 3;
        v.x = vec[0];
        v.y = vec[1];
        v.z = vec[2];
        if (flags & 1) {
            if (obj->anim.classId == 1 || obj->anim.romDefNo == 0x416) {
                waterFxSpawnContactEffect((u8*)obj, (f32*)&v, i & 1, sfx);
            }
            ps.pos.x = vec[0];
            ps.pos.y = vec[1];
            ps.pos.z = vec[2];
            ps.scale = scale;
            ps.id = sfx;
            ps.unk4 = 0;
            ps.unk2 = 0;
            v.x = 0.25f * obj->anim.velocityX;
            v.y = 0.25f * obj->anim.velocityY;
            v.z = 0.25f * obj->anim.velocityZ;
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
        i++;
    }
}

void* surfaceSfxGetRecord(u32 i)
{
    u8* base = gSurfaceSfxTable;
    switch (i)
    {
    case 1:
        return base;
    case 3:
        return base + 0x14;
    case 4:
        return base + 0x3C;
    case 5:
        return base + 0x64;
    case 6:
        return base + 0x50;
    case 8:
        return base + 0x78;
    case 10:
        return base + 0x8C;
    case 9:
        return base + 0xA0;
    case 7:
        return base + 0x28;
    default:
        return base + 0x28;
    }
}

int lbl_803DD03C;
f32 gFogNearZ;
f32 gFogFarZ;
u32 gTevStageCursor;
u32 gTevTexCoordCursor;
u32 gTevTexMapCursor;
f32 gFogStartZ;
f32 gFogEndZ;
GXColor gFogColor;
u8 gGxZModeValid;
u8 gGxZCompLocValid;
u8 gGxZModeCompareEnable;
int gGxZModeCompareFunc;
u8 gGxZModeUpdateEnable;
u8 gGxZCompLocCached;
u8 gMoonFxDayNo;
f32 gSnowFlashOverlayAngle;
u8 gTevStageCount;
u8 gTevTexGenCount;
u8 gTevChanCount;
u8 gTevIndStageCount;
u32 screenWidth;
u16 gDepthReadResultCount;
u16 gDepthReadPendingCount;
u32 sIntersectUnused0;
u8 gWaterFxDisabled;
u8 gWaterQuadWriteIdx;
u8 gWaterRippleWriteIdx;
u32 lbl_803DCFF4;
u8 gWaterFxBank;

u8 gReflectionTintAlpha = 0x60;
u8 gHudTintAlpha = 0xFF;
GXColor gWaterCausticKColor = {0xFF, 0xFF, 0xFF, 0x60};
GXColor gReflectionBumpTintColor = {0xFF, 0xFF, 0xFF, 0x60};
GXColor gReflectionBumpKColor = {0xA0, 0xA0, 0xA0, 0x80};
GXColor gReflectionTintColor = {0xFF, 0xFF, 0xFF, 0x60};
GXColor gReflectionKColor = {0xA0, 0xA0, 0xA0, 0x80};
GXColor gWaterReflectionKColorR = {0xC0, 0, 0, 0};
GXColor gWaterReflectionKColorG = {0, 0xC0, 0, 0};
GXColor gWaterReflectionKColorB = {0, 0, 0xC0, 0};
GXColor gBlurFilterKColor = {0x66, 0x66, 0x66, 0xFF};
GXColor gMotionBlurKColor = {0, 0, 0, 0x7F};
GXColor gHeatEffectKColor = {0xFF, 0xFF, 0xFF, 0xFC};
GXColor gObjectShadowTevColor = {0xFF, 0xFF, 0xFF, 0xFF};
f32 gCausticReflectionDiskScale = 0.55f;
f32 gTrackProjectedTexScale = 2.0f;
f32 gTrackNormalTexScale = 0.25f;
f32 gFrozenReflectionNormalScale = 0.4f;
GXColor gFrozenTintColor = {0x80, 0x80, 0x80, 0xFF};
f32 gFrozenWhirlpoolTexScale = 2.0f;
f32 gDistortionTexCoordScale = 0.3878f;
f32 gDistortionAlphaRadius = 15.0f;
f32 gDistortionIndMtxRadius = 100.0f;
GXColor gSpiritVisionKColor0 = {0x42, 0x42, 0x42, 0};
GXColor gSpiritVisionKColor1 = {0x81, 0x81, 0x81, 0};
GXColor gSpiritVisionKColor2 = {0x19, 0x19, 0x19, 0};
GXColor gSpiritVisionRegColor = {0x10, 0x10, 0x10, 0xFF};
GXColor gScreenImageRegColor = {0, 0, 0, 0xFF};
GXColor gScreenImageKColor0 = {0, 0, 0x80, 0};
GXColor gScreenImageKColor1 = {0x80, 0x80, 0, 0};
GXColor gScreenImageKColor2 = {0, 0x80, 0, 0};
GXColor gScreenImageKColor3 = {0x80, 0, 0x80, 0};
GXColor gWhirlpoolReflectionTintColor = {0xFF, 0xFF, 0xFF, 0x60};
GXColor gWhirlpoolReflectionKColor = {0xA0, 0xA0, 0xA0, 0x80};
static u32 sIntersectUnused1[1] = {0};



/* Per-frame alpha decrement of the two water-effect pools. */
void waterFxUpdate(f32 step) {
    int i;
    SplashQuad* quad;
    RippleEntry* ripple;
    u8 alpha;

    for (i = 0; i < 256; i++) {
        quad = &gWaterSplashQuads[i];
        ripple = &gWaterRipples[i];
        alpha = quad->alpha;
        if (alpha != 0) {
            if (alpha - step <= 0.0f) {
                quad->alpha = 0;
            } else {
                quad->alpha -= step;
            }
        }
        alpha = ripple->alpha;
        if (alpha != 0) {
            if (alpha - step <= 0.0f) {
                ripple->alpha = 0;
            } else {
                ripple->alpha -= step;
            }
        }
    }
}

void waterFxDraw(void)
{
    GXColor color;
    Mtx camTrans;
    Mtx posMtx;
    Mtx rot;
    Mtx trans;
    SplashQuad* quad;
    f32* view;
    int i;
    f32 tTop;
    f32 tBot;
    f32 sLeft;
    f32 sRight;
    u8 alpha;

    if (Obj_GetPlayerObject() == NULL)
    {
        return;
    }
    Camera_ApplyDecalViewport();
    GXSetCurrentMtx(GX_PNMTX0);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    selectTexture(gWaterFxTextures[gWaterFxBank], 0);
    view = Camera_GetViewMatrix();
    PSMTXTrans(camTrans, -playerMapOffsetX, 0.0f, -playerMapOffsetZ);
    PSMTXConcat((MtxP)view, camTrans, posMtx);
    GXLoadPosMtxImm(posMtx, GX_PNMTX0);
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    sLeft = 0.0f;
    sRight = 1.0f;
    i = 0;
    for (; i < 0x100; i++)
    {
        quad = &gWaterSplashQuads[i];
        alpha = quad->alpha;
        if (alpha != 0)
        {
            if (quad->type == 1)
            {
                color.a = alpha >> 2;
            }
            else
            {
                color.a = alpha >> 1;
            }
            GXSetTevKColor(GX_KCOLOR0, color);
            if (quad->flip != 0)
            {
                tTop = 1.0f;
                tBot = 0.0f;
                PSMTXRotRad(rot, 0x7a,
                            2.0f * (3.142f * (f32)(int)(0x8000 - quad->angle)) / 65536.0f);
            }
            else
            {
                tTop = 0.0f;
                tBot = 1.0f;
                PSMTXRotRad(rot, 0x7a, 2.0f * (3.142f * (f32)(u32)quad->angle) / 65536.0f);
            }
            PSMTXTrans(trans, -0.5f, -0.5f, 0.0f);
            PSMTXConcat(rot, trans, rot);
            PSMTXTrans(trans, 0.5f, 0.5f, 0.0f);
            PSMTXConcat(trans, rot, rot);
            GXLoadTexMtxImm(rot, GX_TEXMTX0, GX_MTX2x4);
            GXBegin(GX_QUADS, GX_VTXFMT2, 4);
            {
                f32 px, py, pz;
                pz = quad->v[2];
                py = quad->v[1];
                px = quad->v[0];
                GXWGFifo.f32 = px;
                GXWGFifo.f32 = py;
                GXWGFifo.f32 = pz;
            }
            GXWGFifo.f32 = sLeft;
            GXWGFifo.f32 = tTop;
            {
                f32 px, py, pz;
                pz = quad->v[5];
                py = quad->v[4];
                px = quad->v[3];
                GXWGFifo.f32 = px;
                GXWGFifo.f32 = py;
                GXWGFifo.f32 = pz;
            }
            GXWGFifo.f32 = sRight;
            GXWGFifo.f32 = tTop;
            {
                f32 px, py, pz;
                pz = quad->v[8];
                py = quad->v[7];
                px = quad->v[6];
                GXWGFifo.f32 = px;
                GXWGFifo.f32 = py;
                GXWGFifo.f32 = pz;
            }
            GXWGFifo.f32 = sRight;
            GXWGFifo.f32 = tBot;
            {
                f32 px, py, pz;
                pz = quad->v[11];
                py = quad->v[10];
                px = quad->v[9];
                GXWGFifo.f32 = px;
                GXWGFifo.f32 = py;
                GXWGFifo.f32 = pz;
            }
            GXWGFifo.f32 = sLeft;
            GXWGFifo.f32 = tBot;
        }
    }
    Camera_ApplyFullViewport();
}



void waterFxSpawnContactEffect(u8* obj, f32* pos, u8 flip, u8 type)
{
    WaterFxState* base;
    f32 x, y, z;
    f32 ax, px;
    f32 ay, py, az, pz;
    f32 xm, ym, zm;
    f32 groundY;
    Vec axis;
    Vec perp;
    Vec norm;
    f32 fscale;

    base = (WaterFxState*)gWaterFxState;
    if (((GameObject*)obj)->anim.classId == 1)
    {
        gWaterFxBank = ((GameObject*)obj)->anim.bankIndex;
    }
    else if (((GameObject*)obj)->anim.romDefNo == 0x416)
    {
        gWaterFxBank = 3;
    }
    if (trackGetNearestGroundOffsetAndNormal((GameObject*)obj, ((GameObject*)obj)->anim.localPosX,
                                             ((GameObject*)obj)->anim.localPosY,
                                             ((GameObject*)obj)->anim.localPosZ, &groundY, (f32*)&norm, 0) == 0)
    {
        if (type == 1)
        {
            base->ripples[gWaterRippleWriteIdx].x = pos[0];
            base->ripples[gWaterRippleWriteIdx].y = 2.0f + pos[1];
            base->ripples[gWaterRippleWriteIdx].z = pos[2];
            base->ripples[gWaterRippleWriteIdx].id = *(s16*)obj;
            base->ripples[gWaterRippleWriteIdx].alpha = 0xff;
            base->ripples[gWaterRippleWriteIdx].flip = flip;
            gWaterRippleWriteIdx++;
            if (gWaterRippleWriteIdx >= 0x100)
            {
                gWaterRippleWriteIdx = 0;
            }
        }
        PSVECNormalize(&norm, &norm);
        axis.x = 1.0f;
        axis.y = 0.0f;
        axis.z = 0.0f;
        if (__fabsf(PSVECDotProduct(&norm, &axis)) >= 0.9f)
        {
            axis.x = 0.0f;
            axis.z = 1.0f;
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
        base->quads[gWaterQuadWriteIdx].angle = 0x10000 - *(s16*)obj;
        base->quads[gWaterQuadWriteIdx].type = type;
        base->quads[gWaterQuadWriteIdx].alpha = 0xff;
        base->quads[gWaterQuadWriteIdx].flip = flip;
        gWaterQuadWriteIdx++;
        if (gWaterQuadWriteIdx >= 0x100)
        {
            gWaterQuadWriteIdx = 0;
        }
    }
}

void waterFxSetDisabled(int disabled)
{
    int i;
    SplashQuad* quads;
    RippleEntry* ripples;

    gWaterFxDisabled = disabled;
    if (disabled != 0)
    {
        return;
    }
    quads = gWaterSplashQuads;
    ripples = gWaterRipples;
    for (i = 0; i < 32; i++)
    {
        quads[i * 8].alpha = 0;
        ripples[i * 8].alpha = 0;
        quads[i * 8 + 1].alpha = 0;
        ripples[i * 8 + 1].alpha = 0;
        quads[i * 8 + 2].alpha = 0;
        ripples[i * 8 + 2].alpha = 0;
        quads[i * 8 + 3].alpha = 0;
        ripples[i * 8 + 3].alpha = 0;
        quads[i * 8 + 4].alpha = 0;
        ripples[i * 8 + 4].alpha = 0;
        quads[i * 8 + 5].alpha = 0;
        ripples[i * 8 + 5].alpha = 0;
        quads[i * 8 + 6].alpha = 0;
        ripples[i * 8 + 6].alpha = 0;
        quads[i * 8 + 7].alpha = 0;
        ripples[i * 8 + 7].alpha = 0;
    }
    gWaterQuadWriteIdx = 0;
    gWaterRippleWriteIdx = 0;
}

void waterFxInit(void)
{
    int i;
    WaterFxState* waterFx = (WaterFxState*)gWaterFxState;
    SplashQuad* quads = waterFx->quads;
    RippleEntry* ripples = waterFx->ripples;

    for (i = 0; i < 16; i++)
    {
        quads[0].alpha = 0;
        ripples[0].alpha = 0;
        quads[1].alpha = 0;
        ripples[1].alpha = 0;
        quads[2].alpha = 0;
        ripples[2].alpha = 0;
        quads[3].alpha = 0;
        ripples[3].alpha = 0;
        quads[4].alpha = 0;
        ripples[4].alpha = 0;
        quads[5].alpha = 0;
        ripples[5].alpha = 0;
        quads[6].alpha = 0;
        ripples[6].alpha = 0;
        quads[7].alpha = 0;
        ripples[7].alpha = 0;
        quads[8].alpha = 0;
        ripples[8].alpha = 0;
        quads[9].alpha = 0;
        ripples[9].alpha = 0;
        quads[10].alpha = 0;
        ripples[10].alpha = 0;
        quads[11].alpha = 0;
        ripples[11].alpha = 0;
        quads[12].alpha = 0;
        ripples[12].alpha = 0;
        quads[13].alpha = 0;
        ripples[13].alpha = 0;
        quads[14].alpha = 0;
        ripples[14].alpha = 0;
        quads[15].alpha = 0;
        ripples[15].alpha = 0;
        quads += 16;
        ripples += 16;
    }
    waterFx->textures[0] = textureLoadAsset(0x19);
    waterFx->textures[1] = textureLoadAsset(0x18);
    waterFx->textures[2] = textureLoadAsset(0x1A);
    waterFx->textures[3] = textureLoadAsset(0x646);
    waterFx->scales[0] = 4.0f;
    waterFx->scales[1] = 5.0f;
    waterFx->scales[2] = 5.0f;
    waterFx->scales[3] = 8.0f;
    gWaterFxDisabled = 0;
    gWaterQuadWriteIdx = 0;
    gWaterRippleWriteIdx = 0;
    lbl_803DCFF4 = 0;
}


/* .bss block 0x80391DC0-0x803967C0 */
SaveCardFileInfo gSaveCardFileInfo;
int gPerspectiveMtx[0x10];
f32 hudMatrix[4][4];
f32 gCameraLightPerspectiveScaledMatrix[3][4];
f32 gCameraLightPerspectiveFlipYMatrix[3][4];
f32 gCameraLightPerspectiveMatrix[3][4];
f32 gCameraModelViewMatrix[3][4];
DepthReadRequest gDepthReadPendingQueue[0x14];
DepthReadRequest gDepthReadResults[0x14];
SplashQuad gWaterSplashQuads[0x100];
RippleEntry gWaterRipples[0x100];
Texture* gWaterFxTextures[4];
f32 gWaterFxState[4];
