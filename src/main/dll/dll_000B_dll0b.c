/*
 * dll0b (DLL 0x0B) - the engine-wide procedural particle (partfx) back end
 * used across the game's effect DLLs.
 *
 * Responsibilities:
 *   - the partfx pending-spawn queue (dll_0B_func10..func18) and the
 *     0x32-slot active-particle table (dll_0B_func04 allocate,
 *     dll_0B_func05 update, dll_0B_func09 render, fn_800A1040 free).
 *   - modgfx_stepS16VectorLerp: per-frame s16 vector interpolation helper.
 *
 * A block of modgfx vertex-animation / expgfx pool / projgfx preset-spawn
 * scaffolding (modgfx_* helpers, projgfx_spawnPresetEffect and the
 * projgfx_funcs descriptor) was copy-pasted in from the sibling effect DLLs
 * but is not part of the retail dll0b unit; it was dead here and removed.
 */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_play_pointer_legacy_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/dll/bonespawndata_struct.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/frame_timing.h"
#include "main/lightmap_api.h"
#include "main/lightmap_text_color_api.h"
#include "track/intersect_render_setup_api.h"
#include "track/intersect_geom_api.h"
#include "main/shader_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/dll/modgfx.h"
#include "main/resource.h"
#include "main/texture.h"
#include "main/mm.h"
#include "main/vecmath.h"
#include "main/camera.h"
#include "main/dll/dll_000B_dll0b.h"
#include "main/obj_list.h"
#include "dolphin/gx/GXEnum.h"
#include "main/render_mode_api.h"

ModgfxPendingSpawn* gModgfxPendingSpawnStartCursor;
ModgfxPendingSpawn* gModgfxPendingSpawnWriteCursor;
s16 gModgfxSequenceParamIndex;
s16 gModgfxLastSpawnHandle;
f32 gModgfxMotionStep;
u8 lbl_803DD282;
s16 gPartfxSequenceIdCounter;

#define DLL0B_OBJFLAG_RENDERED 0x800

/* DLL-id of the object spawned to back a modgfx effect slot (generic effect
   object; no cache field / spawn-fn / kind name -> suffixless per role-gate). */
#define DLL0B_CHILD_OBJ 0x66

typedef struct ModgfxEffectSlot
{
    u8 pad0[0x4 - 0x0];
    void* sourceObj;
    u8 pad8[0xC - 0x8];
    s16 unkC;
    u8 padE[0x18 - 0xE];
    f32 posOffsetX;
    f32 posOffsetY;
    f32 posOffsetZ;
    f32 motionOffsetX;
    f32 motionOffsetY;
    f32 motionOffsetZ;
    u8 pad30[0x60 - 0x30];
    f32 posCurX;
    f32 posCurY;
    f32 posCurZ;
    u8 pad6C[0x9C - 0x6C];
    void* unk9C;
    u8 padA0[0xA4 - 0xA0];
    s32 sourceFlags;
    u8 padA8[0xBC - 0xA8];
    f32 alphaDelta;
    f32 alphaCurrent;
    u8 padC4[0xEE - 0xC4];
    s16 frameTimings[7];
    s16 frameIndex;
    s16 frameDuration;
    u8 pad100[0x106 - 0x100];
    s16 rotOffsetZ;
    s16 rotOffsetY;
    s16 rotOffsetX;
    s16 animSlotId;
    u8 pad10E[0x139 - 0x10E];
    s8 emitterCount;
    u8 unk13A;
    u8 pad13B[0x13C - 0x13B];
    u8 pendingFrameIdx;
    u8 pad13D[0x13E - 0x13D];
    u8 unk13E;
    u8 pad13F[0x140 - 0x13F];
} ModgfxEffectSlot;

STATIC_ASSERT(offsetof(ModgfxState, vertexBuffers) == 0x78);
STATIC_ASSERT(offsetof(ModgfxState, alphaChannels) == 0xAC);
STATIC_ASSERT(offsetof(ModgfxState, blendColorR) == 0xBC);
STATIC_ASSERT(offsetof(ModgfxState, vertexCount) == 0xEA);
STATIC_ASSERT(offsetof(ModgfxState, posCurX) == 0x60);
STATIC_ASSERT(offsetof(ModgfxState, activeChannel) == 0xFC);
STATIC_ASSERT(offsetof(ModgfxState, rotStepZ) == 0x100);
STATIC_ASSERT(offsetof(ModgfxState, rotOffsetZ) == 0x106);

#define PARTFX_ACTIVE_EFFECT_COUNT 0x32

STATIC_ASSERT(sizeof(ModgfxSpawnContext) == 0x60);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, vecX) == 0x20);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, posX) == 0x2C);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, sequenceParams) == 0x46);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, flags) == 0x54);
STATIC_ASSERT(offsetof(ModgfxSpawnContext, pendingSpawnCount) == 0x5D);

STATIC_ASSERT(sizeof(PartfxEffectState) == 0x140);
STATIC_ASSERT(offsetof(PartfxEffectState, vertexBuffers) == 0x78);
STATIC_ASSERT(offsetof(PartfxEffectState, textureResource) == 0x98);
STATIC_ASSERT(offsetof(PartfxEffectState, flags) == 0xA4);
STATIC_ASSERT(offsetof(PartfxEffectState, drawPosX) == 0x60);
STATIC_ASSERT(offsetof(PartfxEffectState, velocityX) == 0x6C);
STATIC_ASSERT(offsetof(PartfxEffectState, alphaChannels) == 0xAC);
STATIC_ASSERT(offsetof(PartfxEffectState, blendColorR) == 0xBC);
STATIC_ASSERT(offsetof(PartfxEffectState, renderScale) == 0xD4);
STATIC_ASSERT(offsetof(PartfxEffectState, vertexCount) == 0xEA);
STATIC_ASSERT(offsetof(PartfxEffectState, colorVertexCount) == 0xEC);
STATIC_ASSERT(offsetof(PartfxEffectState, stageDurations) == 0xEE);
STATIC_ASSERT(offsetof(PartfxEffectState, sequenceId) == 0x10C);
STATIC_ASSERT(offsetof(PartfxEffectState, inlineData) == 0x12C);
STATIC_ASSERT(offsetof(PartfxEffectState, activeVertexBufferIndex) == 0x130);
STATIC_ASSERT(offsetof(PartfxEffectState, emitterCount) == 0x139);
STATIC_ASSERT(offsetof(PartfxEffectState, textureIsBorrowed) == 0x13F);

u8 gModgfxSpawnContextStorage[0x60];
ModgfxPendingSpawn gModgfxPendingSpawnQueue[0x300 / sizeof(ModgfxPendingSpawn)];
extern void fn_800A1040(s16 a, int b);
extern f32 lbl_803DF430;
extern f32 lbl_803DF434;
extern void _textSetColor(void* ctx, int r, int g, int b, int a);
extern f32 gModgfxMotionStep;

s16 dll_0B_func04(void* base, int z, int c, void* b, int e, void* d, int f, void* g);

#define gModgfxSpawnContext (*(ModgfxSpawnContext*)gModgfxSpawnContextStorage)
s16 dll_0B_func18(void)
{
    return gModgfxLastSpawnHandle;
}

#pragma peephole off
#pragma scheduling off
void dll_0B_func17(u32 flags)
{
    gModgfxSpawnContext.flags |= flags;
}

void dll_0B_func16(void* a, void* b, void* c, void* d, void* e, int f, void* g)
{
    gModgfxSpawnContext.pendingSpawns = gModgfxPendingSpawnQueue;
    gModgfxSpawnContext.pendingSpawnCount = gModgfxPendingSpawnWriteCursor - gModgfxPendingSpawnStartCursor;
    if (g == NULL && f == 0)
    {
        gModgfxSpawnContext.flags |= 0x2000000LL;
    }
    else
    {
        gModgfxSpawnContext.flags |= 0x4000000LL;
    }
    if (gModgfxSpawnContext.flags & 1)
    {
        if (gModgfxSpawnContext.attachedSource != NULL)
        {
            gModgfxSpawnContext.posX += ((ExpgfxSourceObject*)gModgfxSpawnContext.attachedSource)->worldPosX;
            gModgfxSpawnContext.posY += ((ExpgfxSourceObject*)gModgfxSpawnContext.attachedSource)->worldPosY;
            gModgfxSpawnContext.posZ += ((ExpgfxSourceObject*)gModgfxSpawnContext.attachedSource)->worldPosZ;
        }
        else
        {
            gModgfxSpawnContext.posX += ((ExpgfxSourceObject*)a)->localPosX;
            gModgfxSpawnContext.posY += ((ExpgfxSourceObject*)a)->localPosY;
            gModgfxSpawnContext.posZ += ((ExpgfxSourceObject*)a)->localPosZ;
        }
    }
    gModgfxLastSpawnHandle = dll_0B_func04(&gModgfxSpawnContext, 0, (int)c, b, (int)e, d, f, g);
}

void dll_0B_func15(void* params)
{
    memcpy(gModgfxSpawnContext.sequenceParams, params, 0xe);
}

void dll_0B_func14(s16 value)
{
    u8* state = gModgfxSpawnContextStorage;
    state = state + gModgfxSequenceParamIndex * 2;
    *(s16*)(state + 0x46) = value;
}

void dll_0B_func13(s16 x)
{
    gModgfxSequenceParamIndex = x;
}

void dll_0B_func12(void)
{
    gModgfxSequenceParamIndex++;
}

void dll_0B_func11(int modelOrResource, float posX, float posY, float posZ, s16 param14, int param10)
{
    u32 sequenceIndex = gModgfxSequenceParamIndex;
    gModgfxPendingSpawnWriteCursor->sequenceIndex = sequenceIndex;
    gModgfxPendingSpawnWriteCursor->param14 = param14;
    gModgfxPendingSpawnWriteCursor->param10 = param10;
    gModgfxPendingSpawnWriteCursor->modelOrResource = modelOrResource;
    gModgfxPendingSpawnWriteCursor->posX = posX;
    gModgfxPendingSpawnWriteCursor->posY = posY;
    gModgfxPendingSpawnWriteCursor->posZ = posZ;
    gModgfxPendingSpawnWriteCursor++;
}



void dll_0B_func10(void)
{
    ModgfxPendingSpawn* cursor = gModgfxPendingSpawnQueue;
    gModgfxPendingSpawnStartCursor = cursor;
    gModgfxPendingSpawnWriteCursor = cursor;
    gModgfxSequenceParamIndex = 0;
}


void dll_0B_func0F(int source, u8 mode, u8 flagByte, int word40, int word3C)
{
    f32 fz;
    f32 fz2;
    memset(&gModgfxSpawnContext, 0, sizeof(gModgfxSpawnContext));
    gModgfxSpawnContext.modeByte = mode;
    gModgfxSpawnContext.attachedSource = (void*)source;
    gModgfxSpawnContext.sourceModeCopy = mode;
    fz = lbl_803DF430;
    gModgfxSpawnContext.posX = fz;
    gModgfxSpawnContext.posY = fz;
    gModgfxSpawnContext.posZ = fz;
    gModgfxSpawnContext.vecX = fz;
    gModgfxSpawnContext.vecY = fz;
    gModgfxSpawnContext.vecZ = fz;
    fz2 = lbl_803DF434;
    gModgfxSpawnContext.scale = fz2;
    gModgfxSpawnContext.drawGroupCount = word40;
    gModgfxSpawnContext.drawGroupStride = word3C;
    gModgfxSpawnContext.initialStateByte = flagByte;
    gModgfxSpawnContext.byte5A = 0;
    gModgfxSpawnContext.textureFrameTimer = 0;
}

extern void GXSetCullMode(int mode);

#define GX_CULL_NONE  0
#define GX_CULL_FRONT 1
extern void gxTexColorFn_80079254(void);
extern void gxBlendFn_80078b4c(void);

/* Per-bone particle vertex update + draw. */


void fn_800A02DC(ModgfxState* state, f32* in)
{
    extern f32 gModgfxMotionStep;
    int i;
    s32 dy, dx;
    ModgfxVertexData* slot;
    ModgfxVertexData* cur;
    ModgfxVertexData* prev;
    u8 ovx, ovy;
    int j;

    dx = (s32)(4.0f * (in[1] * gModgfxMotionStep));
    dy = (s32)(4.0f * (in[2] * gModgfxMotionStep));

    cur = state->vertexBuffers[state->activeVertexBufferIndex];
    prev = state->vertexBuffers[1 - state->activeVertexBufferIndex];

    ovx = 0;
    ovy = 0;
    for (i = 0; i < state->vertexCount; i++)
    {
        cur->texCoordS = prev->texCoordS;
        cur->texCoordT = prev->texCoordT;
        cur->texCoordS = (s16)(cur->texCoordS + dx);
        if ((s32)cur->texCoordS > 0x100)
            ovx++;
        if ((s32)cur->texCoordS < -0x100)
            ovx++;
        cur->texCoordT = (s16)(cur->texCoordT + dy);
        if ((s32)cur->texCoordT > 0x100)
            ovy++;
        if ((s32)cur->texCoordT < -0x100)
            ovy++;
        cur++;
        prev++;
    }

    slot = state->vertexBuffers[state->activeVertexBufferIndex];
    for (j = 0; j < state->vertexCount; j++)
    {
        if ((s32)ovx == state->vertexCount)
        {
            if ((s32)slot->texCoordS > 0x100)
            {
                slot->texCoordS -= 0x100;
            }
            else
            {
                slot->texCoordS += 0x100;
            }
        }
        if ((s32)ovy == state->vertexCount)
        {
            if ((s32)slot->texCoordT > 0x100)
            {
                slot->texCoordT -= 0x100;
            }
            else
            {
                slot->texCoordT += 0x100;
            }
        }
        slot++;
    }
}

void* gPartfxActiveEffects[0x32];
#pragma peephole reset
#pragma peephole on

void fn_800A0478(ModgfxState* state)
{
    int i;
    ModgfxVertexData* dst;
    ModgfxVertexData* src;
    f32 f1;
    f32 f0;
    src = state->vertexBuffers[1 - state->activeVertexBufferIndex];
    dst = state->baseVertexData;
    for (i = 0; i < state->vertexCount; i++)
    {
        dst->posX = src->posX;
        dst->posY = src->posY;
        dst->posZ = src->posZ;
        dst->colorR = src->colorR;
        dst->colorG = src->colorG;
        dst->colorB = src->colorB;
        dst->alpha = src->alpha;
        dst++;
        src++;
    }
    f1 = *(f32*)&lbl_803DF434;
    state->scaleChannels[0].cur[0] = f1;
    state->scaleChannels[0].cur[1] = f1;
    state->scaleChannels[0].cur[2] = f1;
    f0 = lbl_803DF430;
    state->scaleChannels[0].step[0] = f0;
    state->scaleChannels[0].step[1] = f0;
    state->scaleChannels[0].step[2] = f0;
    state->scaleChannels[1].cur[0] = f1;
    state->scaleChannels[1].cur[1] = f1;
    state->scaleChannels[1].cur[2] = f1;
    state->scaleChannels[1].step[0] = f0;
    state->scaleChannels[1].step[1] = f0;
    state->scaleChannels[1].step[2] = f0;
}
#pragma peephole reset
#pragma peephole off


void fn_800A0524(void* state, void* p, int mode)
{
    u8* buf = ((u8**)((char*)state + 0x78))[((ModgfxState*)state)->activeVertexBufferIndex];
    int j;

    if (mode == 1)
    {
        f32 tr = ((ModgfxVertexGroupCmd*)p)->valueX;
        f32 tg = ((ModgfxVertexGroupCmd*)p)->valueY;
        f32 tb = ((ModgfxVertexGroupCmd*)p)->valueZ;
        if (((ModgfxState*)state)->blendFrameCount != 0)
        {
            ((ModgfxState*)state)->blendColorR = (f32)(u32)buf[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xc];
            ((ModgfxState*)state)->blendColorG = (f32)(u32)buf[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xd];
            ((ModgfxState*)state)->blendColorB = (f32)(u32)buf[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xe];
            ((ModgfxState*)state)->blendColorStepR =
                (tr - (f32)(u32)buf[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xc]) / (f32) * (s16*)((char*)state + 0xfe);
            ((ModgfxState*)state)->blendColorStepG =
                (tg - (f32)(u32)buf[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xd]) / (f32) * (s16*)((char*)state + 0xfe);
            ((ModgfxState*)state)->blendColorStepB =
                (tb - (f32)(u32)buf[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xe]) / (f32) * (s16*)((char*)state + 0xfe);
        }
        else
        {
            ((ModgfxState*)state)->blendColorR = tr;
            ((ModgfxState*)state)->blendColorG = tg;
            ((ModgfxState*)state)->blendColorB = tb;
            {
                f32 z = lbl_803DF430;
                ((ModgfxState*)state)->blendColorStepR = z;
                ((ModgfxState*)state)->blendColorStepG = z;
                ((ModgfxState*)state)->blendColorStepB = z;
            }
        }
    }
    ((ModgfxState*)state)->blendColorR += ((ModgfxState*)state)->blendColorStepR;
    ((ModgfxState*)state)->blendColorG += ((ModgfxState*)state)->blendColorStepG;
    ((ModgfxState*)state)->blendColorB += ((ModgfxState*)state)->blendColorStepB;
    if (((ModgfxState*)state)->blendColorR < lbl_803DF430)
    {
        ((ModgfxState*)state)->blendColorR = lbl_803DF430;
    }
    else if (((ModgfxState*)state)->blendColorR > 255.0f)
    {
        ((ModgfxState*)state)->blendColorR = 255.0f;
    }
    if (((ModgfxState*)state)->blendColorG < lbl_803DF430)
    {
        ((ModgfxState*)state)->blendColorG = lbl_803DF430;
    }
    else if (((ModgfxState*)state)->blendColorG > 255.0f)
    {
        ((ModgfxState*)state)->blendColorG = 255.0f;
    }
    if (((ModgfxState*)state)->blendColorB < lbl_803DF430)
    {
        ((ModgfxState*)state)->blendColorB = lbl_803DF430;
    }
    else if (((ModgfxState*)state)->blendColorB > 255.0f)
    {
        ((ModgfxState*)state)->blendColorB = 255.0f;
    }
    for (j = 0; j < ((ModgfxVertexGroupCmd*)p)->indexCount; j++)
    {
        buf[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xc] = (int)((ModgfxState*)state)->blendColorR;
        buf[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xd] = (int)((ModgfxState*)state)->blendColorG;
        buf[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xe] = (int)((ModgfxState*)state)->blendColorB;
    }
}

void fn_800A081C(int state, int cmd, int mode)
{
    extern f32 gModgfxMotionStep;

    if (mode == 1)
    {
        s16* cf = ((ModgfxState*)state)->channelFrames;
        if (cf[((ModgfxState*)state)->activeChannel] == 0)
        {
            int flags = ((ModgfxState*)state)->flags;
            if ((flags & 0x4) != 0 || (flags & 0x80000) != 0)
            {
                s16 buf[12];
                f32* fbuf = (f32*)&buf[4];
                s16 posBase;
                f32 fill = lbl_803DF430;
                fbuf[1] = fill;
                fbuf[2] = fill;
                fbuf[3] = fill;
                fbuf[0] = lbl_803DF434;
                posBase = *((ModgfxState*)state)->unk04;
                buf[0] = posBase;
                buf[1] = posBase;
                buf[2] = posBase;
                vecRotateZXY(buf, (f32*)(cmd + 0x4));
            }
            ((ModgfxState*)state)->posStepX = ((ModgfxVertexGroupCmd*)cmd)->valueX;
            ((ModgfxState*)state)->posStepY = ((ModgfxVertexGroupCmd*)cmd)->valueY;
            ((ModgfxState*)state)->posStepZ = ((ModgfxVertexGroupCmd*)cmd)->valueZ;
        }
        else
        {
            ((ModgfxState*)state)->posStepX =
                ((ModgfxVertexGroupCmd*)cmd)->valueX / (f32)(s32)((ModgfxState*)state)->blendFrameCount;
            ((ModgfxState*)state)->posStepY =
                ((ModgfxVertexGroupCmd*)cmd)->valueY / (f32)(s32)((ModgfxState*)state)->blendFrameCount;
            ((ModgfxState*)state)->posStepZ =
                ((ModgfxVertexGroupCmd*)cmd)->valueZ / (f32)(s32)((ModgfxState*)state)->blendFrameCount;
        }
        ((ModgfxState*)state)->posCurX = ((ModgfxState*)state)->posCurX + ((ModgfxState*)state)->posStepX;
        ((ModgfxState*)state)->posCurY = ((ModgfxState*)state)->posCurY + ((ModgfxState*)state)->posStepY;
        ((ModgfxState*)state)->posCurZ = ((ModgfxState*)state)->posCurZ + ((ModgfxState*)state)->posStepZ;
    }
    else
    {
        ((ModgfxState*)state)->posCurX =
            ((ModgfxState*)state)->posStepX * gModgfxMotionStep + ((ModgfxState*)state)->posCurX;
        ((ModgfxState*)state)->posCurY =
            ((ModgfxState*)state)->posStepY * gModgfxMotionStep + ((ModgfxState*)state)->posCurY;
        ((ModgfxState*)state)->posCurZ =
            ((ModgfxState*)state)->posStepZ * gModgfxMotionStep + ((ModgfxState*)state)->posCurZ;
    }
}

/* Integer-vector lerp setup. On mode 1, snap or step-interpolate the rotation offset triple
 * toward the rounded params, then advance it by the per-step delta. */
void modgfx_stepS16VectorLerp(int* obj, f32* params, int mode)
{
    if (mode == 1)
    {
        s16 tx = params[1];
        s16 ty = params[2];
        s16 tz = params[3];
        if (((ModgfxState*)obj)->blendFrameCount != 0)
        {
            ((ModgfxState*)obj)->rotStepZ =
                (s16)((tx - ((ModgfxState*)obj)->rotOffsetZ) / ((ModgfxState*)obj)->blendFrameCount);
            ((ModgfxState*)obj)->rotStepY =
                (s16)((ty - ((ModgfxState*)obj)->rotOffsetY) / ((ModgfxState*)obj)->blendFrameCount);
            ((ModgfxState*)obj)->rotStepX =
                (s16)((tz - ((ModgfxState*)obj)->rotOffsetX) / ((ModgfxState*)obj)->blendFrameCount);
        }
        else
        {
            ((ModgfxState*)obj)->rotOffsetZ = tx;
            ((ModgfxState*)obj)->rotStepZ = 0;
            ((ModgfxState*)obj)->rotOffsetY = ty;
            ((ModgfxState*)obj)->rotStepY = 0;
            ((ModgfxState*)obj)->rotOffsetX = tz;
            ((ModgfxState*)obj)->rotStepX = 0;
        }
    }
    ((ModgfxState*)obj)->rotOffsetZ += ((ModgfxState*)obj)->rotStepZ;
    ((ModgfxState*)obj)->rotOffsetY += ((ModgfxState*)obj)->rotStepY;
    ((ModgfxState*)obj)->rotOffsetX += ((ModgfxState*)obj)->rotStepX;
}
#pragma opt_common_subs off
void fn_800A0AB4(void* state, void* p, int mode, u8 idx)
{
    extern f32 gModgfxMotionStep;
    int k = idx * 2;
    char* slots = (char*)state + 0x78;
    u8* bufB = *(u8**)(slots + ((ModgfxState*)state)->activeVertexBufferIndex * 4);
    u8* bufA = *(u8**)((char*)state + 0x80);
    int j;

    if (mode == 1)
    {
        f32 target = ((ModgfxVertexGroupCmd*)p)->valueX;
        s16 frames = ((ModgfxState*)state)->blendFrameCount;
        if (frames != 0)
        {
            ((f32*)((char*)state + 0xac))[k] =
                (target - (f32)(u32)bufA[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xf]) / frames;
            ((f32*)((char*)state + 0xac))[k + 1] = (f32)(u32)bufA[(*(s16**)((char*)p + 0x10))[0] * 16 + 0xf];
            goto animate;
        }
        for (j = 0; j < ((ModgfxVertexGroupCmd*)p)->indexCount; j++)
        {
            bufA[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xf] = target;
            bufB[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xf] = bufA[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xf];
        }
        return;
    }
animate:
{
    char* kb;
    int k4 = k * 4;
    kb = (char*)state + k4;
    *(f32*)(kb + 0xb0) = *(f32*)(kb + 0xb0) + *(f32*)(kb + 0xac) * gModgfxMotionStep;
    if (*(f32*)(kb + 0xb0) < lbl_803DF430)
    {
        *(f32*)(kb + 0xb0) = lbl_803DF430;
    }
    else if (*(f32*)(kb + 0xb0) > 255.0f)
    {
        *(f32*)(kb + 0xb0) = 255.0f;
    }
    {
        for (j = 0; j < ((ModgfxVertexGroupCmd*)p)->indexCount; j++)
        {
            bufB[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xf] = *(f32*)((char*)state + k4 + 0xb0);
            bufA[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xf] = bufB[(*(s16**)((char*)p + 0x10))[j] * 16 + 0xf];
        }
    }
}
}
#pragma opt_common_subs reset

void fn_800A0C78(void* state, void* p, int mode, u8 idx)
{
    extern f32 gModgfxMotionStep;
    int idx2 = idx * 2;
#define base ((char*)state + idx2 * 0xc)
    int j;

    if (mode == 1)
    {
        f32 tx = ((ModgfxVertexGroupCmd*)p)->valueX;
        f32 ty = ((ModgfxVertexGroupCmd*)p)->valueY;
        f32 tz = ((ModgfxVertexGroupCmd*)p)->valueZ;
        if (((ModgfxState*)state)->blendFrameCount != 0)
        {
            *(f32*)(base + 0x3c) = (tx - *(f32*)(base + 0x30)) / (f32)((ModgfxState*)state)->blendFrameCount;
            *(f32*)(base + 0x40) = (ty - *(f32*)(base + 0x34)) / (f32)((ModgfxState*)state)->blendFrameCount;
            *(f32*)(base + 0x44) = (tz - *(f32*)(base + 0x38)) / (f32)((ModgfxState*)state)->blendFrameCount;
        }
        else
        {
            u8* buf2;
            u8* buf = (u8*)((ModgfxState*)state)->baseVertexData;
            f32 cv;
            state = (char*)state + ((ModgfxState*)state)->activeVertexBufferIndex * 4;
            buf2 = *(u8**)((char*)state + 0x78);
            for (j = 0; j < ((ModgfxVertexGroupCmd*)p)->indexCount; j++)
            {
                cv = *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 0);
                *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 0) = cv * tx;
                cv = *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 2);
                *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 2) = cv * ty;
                cv = *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 4);
                *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 4) = cv * tz;
                *(s16*)(buf2 + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 0) =
                    *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 0);
                *(s16*)(buf2 + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 2) =
                    *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 2);
                *(s16*)(buf2 + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 4) =
                    *(s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 4);
            }
            return;
        }
    }
    {
        char* bp = base;
        *(f32*)(bp + 0x30) = *(f32*)(bp + 0x30) + *(f32*)(bp + 0x3c) * gModgfxMotionStep;
        *(f32*)(bp + 0x34) = *(f32*)(bp + 0x34) + *(f32*)(bp + 0x40) * gModgfxMotionStep;
        *(f32*)(bp + 0x38) = *(f32*)(bp + 0x38) + *(f32*)(bp + 0x44) * gModgfxMotionStep;
        {
            u8* buf = (u8*)((ModgfxState*)state)->baseVertexData;
            u8* buf2;
            f32 noChange = 1.0f;
            state = (char*)state + ((ModgfxState*)state)->activeVertexBufferIndex * 4;
            buf2 = *(u8**)((char*)state + 0x78);
            for (j = 0; j < ((ModgfxVertexGroupCmd*)p)->indexCount; j++)
            {
                if (noChange != *(f32*)(bp + 0x30))
                {
                    *(s16*)(buf2 + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 0) =
                        *(f32*)(bp + 0x30) * (f32) * (s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 0);
                }
                if (noChange != *(f32*)(bp + 0x34))
                {
                    *(s16*)(buf2 + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 2) =
                        *(f32*)(bp + 0x34) * (f32) * (s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 2);
                }
                if (noChange != *(f32*)(bp + 0x38))
                {
                    *(s16*)(buf2 + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 4) =
                        *(f32*)(bp + 0x38) * (f32) * (s16*)(buf + ((ModgfxVertexGroupCmd*)p)->indices[j] * 16 + 4);
                }
            }
        }
    }
#undef base
}

#pragma peephole reset
#pragma peephole on
void fn_800A0FD0(ModgfxState* state)
{
    int i;
    ModgfxVertexData* src;
    ModgfxVertexData* dst = state->vertexBuffers[state->activeVertexBufferIndex];
    src = state->baseVertexData;
    for (i = 0; i < state->vertexCount; i++)
    {
        dst->posX = src->posX;
        dst->posY = src->posY;
        dst->posZ = src->posZ;
        dst->colorR = src->colorR;
        dst->colorG = src->colorG;
        dst->colorB = src->colorB;
        dst->alpha = src->alpha;
        dst++;
        src++;
    }
}
#pragma dont_inline on
#pragma peephole reset
#pragma peephole off
void fn_800A1040(s16 sequenceId, int forceAll)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        if (arr[i] == NULL)
            continue;
        if (sequenceId != arr[i]->sequenceId && forceAll == 0)
            continue;
        if (arr[i]->auxAllocation != NULL)
        {
            mm_free(arr[i]->auxAllocation);
        }
        if (arr[i]->instanceObject != NULL)
        {
            Obj_FreeObject(arr[i]->instanceObject);
        }
        arr[i]->inlineData = NULL;
        if (arr[i]->textureIsBorrowed == 0 && arr[i]->textureResource != NULL)
        {
            textureFree((Texture*)(arr[i]->textureResource));
        }
        if (arr[i]->textureIsBorrowed == 0)
        {
            arr[i]->textureResource = NULL;
        }
        mm_free(arr[i]);
        arr[i] = NULL;
    }
}

#pragma dont_inline reset

/* Flag every active effect whose owner object has the 0x800 state bit
 * by setting its frameUpdated flag. */
void dll_0B_func0E(void)
{
    PartfxEffectState* effect;
    GameObject* sourceObject;
    int i;
    PartfxEffectState** effects = (PartfxEffectState**)gPartfxActiveEffects;

    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        effect = effects[i];
        if (effect != NULL)
        {
            sourceObject = effect->sourceObject;
            if (sourceObject != NULL && (sourceObject->objectFlags & DLL0B_OBJFLAG_RENDERED) != 0)
            {
                effect->frameUpdated = 1;
            }
        }
    }
}

void dll_0B_func0D(void* source)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        if (arr[i] != NULL && arr[i]->sourceObject == source)
        {
            arr[i]->releaseRequested = 1;
        }
    }
}


void dll_0B_func0C(void* source, char value)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        if (arr[i] != NULL && arr[i]->sourceObject == source)
        {
            arr[i]->byte13B = value;
        }
    }
}
#pragma peephole reset
#pragma peephole on
#pragma scheduling reset
#pragma scheduling on
void dll_0B_func0B(void)
{
    lbl_803DD282 = lbl_803DD282 + 1;
}
#pragma peephole reset
#pragma peephole off
#pragma scheduling reset
#pragma scheduling off

void dll_0B_func0A(s16* p)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        if (arr[i] != NULL && *p == arr[i]->sequenceId)
        {
            arr[i]->releaseRequested = 1;
        }
    }
    *p = -1;
}

extern void GXLoadPosMtxImm(void* mtx, int id);
extern void Obj_RotateLocalOffsetByYaw(f32* local, f32* out, s8 yawIndex);
extern void gxTevAddTextureFrameBlendStages(void);
extern void fn_80078DFC(void);
extern void fn_80078ED0(void);
extern void textBlendSetupFn_80078a7c(void);
extern void fn_800542F4(void);

int dll_0B_func09(void* a0, int a1, int a2, u8 a3, void* a4)
{
    u8 ar;
    u8 ag;
    u8 ab;
    f32 pos[3];
    f32 rot[3];
    MatrixTransform xf;
    f32 mtxB[16];
    f32 mtxA[12];
    int** p;
    int slot;
    CameraViewSlot* view;
    u8 texCount;
    void* buf1;
    void* buf2;
    u8 aligned;
    void* tex;
    int n131p1;
    int n131;
    int j;
    f32 dirX;
    f32 dirZ;
    f32 dscale;

    n131p1 = 0;
    n131 = 0;
    if (a4 != NULL)
    {
        getAmbientColor(*(u8*)((char*)a4 + 0xf2), &ar, &ag, &ab);
    }
    else
    {
        getAmbientColor(0, &ar, &ag, &ab);
    }
    GXSetCullMode(GX_CULL_NONE);
    if (renderModeSetOrGet(-1) == 1)
    {
        return 1;
    }
    view = Camera_GetCurrentViewSlot();
    p = (int**)gPartfxActiveEffects;
    for (slot = 0; slot < PARTFX_ACTIVE_EFFECT_COUNT; slot++)
    {
        if (p[slot] == NULL)
            continue;
        if (((PartfxEffectState*)p[slot])->sequenceId == -1)
            continue;
        if (a3)
        {
            if (((int)((PartfxEffectState*)p[slot])->flags & 0x2000) == 0)
                continue;
        }
        if (a3)
        {
            if (((PartfxEffectState*)p[slot])->sourceObject != a4)
                continue;
        }
        if (!a3)
        {
            if ((int)((PartfxEffectState*)p[slot])->flags & 0x2000)
                continue;
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x800)
        {
            ((PartfxEffectState*)p[slot])->frameUpdated = 0;
        }
        aligned = 0;
        buf1 = ((PartfxEffectState*)p[slot])->vertexBuffers[((PartfxEffectState*)p[slot])->activeVertexBufferIndex];
        buf2 = ((PartfxEffectState*)p[slot])->colorBuffers[((PartfxEffectState*)p[slot])->activeVertexBufferIndex];
        xf.x = lbl_803DF430;
        xf.y = lbl_803DF430;
        xf.z = lbl_803DF430;
        xf.scale = lbl_803DF434;
        xf.rotZ = 0;
        xf.rotY = 0;
        pos[0] = ((PartfxEffectState*)p[slot])->drawPosX;
        pos[1] = ((PartfxEffectState*)p[slot])->drawPosY;
        pos[2] = ((PartfxEffectState*)p[slot])->drawPosZ;
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x4)
        {
            if (lbl_803DF430 == pos[2] + (pos[0] + pos[1]))
            {
                aligned = 1;
            }
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x4)
        {
            if (!aligned)
            {
                if (((PartfxEffectState*)p[slot])->sourceObject != NULL)
                {
                    xf.rotX = *(s16*)((char*)((PartfxEffectState*)p[slot])->sourceObject);
                    xf.rotY = *(s16*)((char*)((PartfxEffectState*)p[slot])->sourceObject + 2);
                    xf.rotZ = *(s16*)((char*)((PartfxEffectState*)p[slot])->sourceObject + 4);
                    vecRotateZXY(&xf.rotX, &pos[0]);
                }
            }
        }
        rot[0] = lbl_803DF430;
        rot[1] = lbl_803DF430;
        rot[2] = lbl_803DF430;
        if (((int)((PartfxEffectState*)p[slot])->flags & 1) == 0)
        {
            if (((PartfxEffectState*)p[slot])->sourceObject != NULL)
            {
                rot[0] = *(f32*)((char*)((PartfxEffectState*)p[slot])->sourceObject + 0x18);
                rot[1] = *(f32*)((char*)((PartfxEffectState*)p[slot])->sourceObject + 0x1c);
                rot[2] = *(f32*)((char*)((PartfxEffectState*)p[slot])->sourceObject + 0x20);
            }
            else
            {
                rot[0] = ((PartfxEffectState*)p[slot])->sourcePosX;
                rot[1] = ((PartfxEffectState*)p[slot])->sourcePosY;
                rot[2] = ((PartfxEffectState*)p[slot])->sourcePosZ;
                Obj_RotateLocalOffsetByYaw(&((PartfxEffectState*)p[slot])->sourcePosX, &rot[0],
                                           ((PartfxEffectState*)p[slot])->sourceYawIndex);
            }
        }
        if (rot[0] > 65534.0f || rot[0] < -65534.0f)
        {
            rot[0] = -playerMapOffsetX;
        }
        if (rot[1] > 65534.0f || rot[1] < -65534.0f)
        {
            rot[1] = lbl_803DF430;
        }
        if (rot[2] > 65534.0f || rot[2] < -65534.0f)
        {
            rot[2] = -playerMapOffsetZ;
        }
        xf.x = rot[0] + pos[0];
        xf.y = rot[1] + pos[1];
        xf.z = rot[2] + pos[2];
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x400000)
        {
            dscale = 0.5f * ((PartfxEffectState*)p[slot])->renderScale;
            xf.scale = dscale + dscale / (int)randomGetRange(1, 10);
        }
        else
        {
            xf.scale = 0.01f * ((PartfxEffectState*)p[slot])->renderScale;
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x80000)
        {
            xf.rotZ = *(s16*)((char*)((PartfxEffectState*)p[slot])->sourceObject + 4);
            xf.rotY = *(s16*)((char*)((PartfxEffectState*)p[slot])->sourceObject + 2);
            xf.rotX = *(s16*)((char*)((PartfxEffectState*)p[slot])->sourceObject);
        }
        else if (aligned && ((PartfxEffectState*)p[slot])->sourceObject != NULL)
        {
            xf.rotZ = ((PartfxEffectState*)p[slot])->rotOffsetZ +
                        *(s16*)((char*)((PartfxEffectState*)p[slot])->sourceObject + 4);
            xf.rotY = ((PartfxEffectState*)p[slot])->rotOffsetY +
                        *(s16*)((char*)((PartfxEffectState*)p[slot])->sourceObject + 2);
            xf.rotX =
                ((PartfxEffectState*)p[slot])->rotOffsetX + *(s16*)((char*)((PartfxEffectState*)p[slot])->sourceObject);
        }
        else if (aligned)
        {
            xf.rotZ = ((PartfxEffectState*)p[slot])->rotOffsetZ + ((PartfxEffectState*)p[slot])->sourceRotZ;
            xf.rotY = ((PartfxEffectState*)p[slot])->rotOffsetY + ((PartfxEffectState*)p[slot])->sourceRotY;
            xf.rotX = ((PartfxEffectState*)p[slot])->rotOffsetX + ((PartfxEffectState*)p[slot])->sourceRotX;
        }
        else
        {
            xf.rotZ = ((PartfxEffectState*)p[slot])->rotOffsetZ;
            xf.rotY = ((PartfxEffectState*)p[slot])->rotOffsetY;
            xf.rotX = ((PartfxEffectState*)p[slot])->rotOffsetX;
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x1000)
        {
            if (((PartfxEffectState*)p[slot])->sourceObject != NULL)
            {
                dirX = view->worldX - *(f32*)((char*)((PartfxEffectState*)p[slot])->sourceObject + 0x18);
                dirZ = view->worldZ -
                       *(f32*)((char*)((PartfxEffectState*)p[slot])->sourceObject + 0x20);
                dscale = sqrtf(dirX * dirX + dirZ * dirZ);
                if (dscale != lbl_803DF430)
                {
                    dirX = dirX / dscale;
                    dirZ = dirZ / dscale;
                }
                dscale = (u16)getAngle(dirX, dirZ);
                xf.rotX += (s16)dscale;
            }
        }
        xf.x = xf.x - playerMapOffsetX;
        xf.z = xf.z - playerMapOffsetZ;
        setMatrixFromObjectPos(mtxB, &xf);
        mtx44Transpose(mtxB, mtxA);
        PSMTXConcat((f32*)Camera_GetViewMatrix(), mtxA, mtxA);
        GXLoadPosMtxImm(mtxA, GX_PNMTX0);
        tex = ((PartfxEffectState*)p[slot])->textureResource;
        if (tex != NULL)
        {
            texCount = (u8)(*(u16*)((char*)tex + 0x10) >> 8);
        }
        if (tex != NULL && ((PartfxEffectState*)p[slot])->textureFrameTimer != 0)
        {
            ((PartfxEffectState*)p[slot])->textureFrameStep -= 1;
            if (((PartfxEffectState*)p[slot])->textureFrameStep == 0)
            {
                ((PartfxEffectState*)p[slot])->textureFrameStep =
                    0x3c / ((PartfxEffectState*)p[slot])->textureFrameTimer;
                ((PartfxEffectState*)p[slot])->textureFrame += 1;
                if (((PartfxEffectState*)p[slot])->textureFrame >= (u32)texCount)
                {
                    ((PartfxEffectState*)p[slot])->textureFrame = 0;
                }
            }
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x10000000)
        {
            setTextColorContextLegacy(a0, ar, ag, ab, 0xff);
        }
        else if (((PartfxEffectState*)p[slot])->sourceObject != NULL &&
                 ((int)((PartfxEffectState*)p[slot])->flags & 0x4000))
        {
            setTextColorContextLegacy(a0, 0xff, 0xff, 0xff,
                                      *(u8*)((char*)((PartfxEffectState*)p[slot])->sourceObject + 0x37));
        }
        else
        {
            setTextColorContextLegacy(a0, 0xff, 0xff, 0xff, 0xff);
        }
        tex = ((PartfxEffectState*)p[slot])->textureResource;
        if (tex != NULL)
        {
            n131 = ((PartfxEffectState*)p[slot])->textureFrame;
            n131p1 = (n131 + 1) & 0xff;
            if (n131p1 > texCount - 1)
            {
                n131p1 = 0;
            }
        }
        if (((int)((PartfxEffectState*)p[slot])->flags & 0x1000000) &&
            (((PartfxEffectState*)p[slot])->frameUpdated != 0 || ((int)((PartfxEffectState*)p[slot])->flags & 0x400)))
        {
            {
                for (j = 0; j < (u8)n131p1; j++)
                {
                    tex = *(void**)tex;
                }
                _textSetColor(a0, 0xff, 0xff, 0xff,
                              (u8)(0xff - ((PartfxEffectState*)p[slot])->textureFrameStep *
                                              ((PartfxEffectState*)p[slot])->textureFrameFadeStep));
                textureSetupFn_800799c0();
                gxTevAddTextureFrameBlendStages();
                fn_80078DFC();
                textRenderSetupFn_80079804();
                selectTexture((Texture*)tex, 1);
            }
        }
        else if ((int)((PartfxEffectState*)p[slot])->flags & 0x2000000)
        {
            textureSetupFn_800799c0();
            fn_80078ED0();
            textRenderSetupFn_80079804();
        }
        else if ((int)((PartfxEffectState*)p[slot])->flags & 0x4000000)
        {
            textureSetupFn_800799c0();
            geomDrawFn_800796f0();
            gxTexColorFn_80079254();
            textRenderSetupFn_80079804();
        }
        if (((int)((PartfxEffectState*)p[slot])->flags & 0x05000000) &&
            (((PartfxEffectState*)p[slot])->frameUpdated != 0 || ((int)((PartfxEffectState*)p[slot])->flags & 0x400)))
        {
            {
                tex = ((PartfxEffectState*)p[slot])->textureResource;
                for (j = 0; j < (u8)n131; j++)
                {
                    tex = *(void**)tex;
                }
                selectTexture((Texture*)tex, 0);
            }
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x100)
        {
            gxBlendFn_80078b4c();
        }
        else if (((int)((PartfxEffectState*)p[slot])->flags & 0x10) &&
                 ((int)((PartfxEffectState*)p[slot])->flags & 0x80))
        {
            textBlendSetupFn_80078a7c();
        }
        else if ((int)((PartfxEffectState*)p[slot])->flags & 0x80)
        {
            gxBlendFn_80078b4c();
        }
        else if ((int)((PartfxEffectState*)p[slot])->flags & 0x10)
        {
            textBlendSetupFn_80078a7c();
        }
        else
        {
            gxBlendFn_80078b4c();
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x40)
        {
            GXSetCullMode(GX_CULL_FRONT);
        }
        else
        {
            GXSetCullMode(GX_CULL_NONE);
        }
        if (((PartfxEffectState*)p[slot])->frameUpdated != 0 || ((int)((PartfxEffectState*)p[slot])->flags & 0x400))
        {
            int di;
            for (di = 0; di < ((PartfxEffectState*)p[slot])->drawGroupCount; di++)
            {
                if ((int)((PartfxEffectState*)p[slot])->flags & 0x8000000)
                {
                    drawFn_8005cf8c((int)buf1, (const u8*)buf2,
                                    ((PartfxEffectState*)p[slot])->colorVertexCount /
                                        ((PartfxEffectState*)p[slot])->drawGroupCount);
                }
                else
                {
                    drawFn_8005cf8c((int)buf1, (const u8*)buf2,
                                    ((PartfxEffectState*)p[slot])->colorVertexCount);
                }
                buf1 = (char*)buf1 + (((PartfxEffectState*)p[slot])->drawGroupStride << 4);
                if ((int)((PartfxEffectState*)p[slot])->flags & 0x8000000)
                {
                    buf2 = (char*)buf2 + ((((PartfxEffectState*)p[slot])->colorVertexCount /
                                           ((PartfxEffectState*)p[slot])->drawGroupCount)
                                          << 4);
                }
            }
            fn_800542F4();
            ((PartfxEffectState*)p[slot])->activeVertexBufferIndex =
                1 - ((PartfxEffectState*)p[slot])->activeVertexBufferIndex;
        }
    }
    return 0;
}


void dll_0B_func08(void* param)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;

    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        if (arr[i] != NULL && arr[i]->sourceObject == param)
        {
            if ((int)arr[i]->flags & 0x10000)
            {
                fn_800A1040(arr[i]->sequenceId, 0);
            }
            else
            {
                arr[i]->sourcePosX = ((GameObject*)arr[i]->sourceObject)->anim.worldPosX;
                arr[i]->sourcePosY = ((GameObject*)arr[i]->sourceObject)->anim.worldPosY;
                arr[i]->sourcePosZ = ((GameObject*)arr[i]->sourceObject)->anim.worldPosZ;
                arr[i]->sourceScale = ((GameObject*)arr[i]->sourceObject)->anim.rootMotionScale;
                arr[i]->sourceRotZ = ((GameObject*)arr[i]->sourceObject)->anim.rotZ;
                arr[i]->sourceRotY = ((GameObject*)arr[i]->sourceObject)->anim.rotY;
                arr[i]->sourceRotX = ((GameObject*)arr[i]->sourceObject)->anim.rotX;
                if ((int)arr[i]->flags & 0x2)
                {
                    arr[i]->velocityX += ((GameObject*)arr[i]->sourceObject)->anim.velocityX;
                    arr[i]->velocityY += ((GameObject*)arr[i]->sourceObject)->anim.velocityY;
                    arr[i]->velocityZ += ((GameObject*)arr[i]->sourceObject)->anim.velocityZ;
                }
                if (!((int)arr[i]->flags & 0x200000))
                {
                    arr[i]->flags |= 0x200000;
                }
                *(int*)&arr[i]->sourceObject = 0;
            }
        }
    }
}

void dll_0B_func07(void* source)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        if (arr[i] == NULL)
            continue;
        if (arr[i]->sourceObject != source)
            continue;
        if (arr[i]->instanceObject != NULL)
        {
            Obj_FreeObject(arr[i]->instanceObject);
        }
        arr[i]->inlineData = NULL;
        if (arr[i]->textureIsBorrowed == 0 && arr[i]->textureResource != NULL)
        {
            textureFree((Texture*)(arr[i]->textureResource));
        }
        if (arr[i]->textureIsBorrowed == 0)
        {
            arr[i]->textureResource = NULL;
        }
        mm_free(arr[i]);
        arr[i] = NULL;
    }
}


static inline int modgfx_findFreeEffectSlot(void** p, int found, int i)
{
    for (; i < PARTFX_ACTIVE_EFFECT_COUNT && found == 0; p++, i++)
    {
        if (*p == NULL)
            found = 1;
    }
    if (found)
    {
        return i - 1;
    }
    return -1;
}

#pragma peephole reset
#pragma peephole on
void dll_0B_func06(void)
{
    fn_800A1040(0, 1);
}
#pragma peephole reset
#pragma peephole off



typedef void (*ExpFn2)(void*, int);
typedef void (*ExpFn3)(void*, void*, int);
typedef void (*ExpFn4)(void*, void*, int, int);
typedef void (*ExpResFn6)(void*, int, void*, int, int, void*);

#define E9 ((char*)*(int**)((char*)eff + 0x9c))

void dll_0B_func05(void)
{
    int emOff;
    int** pp;
    int* eff;
    int reprocess;
    int active;
    int emIdx;
    int slot;
    int feFlag;
    int cntC;
    int cntA;
    int k;
    void* res;
    s16 ang[3];
    volatile f32 q[4];
    BoneSpawnData tmpl;
    int objCount;
    int objIdx;

    emIdx = 0;
    gExpgfxUpdatingActivePools = 2;
    if (renderModeSetOrGet(-1) == 1)
    {
        return;
    }
    gModgfxMotionStep = timeDelta;
    pp = (int**)gPartfxActiveEffects;
    for (slot = 0; slot < PARTFX_ACTIVE_EFFECT_COUNT; slot++)
    {
        reprocess = 1;
        while (reprocess)
        {
            reprocess = 0;
            eff = pp[slot];
            if (eff == NULL)
                break;
            if (((ModgfxEffectSlot*)eff)->animSlotId == -1)
                break;
            active = 0;
            ((ModgfxEffectSlot*)eff)->unk13E = 0;
            if (((ModgfxEffectSlot*)eff)->frameDuration < 0 || ((ModgfxEffectSlot*)eff)->frameIndex == -1)
            {
                ((ModgfxEffectSlot*)eff)->frameIndex += 1;
                if (((ModgfxEffectSlot*)eff)->frameIndex > 6)
                {
                    fn_800A1040(((ModgfxEffectSlot*)eff)->animSlotId, 0);
                    goto slot_done;
                }
                ((ModgfxEffectSlot*)eff)->frameDuration =
                    ((ModgfxEffectSlot*)eff)->frameTimings[((ModgfxEffectSlot*)eff)->frameIndex];
                active = 1;
                ((ExpFn2)fn_800A0478)(eff, 0);
            }
            else if (((ModgfxEffectSlot*)eff)->pendingFrameIdx != 0)
            {
                ((ModgfxEffectSlot*)eff)->frameIndex = ((ModgfxEffectSlot*)eff)->pendingFrameIdx;
                ((ModgfxEffectSlot*)eff)->pendingFrameIdx = 0;
                if (((ModgfxEffectSlot*)eff)->frameIndex > 6)
                {
                    fn_800A1040(((ModgfxEffectSlot*)eff)->animSlotId, 0);
                    goto slot_done;
                }
                ((ModgfxEffectSlot*)eff)->frameDuration =
                    ((ModgfxEffectSlot*)eff)->frameTimings[((ModgfxEffectSlot*)eff)->frameIndex];
                active = 1;
                ((ExpFn2)fn_800A0478)(eff, 0);
            }
            cntC = 0;
            cntA = 0;
            ((ExpFn3)fn_800A0FD0)(eff, E9 + emIdx * 0x18, active);
            feFlag = 0;
            emIdx = 0;
            emOff = 0;
            for (; emIdx < ((ModgfxEffectSlot*)eff)->emitterCount; emOff += 0x18, emIdx++)
            {
                int flags;
                if (((ModgfxEffectSlot*)eff)->frameIndex != ((ModgfxPendingSpawn*)(E9 + emOff))->sequenceIndex)
                    continue;
                flags = ((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource;
                if ((flags & 0x1000) && ((ModgfxPendingSpawn*)(E9 + emOff))->posX > lbl_803DF430 &&
                    ((ModgfxEffectSlot*)eff)->frameIndex > 0)
                {
                    ((ModgfxEffectSlot*)eff)->frameIndex = ((ModgfxPendingSpawn*)(E9 + emIdx * 0x18))->param14;
                    ((ModgfxPendingSpawn*)(E9 + emIdx * 0x18))->posX =
                        ((ModgfxPendingSpawn*)(E9 + emIdx * 0x18))->posX - lbl_803DF434;
                    ((ModgfxEffectSlot*)eff)->frameDuration = -1;
                    break;
                }
                if (flags & 0x2000)
                {
                    if (((ModgfxEffectSlot*)eff)->unk13A != 0)
                    {
                        ((ModgfxEffectSlot*)eff)->unk13A = 0;
                        ((ModgfxPendingSpawn*)(E9 + emIdx * 0x18))->modelOrResource = 0;
                        ((ModgfxPendingSpawn*)(E9 + emIdx * 0x18))->modelOrResource = 0x20;
                        ((ModgfxEffectSlot*)eff)->frameDuration = -1;
                        reprocess = 1;
                        feFlag = 0;
                        break;
                    }
                    if (((ModgfxEffectSlot*)eff)->frameIndex > 0)
                    {
                        feFlag = 1;
                        ((ModgfxEffectSlot*)eff)->frameIndex = ((ModgfxPendingSpawn*)(E9 + emIdx * 0x18))->param14;
                        ((ModgfxEffectSlot*)eff)->frameDuration = -1;
                        reprocess = 1;
                        break;
                    }
                }
                if (flags & 0x10000000)
                {
                    tmpl.x = ((ModgfxEffectSlot*)eff)->posCurX;
                    tmpl.y = ((ModgfxEffectSlot*)eff)->posCurY;
                    tmpl.z = ((ModgfxEffectSlot*)eff)->posCurZ;
                    q[1] = lbl_803DF430;
                    q[2] = lbl_803DF430;
                    q[3] = lbl_803DF430;
                    q[0] = lbl_803DF434;
                    if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                    {
                        ang[0] = ((ModgfxEffectSlot*)eff)->unkC;
                    }
                    else
                    {
                        ang[0] = *(s16*)(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj);
                    }
                    ang[1] = 0;
                    ang[2] = 0;
                    vecRotateZXY(&ang[0], &tmpl.x);
                    if (*(void**)eff == NULL)
                    {
                        if (Obj_IsLoadingLocked())
                        {
                            int* o;
                            if ((((ModgfxEffectSlot*)eff)->sourceFlags & 1) == 0)
                            {
                                tmpl.x = ((GameObject*)((ModgfxEffectSlot*)eff)->sourceObj)->anim.worldPosX + tmpl.x;
                                tmpl.y = ((GameObject*)((ModgfxEffectSlot*)eff)->sourceObj)->anim.worldPosY + tmpl.y;
                                tmpl.z = ((GameObject*)((ModgfxEffectSlot*)eff)->sourceObj)->anim.worldPosZ + tmpl.z;
                            }
                            else
                            {
                                tmpl.x = ((ModgfxEffectSlot*)eff)->posOffsetX + tmpl.x;
                                tmpl.y = ((ModgfxEffectSlot*)eff)->posOffsetY + tmpl.y;
                                tmpl.z = ((ModgfxEffectSlot*)eff)->posOffsetZ + tmpl.z;
                            }
                            o = (int*)Obj_AllocObjectSetup(0x20, DLL0B_CHILD_OBJ);
                            ((GameObject*)o)->anim.rootMotionScale = tmpl.x;
                            ((GameObject*)o)->anim.localPosX = tmpl.y;
                            *(f32*)&((ObjDef*)o)->jointData = tmpl.z;
                            *(int*)eff = (int)Obj_SetupObject((ObjPlacement*)o, 5, -1, -1, NULL);
                            *(int*)(*(int*)eff + 0xf8) = 1;
                        }
                    }
                    if (*(void**)eff != NULL)
                    {
                        if ((((ModgfxEffectSlot*)eff)->sourceFlags & 1) == 0)
                        {
                            tmpl.x = ((GameObject*)((ModgfxEffectSlot*)eff)->sourceObj)->anim.worldPosX + tmpl.x;
                            tmpl.y = ((GameObject*)((ModgfxEffectSlot*)eff)->sourceObj)->anim.worldPosY + tmpl.y;
                            tmpl.z = ((GameObject*)((ModgfxEffectSlot*)eff)->sourceObj)->anim.worldPosZ + tmpl.z;
                        }
                        else
                        {
                            tmpl.x = ((ModgfxEffectSlot*)eff)->posOffsetX + tmpl.x;
                            tmpl.y = ((ModgfxEffectSlot*)eff)->posOffsetY + tmpl.y;
                            tmpl.z = ((ModgfxEffectSlot*)eff)->posOffsetZ + tmpl.z;
                        }
                        *(f32*)(*(int*)eff + 0x18) = tmpl.x;
                        *(f32*)(*(int*)eff + 0x1c) = tmpl.y;
                        *(f32*)(*(int*)eff + 0x20) = tmpl.z;
                    }
                    if (*(void**)eff != NULL)
                    {
                        int* o = *(int**)eff;
                        int* list = *(int**)((char*)*(int**)&((GameObject*)o)->anim.hitReactState + 0x50);
                        if (list != NULL)
                        {
                            if (*(s16*)((char*)list + 0x44) == (int)((ModgfxPendingSpawn*)(E9 + emOff))->posX)
                            {
                                Obj_FreeObject((GameObject*)o);
                                *(int*)eff = 0;
                                ((ModgfxPendingSpawn*)(E9 + emIdx * 0x18))->modelOrResource ^= 0x10000000;
                                if (((ModgfxPendingSpawn*)(E9 + emIdx * 0x18))->posZ >= lbl_803DF430 &&
                                    *(int**)&((ModgfxEffectSlot*)eff)->sourceObj != NULL)
                                {
                                    (*gPartfxInterface)
                                        ->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                      (int)((ModgfxPendingSpawn*)(E9 + emIdx * 0x18))->posZ, &tmpl,
                                                      0x200001, -1, 0);
                                }
                                ((ModgfxEffectSlot*)eff)->pendingFrameIdx =
                                    ((ModgfxPendingSpawn*)(E9 + emIdx * 0x18))->posY;
                                break;
                            }
                        }
                    }
                }
                ObjList_GetObjects(&objIdx, &objCount);
                if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x2)
                {
                    fn_800A0C78(eff, E9 + emOff, active, cntC);
                    cntC++;
                }
                if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x4)
                {
                    fn_800A0AB4(eff, E9 + emOff, active, cntA);
                    cntA++;
                }
                if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x8)
                {
                    ((ExpFn4)fn_800A0524)(eff, E9 + emOff, active, 0);
                }
                if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x100)
                {
                    char* em = E9 + emOff;
                    ((ModgfxEffectSlot*)eff)->rotOffsetZ += (s16)(*(f32*)(em + 0x4) * gModgfxMotionStep);
                    ((ModgfxEffectSlot*)eff)->rotOffsetY += (s16)(*(f32*)(em + 0x8) * gModgfxMotionStep);
                    ((ModgfxEffectSlot*)eff)->rotOffsetX += (s16)(*(f32*)(em + 0xc) * gModgfxMotionStep);
                }
                if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x80)
                {
                    ((ExpFn4)modgfx_stepS16VectorLerp)(eff, E9 + emOff, active, 0);
                }
                if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x8000000)
                {
                    ((ModgfxPendingSpawn*)(E9 + emOff))->posZ = randomGetRange(0, 0xffff);
                    ((ExpFn4)modgfx_stepS16VectorLerp)(eff, E9 + emOff, active, 0);
                }
                if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x4000)
                {
                    ((ExpFn4)fn_800A02DC)(eff, E9 + emOff, active, 0);
                }
                if ((((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x10000) && active != 0)
                {
                    if (((ModgfxPendingSpawn*)(E9 + emOff))->param14 == -1)
                    {
                        Sfx_StopObjectChannelPtrLegacy(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj, 0x40);
                    }
                    else
                    {
                        Sfx_PlayFromObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                           (u16) * (s16*)(E9 + emOff + 0x14));
                    }
                }
                if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x100000)
                {
                    if (active == 1)
                    {
                        if (((ModgfxEffectSlot*)eff)->frameDuration != 0)
                        {
                            ((ModgfxEffectSlot*)eff)->alphaDelta =
                                (((ModgfxPendingSpawn*)(E9 + emOff))->posX -
                                 (f32)(u32)(*(GameObject**)&((ModgfxEffectSlot*)eff)->sourceObj)->anim.alpha) /
                                (f32)((ModgfxEffectSlot*)eff)->frameDuration;
                            ((ModgfxEffectSlot*)eff)->alphaCurrent =
                                (f32)(u32)(*(GameObject**)&((ModgfxEffectSlot*)eff)->sourceObj)->anim.alpha;
                        }
                        else
                        {
                            ((ModgfxEffectSlot*)eff)->alphaDelta =
                                ((ModgfxPendingSpawn*)(E9 + emOff))->posX -
                                (f32)(u32)(*(GameObject**)&((ModgfxEffectSlot*)eff)->sourceObj)->anim.alpha;
                            ((ModgfxEffectSlot*)eff)->alphaCurrent = lbl_803DF430;
                        }
                    }
                    ((ModgfxEffectSlot*)eff)->alphaCurrent =
                        ((ModgfxEffectSlot*)eff)->alphaCurrent + ((ModgfxEffectSlot*)eff)->alphaDelta;
                    if (((ModgfxEffectSlot*)eff)->alphaCurrent > 255.0f)
                    {
                        ((ModgfxEffectSlot*)eff)->alphaCurrent = 255.0f;
                    }
                    else if (((ModgfxEffectSlot*)eff)->alphaCurrent < lbl_803DF430)
                    {
                        ((ModgfxEffectSlot*)eff)->alphaCurrent = lbl_803DF430;
                    }
                    (*(GameObject**)&((ModgfxEffectSlot*)eff)->sourceObj)->anim.alpha =
                        ((ModgfxEffectSlot*)eff)->alphaCurrent;
                }
                if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x400000)
                {
                    ((ExpFn4)fn_800A081C)(eff, E9 + emOff, active, 0);
                }
                if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x80000000)
                {
                    char* em = E9 + emOff;
                    ((ModgfxEffectSlot*)eff)->motionOffsetX =
                        *(f32*)(em + 0x4) * gModgfxMotionStep + ((ModgfxEffectSlot*)eff)->motionOffsetX;
                    ((ModgfxEffectSlot*)eff)->motionOffsetY =
                        *(f32*)(em + 0x8) * gModgfxMotionStep + ((ModgfxEffectSlot*)eff)->motionOffsetY;
                    ((ModgfxEffectSlot*)eff)->motionOffsetZ =
                        *(f32*)(em + 0xc) * gModgfxMotionStep + ((ModgfxEffectSlot*)eff)->motionOffsetZ;
                }
                if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x800000)
                {
                    if ((((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x1000000) &&
                        lbl_803DF430 == ((ModgfxPendingSpawn*)(E9 + emOff))->posY)
                    {
                        for (k = 0; k < (int)((ModgfxPendingSpawn*)(E9 + emOff))->posX; k++)
                        {
                            if (randomGetRange(0, (int)((ModgfxPendingSpawn*)(E9 + emOff))->posZ) == 0)
                            {
                                if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                                {
                                    (*gPartfxInterface)
                                        ->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                      ((ModgfxPendingSpawn*)(E9 + emOff))->param14, NULL, 0x10001, -1,
                                                      NULL);
                                }
                                else
                                {
                                    (*gPartfxInterface)
                                        ->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                      ((ModgfxPendingSpawn*)(E9 + emOff))->param14, NULL, 0x10001, -1,
                                                      NULL);
                                }
                            }
                        }
                    }
                    else if (lbl_803DF430 == ((ModgfxPendingSpawn*)(E9 + emOff))->posY)
                    {
                        for (k = 0; k < (int)((ModgfxPendingSpawn*)(E9 + emOff))->posX; k++)
                        {
                            if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                            {
                                (*gPartfxInterface)
                                    ->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                  ((ModgfxPendingSpawn*)(E9 + emOff))->param14, eff + 3, 0x10002, -1,
                                                  NULL);
                            }
                            else
                            {
                                (*gPartfxInterface)
                                    ->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                  ((ModgfxPendingSpawn*)(E9 + emOff))->param14, NULL, 0x10002, -1,
                                                  NULL);
                            }
                        }
                    }
                    else if (lbl_803DF434 == ((ModgfxPendingSpawn*)(E9 + emOff))->posY)
                    {
                        if ((((ModgfxEffectSlot*)eff)->sourceFlags & 1) == 0)
                        {
                            tmpl.x = ((GameObject*)((ModgfxEffectSlot*)eff)->sourceObj)->anim.worldPosX +
                                     ((ModgfxEffectSlot*)eff)->posCurX;
                            tmpl.y = ((GameObject*)((ModgfxEffectSlot*)eff)->sourceObj)->anim.worldPosY +
                                     ((ModgfxEffectSlot*)eff)->posCurY;
                            tmpl.z = ((GameObject*)((ModgfxEffectSlot*)eff)->sourceObj)->anim.worldPosZ +
                                     ((ModgfxEffectSlot*)eff)->posCurZ;
                            if (*(int**)&((ModgfxEffectSlot*)eff)->sourceObj != NULL)
                            {
                                (*gPartfxInterface)
                                    ->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                  ((ModgfxPendingSpawn*)(E9 + emOff))->param14, &tmpl, 0x10001, -1,
                                                  NULL);
                            }
                        }
                        else
                        {
                            tmpl.x = ((ModgfxEffectSlot*)eff)->posCurX;
                            tmpl.y = ((ModgfxEffectSlot*)eff)->posCurY;
                            tmpl.z = ((ModgfxEffectSlot*)eff)->posCurZ;
                            if (*(int**)&((ModgfxEffectSlot*)eff)->sourceObj != NULL)
                            {
                                (*gPartfxInterface)
                                    ->spawnObject(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj,
                                                  ((ModgfxPendingSpawn*)(E9 + emOff))->param14, &tmpl, 0x10001, -1,
                                                  NULL);
                            }
                        }
                    }
                }
                if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x4000000)
                {
                    res = Resource_Acquire((u16)(((ModgfxPendingSpawn*)(E9 + emOff))->param14 + 0x58), 1);
                    if (((ModgfxPendingSpawn*)(E9 + emOff))->modelOrResource & 0x1000000)
                    {
                        for (k = 0; k < (int)*(f32*)(E9 + (emOff + 0x4)); k++)
                        {
                            if (randomGetRange(0, 5) == 0)
                            {
                                if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                                {
                                    (*(ExpResFn6*)(*(int*)res + 4))(NULL, 0, eff + 3, 1, -1, NULL);
                                }
                                else
                                {
                                    (*(ExpResFn6*)(*(int*)res + 4))(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj, 0,
                                                                    NULL, 1, -1, NULL);
                                }
                            }
                        }
                    }
                    else
                    {
                        for (k = 0; k < (int)*(f32*)(E9 + (emOff + 0x4)); k++)
                        {
                            if (((ModgfxEffectSlot*)eff)->sourceFlags & 1)
                            {
                                (*(ExpResFn6*)(*(int*)res + 4))(NULL, 0, eff + 3, 1, -1, NULL);
                            }
                            else
                            {
                                (*(ExpResFn6*)(*(int*)res + 4))(*(int**)&((ModgfxEffectSlot*)eff)->sourceObj, 0, NULL,
                                                                1, -1, NULL);
                            }
                        }
                    }
                    Resource_Release(res);
                }
            }
            if (feFlag == 0)
            {
                ((ModgfxEffectSlot*)eff)->frameDuration = ((ModgfxEffectSlot*)eff)->frameDuration - framesThisStep;
            }
        }
    slot_done:
        gExpgfxUpdatingActivePools = 0;
    }
}

#pragma opt_propagation off
s16 dll_0B_func04(void* base, int z, int c, void* b, int e, void* d, int f, void* g)
{
    int base0;
    int total = 0;
    ModgfxSpawnContext* st = base;
    int found;
    int i;
    int spawnCount;
    int divThresh;
    int slot;
    f32 fz434;
    f32 fz430;

    i = 0;
    found = i;
    slot = modgfx_findFreeEffectSlot(gPartfxActiveEffects, found, i);
    if (slot == -1)
    {
        return 0;
    }

    {
        int off;
        off = 0;
        spawnCount = st->pendingSpawnCount;
        for (i = 0; i < spawnCount; i++, off += 0x18)
        {
            ModgfxPendingSpawn* item = (ModgfxPendingSpawn*)((u8*)st->pendingSpawns + off);
            if ((item->modelOrResource & 0xf7fff180) == 0 && item->param14 != 0)
            {
                total += item->param14;
            }
        }
    }

    base0 = 0;
    if ((st->flags & 0x800) == 0)
    {
        base0 = (int)(long)((c * 3) << 4) + ((e * 3) << 4);
    }

    ((PartfxEffectState**)gPartfxActiveEffects)[slot] =
        (PartfxEffectState*)mmAlloc(base0 + spawnCount * 0x18 + total * 2 + 0x240, 0x15, 0);
    if (((PartfxEffectState**)gPartfxActiveEffects)[slot] == NULL)
    {
        fn_800A1040(0, 0);
        return -1;
    }

    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->inlineData =
        (u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot] + sizeof(PartfxEffectState);
    {
        u8* bufp = ((PartfxEffectState**)gPartfxActiveEffects)[slot]->inlineData;
        if ((st->flags & 0x800) == 0)
        {
            ((PartfxEffectState**)gPartfxActiveEffects)[slot]->colorBuffers[0] = bufp;
            bufp += e * 16;
            ((PartfxEffectState**)gPartfxActiveEffects)[slot]->colorBuffers[1] = bufp;
            bufp += e * 16;
            ((PartfxEffectState**)gPartfxActiveEffects)[slot]->colorBuffers[2] = bufp;
            bufp += e * 16;
            ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vertexBuffers[0] = bufp;
            bufp += c * 16;
            ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vertexBuffers[1] = bufp;
            bufp += c * 16;
            ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vertexBuffers[2] = bufp;
            bufp += c * 16;
        }
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->baseVertexBuffer = bufp;
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->baseColorBuffer = bufp + 0x80;
    }

    if (st->drawGroupCount != 0)
    {
        divThresh = e / st->drawGroupCount;
    }
    else
    {
        divThresh = e;
    }
    if ((st->flags & 0x800) == 0)
    {
        int k;
        int off;
        for (off = k = 0; k < 3; off += 4, k++)
        {
            u8* q = (u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot];
            int idx = off + 0x84;
            u8* dstc = *(u8**)(q + idx);
            int bias = 0;
            int j;
            s16* sd = d;
            for (j = 0; j < e; j++)
            {
                if ((st->flags & 0x8000000) && j == divThresh)
                {
                    bias = st->drawGroupStride;
                }
                dstc[1] = sd[0] - bias;
                dstc[2] = sd[1] - bias;
                dstc[3] = sd[2] - bias;
                sd += 3;
                dstc += 0x10;
            }
        }
    }

    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureResource = NULL;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureIsBorrowed = 0;
    if (g != NULL)
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureResource = g;
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureIsBorrowed = 1;
    }
    else if (f != 0)
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureResource = textureLoadAsset(f);
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureIsBorrowed = 0;
    }

    if ((st->flags & 0x800) == 0)
    {
        int k;
        int off;
        for (off = k = 0; k < 3; off += 4, k++)
        {
            u8* q = (u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot];
            int idx = off + 0x78;
            u8* dstv = *(u8**)(q + idx);
            int j;
            s16* sb = b;
            for (j = 0; j < c; j++)
            {
                *(s16*)(dstv + 0) = sb[0];
                *(s16*)(dstv + 2) = sb[1];
                *(s16*)(dstv + 4) = sb[2];
                if (((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureResource != NULL)
                {
                    *(s16*)(dstv + 8) =
                        128.0f *
                        ((f32)sb[3] / (f32) *
                         (u16*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureResource + 0xa));
                    *(s16*)(dstv + 0xa) =
                        128.0f *
                        ((f32)sb[4] / (f32) *
                         (u16*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureResource + 0xc));
                }
                dstv[0xc] = 0xff;
                dstv[0xd] = 0xff;
                dstv[0xe] = 0xff;
                dstv[0xf] = 0xff;
                dstv += 0x10;
                sb += 5;
            }
        }
    }

    *(u8*)&((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCount = st->pendingSpawnCount;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->word114 = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->word118 = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->word11C = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->auxAllocation = NULL;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->releaseRequested = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->byte13D = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageTimer = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->nextStage = -1;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->requestedStage = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[0] = st->sequenceParams[0];
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[1] = st->sequenceParams[1];
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[2] = st->sequenceParams[2];
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[3] = st->sequenceParams[3];
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[4] = st->sequenceParams[4];
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[5] = st->sequenceParams[5];
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageDurations[6] = st->sequenceParams[6];
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands =
        (u8*)(base0 + (int)((PartfxEffectState**)gPartfxActiveEffects)[slot]->inlineData) + 0x100;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->auxSequenceBuffer = NULL;
    if (total != 0)
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->auxSequenceBuffer =
            (u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands +
            st->pendingSpawnCount * 0x18;
    }

    {
        u8* dst = ((PartfxEffectState**)gPartfxActiveEffects)[slot]->auxSequenceBuffer;
        int m;
        int off;
        for (m = 0, off = 0; m < ((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCount; m++, off += 0x18)
        {
            ((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off))
                ->sequenceIndex = ((ModgfxPendingSpawn*)((u8*)st->pendingSpawns + off))->sequenceIndex;
            ((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off))
                ->param14 = ((ModgfxPendingSpawn*)((u8*)st->pendingSpawns + off))->param14;
            ((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off))
                ->param10 = 0;
            ((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off))
                ->modelOrResource = ((ModgfxPendingSpawn*)((u8*)st->pendingSpawns + off))->modelOrResource;
            if ((((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off))
                     ->modelOrResource &
                 0xf7fff180) == 0 &&
                ((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off))
                        ->param14 != 0)
            {
                int k;
                ((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off))
                    ->param10 = 0;
                *(u8**)&((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands +
                                               off))
                     ->param10 = dst;
                dst += ((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands +
                                              off))
                           ->param14 *
                       2;
                for (k = 0;
                     k <
                     ((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands +
                                            off))
                         ->param14;
                     k++)
                {
                    *(s16*)(*(u8**)&((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]
                                                               ->emitterCommands +
                                                           off))
                                 ->param10 +
                            k * 2) =
                        *(s16*)(*(u8**)&((ModgfxPendingSpawn*)((u8*)st->pendingSpawns + off))->param10 + k * 2);
                }
            }
            ((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off))
                ->posX = ((ModgfxPendingSpawn*)((u8*)st->pendingSpawns + off))->posX;
            ((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off))
                ->posY = ((ModgfxPendingSpawn*)((u8*)st->pendingSpawns + off))->posY;
            ((ModgfxPendingSpawn*)((u8*)((PartfxEffectState**)gPartfxActiveEffects)[slot]->emitterCommands + off))
                ->posZ = ((ModgfxPendingSpawn*)((u8*)st->pendingSpawns + off))->posZ;
        }
    }

    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->currentStage = -1;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->stageFrameCountdown =
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]
            ->stageDurations[((PartfxEffectState**)gPartfxActiveEffects)[slot]->currentStage];
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->flags = st->flags;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->drawPosX = st->posX;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->drawPosY = st->posY;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->drawPosZ = st->posZ;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->renderScale = st->scale;
    if ((int)((PartfxEffectState**)gPartfxActiveEffects)[slot]->flags & 1)
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sourcePosX = st->posX;
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sourcePosY = st->posY;
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sourcePosZ = st->posZ;
    }
    fz434 = lbl_803DF434;
    fz430 = lbl_803DF430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->posStepX = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->posStepY = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->posStepZ = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[0].cur[0] = fz434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[0].cur[1] = fz434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[0].cur[2] = fz434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[0].step[1] = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[0].step[2] = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[0].step[0] = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[1].cur[2] = fz434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[1].cur[0] = fz434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[1].cur[1] = fz434;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[1].step[2] = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[1].step[0] = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->scaleChannels[1].step[1] = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->rotOffsetZ = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->rotOffsetY = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->rotOffsetX = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vec120 = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vec122 = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vec124 = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->alphaChannels[0].step = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->alphaChannels[0].cur = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->alphaChannels[1].step = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->alphaChannels[1].cur = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->blendColorR = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->blendColorG = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->blendColorB = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->blendColorStepR = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->blendColorStepG = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->blendColorStepB = fz430;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->velocityX = st->vecX;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->velocityY = st->vecY;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->velocityZ = st->vecZ;
    gPartfxSequenceIdCounter += 1;
    if (gPartfxSequenceIdCounter > 0x4e20)
    {
        gPartfxSequenceIdCounter = 0;
    }
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sequenceId = gPartfxSequenceIdCounter;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->byte126 = lbl_803DD282;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->vertexCount = c;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->colorVertexCount = e;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sourceObject = st->attachedSource;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->instanceObject = NULL;
    *(u8*)&((PartfxEffectState**)gPartfxActiveEffects)[slot]->sourceYawIndex = st->sourceYawIndex;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->drawGroupCount = st->drawGroupCount;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->drawGroupStride = st->drawGroupStride;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->initialStateByte = st->initialStateByte;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->soundHandle = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->activeVertexBufferIndex = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->byte13B = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->frameUpdated = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameTimer = st->textureFrameTimer;
    if (((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameTimer != 0)
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameStep =
            0x3c / ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameTimer;
    }
    else
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameStep = 0;
    }
    if (((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameStep != 0)
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameFadeStep =
            0xff / ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameStep;
    }
    else
    {
        ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrameFadeStep = 0;
    }
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->textureFrame = 0;
    ((PartfxEffectState**)gPartfxActiveEffects)[slot]->initialDelayFrames = st->sourceModeCopy;
    return ((PartfxEffectState**)gPartfxActiveEffects)[slot]->sequenceId;
}
#pragma opt_propagation reset


void dll_0B_onMapSetup(void)
{
    int i;

    fn_800A1040(0, 1);
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        gPartfxActiveEffects[i] = NULL;
    }
}
#pragma peephole reset
#pragma peephole on

void dll_0B_release(void)
{
    fn_800A1040(0, 1);
}
#pragma peephole reset
#pragma peephole off
void dll_0B_initialise(void)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        arr[i] = NULL;
    }
}
