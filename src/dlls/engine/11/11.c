#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "dolphin/mtx.h"
#include "main/frame_timing.h"
#include "main/expgfx_internal.h"
#include "main/lightmap_api.h"
#include "main/lightmap_text_color_api.h"
#include "string.h"
#include "track/intersect_render_setup_api.h"
#include "track/intersect_geom_api.h"
#include "main/shader_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "game/objects/object.h"
#include "game/objects/object_interface.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
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
#include "main/sky.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXTransform.h"
#include "track/intersect_api.h"

typedef union Dll0BDescriptorTable
{
    u32 words[30];
    u64 align8;
} Dll0BDescriptorTable;

void modgfx_scrollTexCoords(PartfxEffectState* state, f32* in);
void modgfx_captureFrameBaseVertices(PartfxEffectState* state);
void modgfx_stepVertexColor(void* state, void* p, int reinit);
void modgfx_stepPosition(PartfxEffectState* state, ModgfxVertexGroupCmd* cmd, int reinit);
void modgfx_stepS16VectorLerp(PartfxEffectState* state, f32* params, int reinit);
void modgfx_stepVertexAlpha(PartfxEffectState* state, ModgfxVertexGroupCmd* command, int reinit, u8 channelIndex);
void modgfx_stepVertexScale(PartfxEffectState* state, ModgfxVertexGroupCmd* command, int reinit, u8 channelIndex);
void modgfx_restoreBaseVertices(PartfxEffectState* state);

ModgfxPendingSpawn* gModgfxPendingSpawnStartCursor;
ModgfxPendingSpawn* gModgfxPendingSpawnWriteCursor;
s16 gModgfxSequenceParamIndex;
s16 gModgfxLastSpawnHandle;
f32 gModgfxMotionStep;
u8 lbl_803DD282;
s16 gPartfxSequenceIdCounter;

#define DLL0B_OBJFLAG_RENDERED 0x800

/* Object spawned to back a modgfx effect slot; retail OBJECTS.bin name
   "InvHit" (DLL 0xF1). */
#define DLL0B_CHILD_OBJ_INVHIT 0x66

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
STATIC_ASSERT(offsetof(PartfxEffectState, alphaValues) == 0xAC);
STATIC_ASSERT(offsetof(PartfxEffectState, blendColorR) == 0xBC);
STATIC_ASSERT(offsetof(PartfxEffectState, renderScale) == 0xD4);
STATIC_ASSERT(offsetof(PartfxEffectState, vertexCount) == 0xEA);
STATIC_ASSERT(offsetof(PartfxEffectState, colorVertexCount) == 0xEC);
STATIC_ASSERT(offsetof(PartfxEffectState, stageDurations) == 0xEE);
STATIC_ASSERT(offsetof(PartfxEffectState, rotStepZ) == 0x100);
STATIC_ASSERT(offsetof(PartfxEffectState, rotOffsetZ) == 0x106);
STATIC_ASSERT(offsetof(PartfxEffectState, sequenceId) == 0x10C);
STATIC_ASSERT(offsetof(PartfxEffectState, inlineData) == 0x12C);
STATIC_ASSERT(offsetof(PartfxEffectState, activeVertexBufferIndex) == 0x130);
STATIC_ASSERT(offsetof(PartfxEffectState, emitterCount) == 0x139);
STATIC_ASSERT(offsetof(PartfxEffectState, textureIsBorrowed) == 0x13F);

ModgfxSpawnContext gModgfxSpawnContext;
ModgfxPendingSpawn gModgfxPendingSpawnQueue[0x20];
void partfx_freeEffectsBySequence(s16 a, int b);
#define MODGFX_ZERO 0.0f
#define MODGFX_ONE  1.0f

s16 dll_0B_spawnEffect(ModgfxSpawnContext* context, int unused, int vertexCount, s16* vertexData, int colorCount,
                       s16* colorData, int textureAssetId, void* textureResource);

s16 dll_0B_getLastSpawnHandle(void)
{
    return gModgfxLastSpawnHandle;
}

void dll_0B_addSequenceFlags(u32 flags)
{
    gModgfxSpawnContext.flags |= flags;
}

void dll_0B_spawnSequence(void* a, void* b, void* c, void* d, void* e, int f, void* g)
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
            gModgfxSpawnContext.posX += ((ObjAnimComponent*)gModgfxSpawnContext.attachedSource)->worldPosX;
            gModgfxSpawnContext.posY += ((ObjAnimComponent*)gModgfxSpawnContext.attachedSource)->worldPosY;
            gModgfxSpawnContext.posZ += ((ObjAnimComponent*)gModgfxSpawnContext.attachedSource)->worldPosZ;
        }
        else
        {
            gModgfxSpawnContext.posX += ((ObjAnimComponent*)a)->localPosX;
            gModgfxSpawnContext.posY += ((ObjAnimComponent*)a)->localPosY;
            gModgfxSpawnContext.posZ += ((ObjAnimComponent*)a)->localPosZ;
        }
    }
    gModgfxLastSpawnHandle = dll_0B_spawnEffect(&gModgfxSpawnContext, 0, (int)c, b, (int)e, d, f, g);
}

void dll_0B_setSequenceParams(void* params)
{
    memcpy(gModgfxSpawnContext.sequenceParams, params, 0xe);
}

void dll_0B_setSequenceParamValue(s16 value)
{
    gModgfxSpawnContext.sequenceParams[gModgfxSequenceParamIndex] = value;
}

void dll_0B_setSequenceParamIndex(s16 x)
{
    gModgfxSequenceParamIndex = x;
}

void dll_0B_nextSequenceParam(void)
{
    gModgfxSequenceParamIndex++;
}

void dll_0B_addSequenceSpawn(int modelOrResource, float posX, float posY, float posZ, s16 param14, int param10)
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

void dll_0B_resetSequenceSpawns(void)
{
    ModgfxPendingSpawn* cursor = gModgfxPendingSpawnQueue;
    gModgfxPendingSpawnStartCursor = cursor;
    gModgfxPendingSpawnWriteCursor = cursor;
    gModgfxSequenceParamIndex = 0;
}

void dll_0B_beginSequence(void* source, u8 mode, u8 flagByte, int word40, int word3C)
{
    f32 fz;
    f32 fz2;
    memset(&gModgfxSpawnContext, 0, sizeof(gModgfxSpawnContext));
    gModgfxSpawnContext.modeByte = mode;
    gModgfxSpawnContext.attachedSource = source;
    gModgfxSpawnContext.sourceModeCopy = mode;
    fz = MODGFX_ZERO;
    gModgfxSpawnContext.posX = fz;
    gModgfxSpawnContext.posY = fz;
    gModgfxSpawnContext.posZ = fz;
    gModgfxSpawnContext.vecX = fz;
    gModgfxSpawnContext.vecY = fz;
    gModgfxSpawnContext.vecZ = fz;
    fz2 = MODGFX_ONE;
    gModgfxSpawnContext.scale = fz2;
    gModgfxSpawnContext.drawGroupCount = word40;
    gModgfxSpawnContext.drawGroupStride = word3C;
    gModgfxSpawnContext.initialStateByte = flagByte;
    gModgfxSpawnContext.byte5A = 0;
    gModgfxSpawnContext.textureFrameTimer = 0;
}


/* Per-bone particle vertex update + draw. */

void modgfx_scrollTexCoords(PartfxEffectState* state, f32* in)
{
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

void modgfx_captureFrameBaseVertices(PartfxEffectState* state)
{
    int i;
    ModgfxVertexData* dst;
    ModgfxVertexData* src;
    f32 one;
    f32 zero;
    src = state->vertexBuffers[1 - state->activeVertexBufferIndex];
    dst = state->vertexBuffers[2];
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
    one = MODGFX_ONE;
    state->scaleVectors[0].x = one;
    state->scaleVectors[0].y = one;
    state->scaleVectors[0].z = one;
    zero = MODGFX_ZERO;
    state->scaleVectors[1].x = zero;
    state->scaleVectors[1].y = zero;
    state->scaleVectors[1].z = zero;
    state->scaleVectors[2].x = one;
    state->scaleVectors[2].y = one;
    state->scaleVectors[2].z = one;
    state->scaleVectors[3].x = zero;
    state->scaleVectors[3].y = zero;
    state->scaleVectors[3].z = zero;
}

void modgfx_stepVertexColor(void* state, void* p, int reinit)
{
    u8* buf = ((u8**)((char*)state + 0x78))[((PartfxEffectState*)state)->activeVertexBufferIndex];
    int j;

    if (reinit == 1)
    {
        f32 tr = ((ModgfxVertexGroupCmd*)p)->valueX;
        f32 tg = ((ModgfxVertexGroupCmd*)p)->valueY;
        f32 tb = ((ModgfxVertexGroupCmd*)p)->valueZ;
        if (((PartfxEffectState*)state)->stageFrameCountdown != 0)
        {
            ((PartfxEffectState*)state)->blendColorR = (f32)(u32)buf[(((ModgfxVertexGroupCmd*)p)->indices)[0] * 16 + 0xc];
            ((PartfxEffectState*)state)->blendColorG = (f32)(u32)buf[(((ModgfxVertexGroupCmd*)p)->indices)[0] * 16 + 0xd];
            ((PartfxEffectState*)state)->blendColorB = (f32)(u32)buf[(((ModgfxVertexGroupCmd*)p)->indices)[0] * 16 + 0xe];
            ((PartfxEffectState*)state)->blendColorStepR =
                (tr - (f32)(u32)buf[(((ModgfxVertexGroupCmd*)p)->indices)[0] * 16 + 0xc]) / (f32) ((PartfxEffectState*)state)->stageFrameCountdown;
            ((PartfxEffectState*)state)->blendColorStepG =
                (tg - (f32)(u32)buf[(((ModgfxVertexGroupCmd*)p)->indices)[0] * 16 + 0xd]) / (f32) ((PartfxEffectState*)state)->stageFrameCountdown;
            ((PartfxEffectState*)state)->blendColorStepB =
                (tb - (f32)(u32)buf[(((ModgfxVertexGroupCmd*)p)->indices)[0] * 16 + 0xe]) / (f32) ((PartfxEffectState*)state)->stageFrameCountdown;
        }
        else
        {
            ((PartfxEffectState*)state)->blendColorR = tr;
            ((PartfxEffectState*)state)->blendColorG = tg;
            ((PartfxEffectState*)state)->blendColorB = tb;
            {
                f32 z = MODGFX_ZERO;
                ((PartfxEffectState*)state)->blendColorStepR = z;
                ((PartfxEffectState*)state)->blendColorStepG = z;
                ((PartfxEffectState*)state)->blendColorStepB = z;
            }
        }
    }
    ((PartfxEffectState*)state)->blendColorR += ((PartfxEffectState*)state)->blendColorStepR;
    ((PartfxEffectState*)state)->blendColorG += ((PartfxEffectState*)state)->blendColorStepG;
    ((PartfxEffectState*)state)->blendColorB += ((PartfxEffectState*)state)->blendColorStepB;
    if (((PartfxEffectState*)state)->blendColorR < MODGFX_ZERO)
    {
        ((PartfxEffectState*)state)->blendColorR = MODGFX_ZERO;
    }
    else if (((PartfxEffectState*)state)->blendColorR > 255.0f)
    {
        ((PartfxEffectState*)state)->blendColorR = 255.0f;
    }
    if (((PartfxEffectState*)state)->blendColorG < MODGFX_ZERO)
    {
        ((PartfxEffectState*)state)->blendColorG = MODGFX_ZERO;
    }
    else if (((PartfxEffectState*)state)->blendColorG > 255.0f)
    {
        ((PartfxEffectState*)state)->blendColorG = 255.0f;
    }
    if (((PartfxEffectState*)state)->blendColorB < MODGFX_ZERO)
    {
        ((PartfxEffectState*)state)->blendColorB = MODGFX_ZERO;
    }
    else if (((PartfxEffectState*)state)->blendColorB > 255.0f)
    {
        ((PartfxEffectState*)state)->blendColorB = 255.0f;
    }
    for (j = 0; j < ((ModgfxVertexGroupCmd*)p)->indexCount; j++)
    {
        buf[(((ModgfxVertexGroupCmd*)p)->indices)[j] * 16 + 0xc] = (int)((PartfxEffectState*)state)->blendColorR;
        buf[(((ModgfxVertexGroupCmd*)p)->indices)[j] * 16 + 0xd] = (int)((PartfxEffectState*)state)->blendColorG;
        buf[(((ModgfxVertexGroupCmd*)p)->indices)[j] * 16 + 0xe] = (int)((PartfxEffectState*)state)->blendColorB;
    }
}

void modgfx_stepPosition(PartfxEffectState* state, ModgfxVertexGroupCmd* cmd, int reinit)
{

    if (reinit == 1)
    {
        s16* cf = state->stageDurations;
        if (cf[state->currentStage] == 0)
        {
            int flags = state->flags;
            if ((flags & 0x4) != 0 || (flags & 0x80000) != 0)
            {
                s16 buf[12];
                f32* fbuf = (f32*)&buf[4];
                s16 posBase;
                f32 fill = MODGFX_ZERO;
                fbuf[1] = fill;
                fbuf[2] = fill;
                fbuf[3] = fill;
                fbuf[0] = MODGFX_ONE;
                posBase = ((GameObject*)state->sourceObject)->anim.rotX;
                buf[0] = posBase;
                buf[1] = posBase;
                buf[2] = posBase;
                vecRotateZXY(buf, &cmd->valueX);
            }
            state->posStepX = cmd->valueX;
            state->posStepY = cmd->valueY;
            state->posStepZ = cmd->valueZ;
        }
        else
        {
            state->posStepX =
                cmd->valueX / (f32)(s32)state->stageFrameCountdown;
            state->posStepY =
                cmd->valueY / (f32)(s32)state->stageFrameCountdown;
            state->posStepZ =
                cmd->valueZ / (f32)(s32)state->stageFrameCountdown;
        }
        state->drawPosX = state->drawPosX + state->posStepX;
        state->drawPosY = state->drawPosY + state->posStepY;
        state->drawPosZ = state->drawPosZ + state->posStepZ;
    }
    else
    {
        state->drawPosX =
            state->posStepX * gModgfxMotionStep + state->drawPosX;
        state->drawPosY =
            state->posStepY * gModgfxMotionStep + state->drawPosY;
        state->drawPosZ =
            state->posStepZ * gModgfxMotionStep + state->drawPosZ;
    }
}

/* Integer-vector lerp setup. On the reinit step, snap or step-interpolate the rotation offset triple
 * toward the rounded params, then advance it by the per-step delta. */
void modgfx_stepS16VectorLerp(PartfxEffectState* state, f32* params, int reinit)
{
    if (reinit == 1)
    {
        s16 tx = params[1];
        s16 ty = params[2];
        s16 tz = params[3];
        if (state->stageFrameCountdown != 0)
        {
            state->rotStepZ = (s16)((tx - state->rotOffsetZ) / state->stageFrameCountdown);
            state->rotStepY = (s16)((ty - state->rotOffsetY) / state->stageFrameCountdown);
            state->rotStepX = (s16)((tz - state->rotOffsetX) / state->stageFrameCountdown);
        }
        else
        {
            state->rotOffsetZ = tx;
            state->rotStepZ = 0;
            state->rotOffsetY = ty;
            state->rotStepY = 0;
            state->rotOffsetX = tz;
            state->rotStepX = 0;
        }
    }
    state->rotOffsetZ += state->rotStepZ;
    state->rotOffsetY += state->rotStepY;
    state->rotOffsetX += state->rotStepX;
}

void modgfx_stepVertexAlpha(PartfxEffectState* state, ModgfxVertexGroupCmd* command, int reinit, u8 channelIndex)
{
    int alphaIndex = channelIndex * 2;
    ModgfxVertexData* vertices = state->vertexBuffers[state->activeVertexBufferIndex];
    ModgfxVertexData* baseVertices = state->vertexBuffers[2];
    int i;

    if (reinit == 1)
    {
        f32 target = command->valueX;
        s16 frames = state->stageFrameCountdown;

        if (frames != 0)
        {
            state->alphaValues[alphaIndex] =
                (target - (f32)baseVertices[command->indices[0]].alpha) / frames;
            state->alphaValues[alphaIndex + 1] = (f32)baseVertices[command->indices[0]].alpha;
        }
        else
        {
            for (i = 0; i < command->indexCount; i++)
            {
                baseVertices[command->indices[i]].alpha = target;
                vertices[command->indices[i]].alpha = baseVertices[command->indices[i]].alpha;
            }
            return;
        }
    }

    state->alphaValues[alphaIndex + 1] += state->alphaValues[alphaIndex] * gModgfxMotionStep;
    if (state->alphaValues[alphaIndex + 1] < 0.0f)
    {
        state->alphaValues[alphaIndex + 1] = 0.0f;
    }
    else if (state->alphaValues[alphaIndex + 1] > 255.0f)
    {
        state->alphaValues[alphaIndex + 1] = 255.0f;
    }

    for (i = 0; i < command->indexCount; i++)
    {
        vertices[command->indices[i]].alpha = state->alphaValues[alphaIndex + 1];
        baseVertices[command->indices[i]].alpha = vertices[command->indices[i]].alpha;
    }
}

void modgfx_stepVertexScale(PartfxEffectState* state, ModgfxVertexGroupCmd* command, int reinit, u8 channelIndex)
{
    int scaleIndex = channelIndex * 2;
    int i;
    ModgfxVertexData* vertices;
    ModgfxVertexData* baseVertices;

    if (reinit == 1)
    {
        f32 targetX = command->valueX;
        f32 targetY = command->valueY;
        f32 targetZ = command->valueZ;

        if (state->stageFrameCountdown != 0)
        {
            state->scaleVectors[scaleIndex + 1].x =
                (targetX - state->scaleVectors[scaleIndex].x) / (f32)state->stageFrameCountdown;
            state->scaleVectors[scaleIndex + 1].y =
                (targetY - state->scaleVectors[scaleIndex].y) / (f32)state->stageFrameCountdown;
            state->scaleVectors[scaleIndex + 1].z =
                (targetZ - state->scaleVectors[scaleIndex].z) / (f32)state->stageFrameCountdown;
        }
        else
        {
            baseVertices = state->vertexBuffers[2];
            vertices = state->vertexBuffers[state->activeVertexBufferIndex];

            for (i = 0; i < command->indexCount; i++)
            {
                baseVertices[command->indices[i]].posX *= targetX;
                baseVertices[command->indices[i]].posY *= targetY;
                baseVertices[command->indices[i]].posZ *= targetZ;
                vertices[command->indices[i]].posX = baseVertices[command->indices[i]].posX;
                vertices[command->indices[i]].posY = baseVertices[command->indices[i]].posY;
                vertices[command->indices[i]].posZ = baseVertices[command->indices[i]].posZ;
            }
            return;
        }
    }

    state->scaleVectors[scaleIndex].x += state->scaleVectors[scaleIndex + 1].x * gModgfxMotionStep;
    state->scaleVectors[scaleIndex].y += state->scaleVectors[scaleIndex + 1].y * gModgfxMotionStep;
    state->scaleVectors[scaleIndex].z += state->scaleVectors[scaleIndex + 1].z * gModgfxMotionStep;

    {
        baseVertices = state->vertexBuffers[2];
        vertices = state->vertexBuffers[state->activeVertexBufferIndex];

        for (i = 0; i < command->indexCount; i++)
        {
            if (state->scaleVectors[scaleIndex].x != 1.0f)
            {
                vertices[command->indices[i]].posX =
                    state->scaleVectors[scaleIndex].x * baseVertices[command->indices[i]].posX;
            }
            if (state->scaleVectors[scaleIndex].y != 1.0f)
            {
                vertices[command->indices[i]].posY =
                    state->scaleVectors[scaleIndex].y * baseVertices[command->indices[i]].posY;
            }
            if (state->scaleVectors[scaleIndex].z != 1.0f)
            {
                vertices[command->indices[i]].posZ =
                    state->scaleVectors[scaleIndex].z * baseVertices[command->indices[i]].posZ;
            }
        }
    }
}

void modgfx_restoreBaseVertices(PartfxEffectState* state)
{
    int i;
    ModgfxVertexData* src;
    ModgfxVertexData* dst = state->vertexBuffers[state->activeVertexBufferIndex];
    src = state->vertexBuffers[2];
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

void partfx_freeEffectsBySequence(s16 sequenceId, int forceAll)
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
/* Flag every active effect whose owner object has the 0x800 state bit
 * by setting its frameUpdated flag. */
void dll_0B_markSourceFrameUpdated(void)
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
void dll_0B_func0B(void)
{
    lbl_803DD282++;
}

void dll_0B_releaseHandle(s16* p)
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

int dll_0B_renderEffects(void* drawContext, int unused1, int unused2, u8 sourceOnly, void* sourceObject) {
    u8 ar;
    u8 ag;
    u8 ab;
    f32 pos[3];
    f32 rot[3];
    MatrixTransform xf;
    Mtx44 mtxB;
    Mtx mtxA;
    int** p;
    int slot;
    Camera* view;
    u8 textureFrameCount;
    void* buf1;
    void* buf2;
    u8 aligned;
    Texture* texture;
    int nextTextureFrame;
    int textureFrame;
    int frameIndex;
    f32 dirX;
    f32 dirZ;
    f32 dscale;

    nextTextureFrame = 0;
    textureFrame = 0;
    if (sourceObject != NULL) {
        skyGetSunColor(((GameObject*)sourceObject)->lightColorSlot, &ar, &ag, &ab);
    } else {
        skyGetSunColor(0, &ar, &ag, &ab);
    }
    GXSetCullMode(GX_CULL_NONE);
    if (renderModeSetOrGet(-1) == 1) {
        return 1;
    }
    view = Camera_GetCurrent();
    p = (int**)gPartfxActiveEffects;
    for (slot = 0; slot < PARTFX_ACTIVE_EFFECT_COUNT; slot++) {
        if (p[slot] == NULL) {
            continue;
        }
        if (((PartfxEffectState*)p[slot])->sequenceId == -1) {
            continue;
        }
        if (sourceOnly) {
            if (((int)((PartfxEffectState*)p[slot])->flags & 0x2000) == 0) {
                continue;
            }
        }
        if (sourceOnly) {
            if (((PartfxEffectState*)p[slot])->sourceObject != sourceObject) {
                continue;
            }
        }
        if (!sourceOnly) {
            if ((int)((PartfxEffectState*)p[slot])->flags & 0x2000) {
                continue;
            }
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x800) {
            ((PartfxEffectState*)p[slot])->frameUpdated = 0;
        }
        aligned = 0;
        buf1 = ((PartfxEffectState*)p[slot])->vertexBuffers[((PartfxEffectState*)p[slot])->activeVertexBufferIndex];
        buf2 = ((PartfxEffectState*)p[slot])->colorBuffers[((PartfxEffectState*)p[slot])->activeVertexBufferIndex];
        xf.x = MODGFX_ZERO;
        xf.y = MODGFX_ZERO;
        xf.z = MODGFX_ZERO;
        xf.scale = MODGFX_ONE;
        xf.rotZ = 0;
        xf.rotY = 0;
        pos[0] = ((PartfxEffectState*)p[slot])->drawPosX;
        pos[1] = ((PartfxEffectState*)p[slot])->drawPosY;
        pos[2] = ((PartfxEffectState*)p[slot])->drawPosZ;
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x4) {
            if (MODGFX_ZERO == pos[2] + (pos[0] + pos[1])) {
                aligned = 1;
            }
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x4) {
            if (!aligned) {
                if (((PartfxEffectState*)p[slot])->sourceObject != NULL) {
                    xf.rotX = ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.rotX;
                    xf.rotY = ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.rotY;
                    xf.rotZ = ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.rotZ;
                    vecRotateZXY(&xf.rotX, &pos[0]);
                }
            }
        }
        rot[0] = MODGFX_ZERO;
        rot[1] = MODGFX_ZERO;
        rot[2] = MODGFX_ZERO;
        if (((int)((PartfxEffectState*)p[slot])->flags & 1) == 0) {
            if (((PartfxEffectState*)p[slot])->sourceObject != NULL) {
                rot[0] = ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.worldPosX;
                rot[1] = ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.worldPosY;
                rot[2] = ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.worldPosZ;
            } else {
                rot[0] = ((PartfxEffectState*)p[slot])->sourcePosX;
                rot[1] = ((PartfxEffectState*)p[slot])->sourcePosY;
                rot[2] = ((PartfxEffectState*)p[slot])->sourcePosZ;
                Obj_RotateLocalOffsetByYaw(&((PartfxEffectState*)p[slot])->sourcePosX, &rot[0],
                                           ((PartfxEffectState*)p[slot])->sourceYawIndex);
            }
        }
        if (rot[0] > 65534.0f || rot[0] < -65534.0f) {
            rot[0] = -playerMapOffsetX;
        }
        if (rot[1] > 65534.0f || rot[1] < -65534.0f) {
            rot[1] = MODGFX_ZERO;
        }
        if (rot[2] > 65534.0f || rot[2] < -65534.0f) {
            rot[2] = -playerMapOffsetZ;
        }
        xf.x = rot[0] + pos[0];
        xf.y = rot[1] + pos[1];
        xf.z = rot[2] + pos[2];
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x400000) {
            dscale = 0.5f * ((PartfxEffectState*)p[slot])->renderScale;
            xf.scale = dscale + dscale / randomGetRange(1, 10);
        } else {
            xf.scale = 0.01f * ((PartfxEffectState*)p[slot])->renderScale;
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x80000) {
            xf.rotZ = ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.rotZ;
            xf.rotY = ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.rotY;
            xf.rotX = ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.rotX;
        } else if (aligned && ((PartfxEffectState*)p[slot])->sourceObject != NULL) {
            xf.rotZ = ((PartfxEffectState*)p[slot])->rotOffsetZ +
                      ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.rotZ;
            xf.rotY = ((PartfxEffectState*)p[slot])->rotOffsetY +
                      ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.rotY;
            xf.rotX = ((PartfxEffectState*)p[slot])->rotOffsetX +
                      ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.rotX;
        } else if (aligned) {
            xf.rotZ = ((PartfxEffectState*)p[slot])->rotOffsetZ + ((PartfxEffectState*)p[slot])->sourceRotZ;
            xf.rotY = ((PartfxEffectState*)p[slot])->rotOffsetY + ((PartfxEffectState*)p[slot])->sourceRotY;
            xf.rotX = ((PartfxEffectState*)p[slot])->rotOffsetX + ((PartfxEffectState*)p[slot])->sourceRotX;
        } else {
            xf.rotZ = ((PartfxEffectState*)p[slot])->rotOffsetZ;
            xf.rotY = ((PartfxEffectState*)p[slot])->rotOffsetY;
            xf.rotX = ((PartfxEffectState*)p[slot])->rotOffsetX;
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x1000) {
            if (((PartfxEffectState*)p[slot])->sourceObject != NULL) {
                dirX = view->worldX - ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.worldPosX;
                dirZ = view->worldZ - ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.worldPosZ;
                dscale = sqrtf(dirX * dirX + dirZ * dirZ);
                if (dscale) {
                    dirX = dirX / dscale;
                    dirZ = dirZ / dscale;
                }
                dscale = (u16)getAngle(dirX, dirZ);
                xf.rotX += (s16)dscale;
            }
        }
        xf.x = xf.x - playerMapOffsetX;
        xf.z = xf.z - playerMapOffsetZ;
        setMatrixFromObjectPos(mtxB[0], &xf);
        mtx44Transpose(mtxB[0], mtxA[0]);
        PSMTXConcat((MtxPtr)Camera_GetViewMatrix(), mtxA, mtxA);
        GXLoadPosMtxImm(mtxA, GX_PNMTX0);
        texture = ((PartfxEffectState*)p[slot])->textureResource;
        if (texture != NULL) {
            textureFrameCount = (u8)(texture->animationFrameCount >> 8);
        }
        if (texture != NULL && ((PartfxEffectState*)p[slot])->textureFrameTimer != 0) {
            ((PartfxEffectState*)p[slot])->textureFrameStep -= 1;
            if (((PartfxEffectState*)p[slot])->textureFrameStep == 0) {
                ((PartfxEffectState*)p[slot])->textureFrameStep =
                    0x3c / ((PartfxEffectState*)p[slot])->textureFrameTimer;
                ((PartfxEffectState*)p[slot])->textureFrame += 1;
                if (((PartfxEffectState*)p[slot])->textureFrame >= (u32)textureFrameCount) {
                    ((PartfxEffectState*)p[slot])->textureFrame = 0;
                }
            }
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x10000000) {
            setTextColor(drawContext, ar, ag, ab, 0xff);
        } else if (((PartfxEffectState*)p[slot])->sourceObject != NULL &&
                   ((int)((PartfxEffectState*)p[slot])->flags & 0x4000)) {
            setTextColor(drawContext, 0xff, 0xff, 0xff,
                         ((GameObject*)((PartfxEffectState*)p[slot])->sourceObject)->anim.renderAlpha);
        } else {
            setTextColor(drawContext, 0xff, 0xff, 0xff, 0xff);
        }
        texture = ((PartfxEffectState*)p[slot])->textureResource;
        if (texture != NULL) {
            textureFrame = ((PartfxEffectState*)p[slot])->textureFrame;
            nextTextureFrame = (textureFrame + 1) & 0xff;
            if (nextTextureFrame > textureFrameCount - 1) {
                nextTextureFrame = 0;
            }
        }
        if (((int)((PartfxEffectState*)p[slot])->flags & 0x1000000) &&
            (((PartfxEffectState*)p[slot])->frameUpdated != 0 || ((int)((PartfxEffectState*)p[slot])->flags & 0x400))) {
            {
                for (frameIndex = 0; frameIndex < (u8)nextTextureFrame; frameIndex++) {
                    texture = texture->nextAnimationFrame;
                }
                _textSetColor(drawContext, 0xff, 0xff, 0xff,
                              (u8)(0xff - ((PartfxEffectState*)p[slot])->textureFrameStep *
                                              ((PartfxEffectState*)p[slot])->textureFrameFadeStep));
                gxTevResetStages();
                gxTevAddTextureFrameBlendStages();
                gxTevModulateRasStage();
                gxTevCommitStages();
                selectTexture(texture, 1);
            }
        } else if ((int)((PartfxEffectState*)p[slot])->flags & 0x2000000) {
            gxTevResetStages();
            gxTevRasTimesColor1Stage();
            gxTevCommitStages();
        } else if ((int)((PartfxEffectState*)p[slot])->flags & 0x4000000) {
            gxTevResetStages();
            gxTevTextureTimesRasStage();
            gxTevModulateColor1Stage();
            gxTevCommitStages();
        }
        if (((int)((PartfxEffectState*)p[slot])->flags & 0x05000000) &&
            (((PartfxEffectState*)p[slot])->frameUpdated != 0 || ((int)((PartfxEffectState*)p[slot])->flags & 0x400))) {
            {
                texture = ((PartfxEffectState*)p[slot])->textureResource;
                for (frameIndex = 0; frameIndex < (u8)textureFrame; frameIndex++) {
                    texture = texture->nextAnimationFrame;
                }
                selectTexture(texture, 0);
            }
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x100) {
            gxSetAlphaBlendZTest();
        } else if (((int)((PartfxEffectState*)p[slot])->flags & 0x10) &&
                   ((int)((PartfxEffectState*)p[slot])->flags & 0x80)) {
            gxSetAlphaBlendNoZTest();
        } else if ((int)((PartfxEffectState*)p[slot])->flags & 0x80) {
            gxSetAlphaBlendZTest();
        } else if ((int)((PartfxEffectState*)p[slot])->flags & 0x10) {
            gxSetAlphaBlendNoZTest();
        } else {
            gxSetAlphaBlendZTest();
        }
        if ((int)((PartfxEffectState*)p[slot])->flags & 0x40) {
            GXSetCullMode(GX_CULL_FRONT);
        } else {
            GXSetCullMode(GX_CULL_NONE);
        }
        if (((PartfxEffectState*)p[slot])->frameUpdated != 0 || ((int)((PartfxEffectState*)p[slot])->flags & 0x400)) {
            int di;
            for (di = 0; di < ((PartfxEffectState*)p[slot])->drawGroupCount; di++) {
                if ((int)((PartfxEffectState*)p[slot])->flags & 0x8000000) {
                    lightmapDrawTriangleList(buf1, (u8*)buf2,
                                             ((PartfxEffectState*)p[slot])->colorVertexCount /
                                                 ((PartfxEffectState*)p[slot])->drawGroupCount);
                } else {
                    lightmapDrawTriangleList(buf1, (u8*)buf2, ((PartfxEffectState*)p[slot])->colorVertexCount);
                }
                buf1 = (char*)buf1 + (((PartfxEffectState*)p[slot])->drawGroupStride << 4);
                if ((int)((PartfxEffectState*)p[slot])->flags & 0x8000000) {
                    buf2 = (char*)buf2 + ((((PartfxEffectState*)p[slot])->colorVertexCount /
                                           ((PartfxEffectState*)p[slot])->drawGroupCount)
                                          << 4);
                }
            }
        }
        Rcp_ResetRenderState();
        ((PartfxEffectState*)p[slot])->activeVertexBufferIndex =
            1 - ((PartfxEffectState*)p[slot])->activeVertexBufferIndex;
    }
    return 0;
}

void dll_0B_detachSource(void* param)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;

    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        if (arr[i] != NULL && arr[i]->sourceObject == param)
        {
            if ((int)arr[i]->flags & 0x10000)
            {
                partfx_freeEffectsBySequence(arr[i]->sequenceId, 0);
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
                arr[i]->sourceObject = 0;
            }
        }
    }
}

void dll_0B_freeSourceEffects(void* source)
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

void dll_0B_releaseAll(void)
{
    partfx_freeEffectsBySequence(0, 1);
}

typedef void (*ExpFn2)(void*, int);
typedef void (*ExpFn3)(void*, void*, int);
typedef void (*ExpFn4)(void*, void*, int, int);
typedef void (*ExpResFn6)(void*, int, void*, int, int, void*);

#define PENDING_SPAWNS ((char*)((PartfxEffectState*)eff)->emitterCommands)

void dll_0B_updateActiveEffects(void)
{
    int emOff;
    int emIdx;
    int* eff;
    int reprocess;
    int active;
    int** pp;
    int slot;
    int feFlag;
    int scaleGroupIndex;
    int alphaGroupIndex;
    int k;
    void* res;
    PartFxSpawnParams tmpl;
    MatrixTransform rot;
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
            if (((PartfxEffectState*)eff)->sequenceId == -1)
                break;
            active = 0;
            ((PartfxEffectState*)eff)->frameUpdated = 0;
            if (((PartfxEffectState*)eff)->stageFrameCountdown < 0 || ((PartfxEffectState*)eff)->currentStage == -1)
            {
                ((PartfxEffectState*)eff)->currentStage += 1;
                if (((PartfxEffectState*)eff)->currentStage > 6)
                {
                    partfx_freeEffectsBySequence(((PartfxEffectState*)eff)->sequenceId, 0);
                    break;
                }
                ((PartfxEffectState*)eff)->stageFrameCountdown =
                    ((PartfxEffectState*)eff)->stageDurations[((PartfxEffectState*)eff)->currentStage];
                active = 1;
                ((ExpFn2)modgfx_captureFrameBaseVertices)(eff, 0);
            }
            else if (((PartfxEffectState*)eff)->requestedStage != 0)
            {
                ((PartfxEffectState*)eff)->currentStage = ((PartfxEffectState*)eff)->requestedStage;
                ((PartfxEffectState*)eff)->requestedStage = 0;
                if (((PartfxEffectState*)eff)->currentStage > 6)
                {
                    partfx_freeEffectsBySequence(((PartfxEffectState*)eff)->sequenceId, 0);
                    break;
                }
                ((PartfxEffectState*)eff)->stageFrameCountdown =
                    ((PartfxEffectState*)eff)->stageDurations[((PartfxEffectState*)eff)->currentStage];
                active = 1;
                ((ExpFn2)modgfx_captureFrameBaseVertices)(eff, 0);
            }
            scaleGroupIndex = 0;
            alphaGroupIndex = 0;
            ((ExpFn3)modgfx_restoreBaseVertices)(eff, PENDING_SPAWNS + emIdx * sizeof(ModgfxPendingSpawn), active);
            feFlag = 0;
            emIdx = 0;
            emOff = 0;
            for (; emIdx < ((PartfxEffectState*)eff)->emitterCount; emOff += sizeof(ModgfxPendingSpawn), emIdx++)
            {
                s16 frameIndex;
                char* pendingSpawns;
                ModgfxPendingSpawn* emitter;
                int flags;

                frameIndex = ((PartfxEffectState*)eff)->currentStage;
                pendingSpawns = PENDING_SPAWNS;
                emitter = (ModgfxPendingSpawn*)(pendingSpawns + emOff);
                if (frameIndex != emitter->sequenceIndex)
                    continue;
                flags = emitter->modelOrResource;
                if ((flags & 0x1000) && emitter->posX > MODGFX_ZERO && frameIndex > 0)
                {
                    ((PartfxEffectState*)eff)->currentStage = ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emIdx * sizeof(ModgfxPendingSpawn)))->param14;
                    ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emIdx * sizeof(ModgfxPendingSpawn)))->posX =
                        ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emIdx * sizeof(ModgfxPendingSpawn)))->posX - MODGFX_ONE;
                    ((PartfxEffectState*)eff)->stageFrameCountdown = -1;
                    break;
                }
                if (flags & 0x2000)
                {
                    if (((PartfxEffectState*)eff)->releaseRequested != 0)
                    {
                        ((PartfxEffectState*)eff)->releaseRequested = 0;
                        ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emIdx * sizeof(ModgfxPendingSpawn)))->modelOrResource = 0;
                        ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emIdx * sizeof(ModgfxPendingSpawn)))->modelOrResource = 0x20;
                        ((PartfxEffectState*)eff)->stageFrameCountdown = -1;
                        reprocess = 1;
                        feFlag = 0;
                        break;
                    }
                    if (((PartfxEffectState*)eff)->currentStage > 0)
                    {
                        feFlag = 1;
                        ((PartfxEffectState*)eff)->currentStage =
                            ((ModgfxPendingSpawn*)(pendingSpawns + emIdx * sizeof(ModgfxPendingSpawn)))->param14;
                        ((PartfxEffectState*)eff)->stageFrameCountdown = -1;
                        reprocess = 1;
                        break;
                    }
                }
                if (flags & 0x10000000)
                {
                    tmpl.posX = ((PartfxEffectState*)eff)->drawPosX;
                    tmpl.posY = ((PartfxEffectState*)eff)->drawPosY;
                    tmpl.posZ = ((PartfxEffectState*)eff)->drawPosZ;
                    rot.x = MODGFX_ZERO;
                    rot.y = MODGFX_ZERO;
                    rot.z = MODGFX_ZERO;
                    rot.scale = MODGFX_ONE;
                    if ((int)((PartfxEffectState*)eff)->flags & 1)
                    {
                        rot.rotX = ((PartfxEffectState*)eff)->sourceRotX;
                    }
                    else
                    {
                        rot.rotX = *(s16*)((int*)((PartfxEffectState*)eff)->sourceObject);
                    }
                    rot.rotY = 0;
                    rot.rotZ = 0;
                    vecRotateZXY(&rot.rotX, &tmpl.posX);
                    if (*(void**)eff == NULL && Obj_IsLoadingLocked())
                    {
                        int* o;
                        if (((int)((PartfxEffectState*)eff)->flags & 1) == 0)
                        {
                            tmpl.posX = ((GameObject*)((PartfxEffectState*)eff)->sourceObject)->anim.worldPosX + tmpl.posX;
                            tmpl.posY = ((GameObject*)((PartfxEffectState*)eff)->sourceObject)->anim.worldPosY + tmpl.posY;
                            tmpl.posZ = ((GameObject*)((PartfxEffectState*)eff)->sourceObject)->anim.worldPosZ + tmpl.posZ;
                        }
                        else
                        {
                            tmpl.posX = ((PartfxEffectState*)eff)->sourcePosX + tmpl.posX;
                            tmpl.posY = ((PartfxEffectState*)eff)->sourcePosY + tmpl.posY;
                            tmpl.posZ = ((PartfxEffectState*)eff)->sourcePosZ + tmpl.posZ;
                        }
                        o = (int*)Obj_AllocObjectSetup(0x20, DLL0B_CHILD_OBJ_INVHIT);
                        ((ObjPlacement*)o)->posX = tmpl.posX;
                        ((ObjPlacement*)o)->posY = tmpl.posY;
                        ((ObjPlacement*)o)->posZ = tmpl.posZ;
                        *eff = (int)objSetupObject((ObjPlacement*)o, 5, -1, -1, NULL);
                        ((PartfxEffectState*)eff)->instanceObject->userData2 = 1;
                    }
                    else if (*(void**)eff != NULL)
                    {
                        if (((int)((PartfxEffectState*)eff)->flags & 1) == 0)
                        {
                            tmpl.posX = ((GameObject*)((PartfxEffectState*)eff)->sourceObject)->anim.worldPosX + tmpl.posX;
                            tmpl.posY = ((GameObject*)((PartfxEffectState*)eff)->sourceObject)->anim.worldPosY + tmpl.posY;
                            tmpl.posZ = ((GameObject*)((PartfxEffectState*)eff)->sourceObject)->anim.worldPosZ + tmpl.posZ;
                        }
                        else
                        {
                            tmpl.posX = ((PartfxEffectState*)eff)->sourcePosX + tmpl.posX;
                            tmpl.posY = ((PartfxEffectState*)eff)->sourcePosY + tmpl.posY;
                            tmpl.posZ = ((PartfxEffectState*)eff)->sourcePosZ + tmpl.posZ;
                        }
                        ((PartfxEffectState*)eff)->instanceObject->anim.worldPosX = tmpl.posX;
                        ((PartfxEffectState*)eff)->instanceObject->anim.worldPosY = tmpl.posY;
                        ((PartfxEffectState*)eff)->instanceObject->anim.worldPosZ = tmpl.posZ;
                    }
                    if (*(void**)eff != NULL)
                    {
                        int* o = *(int**)eff;
                        int* list = *(int**)((char*)(int*)((GameObject*)o)->anim.hitReactState + 0x50);
                        if (list != NULL)
                        {
                            if (*(s16*)((char*)list + 0x44) == (int)((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->posX)
                            {
                                Obj_FreeObject((GameObject*)o);
                                *eff = 0;
                                ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emIdx * 0x18))->modelOrResource ^= 0x10000000;
                                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emIdx * 0x18))->posZ >= MODGFX_ZERO &&
                                    (int*)((PartfxEffectState*)eff)->sourceObject != NULL)
                                {
                                    (*gPartfxInterface)
                                        ->spawnObject((int*)((PartfxEffectState*)eff)->sourceObject,
                                                      (int)((ModgfxPendingSpawn*)(PENDING_SPAWNS + emIdx * sizeof(ModgfxPendingSpawn)))->posZ, &tmpl,
                                                      0x200001, -1, 0);
                                }
                                ((PartfxEffectState*)eff)->requestedStage =
                                    ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emIdx * 0x18))->posY;
                                break;
                            }
                        }
                    }
                }
                ObjList_GetObjects(&objIdx, &objCount);
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x2)
                {
                    modgfx_stepVertexScale((PartfxEffectState*)eff,
                                           (ModgfxVertexGroupCmd*)(PENDING_SPAWNS + emOff), active, scaleGroupIndex);
                    scaleGroupIndex++;
                }
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x4)
                {
                    modgfx_stepVertexAlpha((PartfxEffectState*)eff,
                                           (ModgfxVertexGroupCmd*)(PENDING_SPAWNS + emOff), active, alphaGroupIndex);
                    alphaGroupIndex++;
                }
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x8)
                {
                    ((ExpFn4)modgfx_stepVertexColor)(eff, PENDING_SPAWNS + emOff, active, 0);
                }
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x100)
                {
                    ModgfxPendingSpawn* em = (ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff);
                    ((PartfxEffectState*)eff)->rotOffsetZ += (s16)(em->posX * gModgfxMotionStep);
                    ((PartfxEffectState*)eff)->rotOffsetY += (s16)(em->posY * gModgfxMotionStep);
                    ((PartfxEffectState*)eff)->rotOffsetX += (s16)(em->posZ * gModgfxMotionStep);
                }
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x80)
                {
                    ((ExpFn4)modgfx_stepS16VectorLerp)(eff, PENDING_SPAWNS + emOff, active, 0);
                }
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x8000000)
                {
                    ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->posZ = randomGetRange(0, 0xffff);
                    ((ExpFn4)modgfx_stepS16VectorLerp)(eff, PENDING_SPAWNS + emOff, active, 0);
                }
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x4000)
                {
                    ((ExpFn4)modgfx_scrollTexCoords)(eff, PENDING_SPAWNS + emOff, active, 0);
                }
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x10000 && active != 0)
                {
                    if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->param14 == -1)
                    {
                        Sfx_StopObjectChannel((GameObject*)((PartfxEffectState*)eff)->sourceObject, 0x40);
                    }
                    else
                    {
                        Sfx_PlayFromObject((GameObject*)((PartfxEffectState*)eff)->sourceObject,
                                           (u16)((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->param14);
                    }
                }
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x100000)
                {
                    if (active == 1)
                    {
                        if (((PartfxEffectState*)eff)->stageFrameCountdown != 0)
                        {
                            ((PartfxEffectState*)eff)->sourceAlphaStep =
                                (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->posX -
                                 (f32)(u32)(*(GameObject**)&((PartfxEffectState*)eff)->sourceObject)->anim.alpha) /
                                (f32)((PartfxEffectState*)eff)->stageFrameCountdown;
                            ((PartfxEffectState*)eff)->sourceAlphaCurrent =
                                (f32)(u32)(*(GameObject**)&((PartfxEffectState*)eff)->sourceObject)->anim.alpha;
                        }
                        else
                        {
                            ((PartfxEffectState*)eff)->sourceAlphaStep =
                                ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->posX -
                                (f32)(u32)(*(GameObject**)&((PartfxEffectState*)eff)->sourceObject)->anim.alpha;
                            ((PartfxEffectState*)eff)->sourceAlphaCurrent = MODGFX_ZERO;
                        }
                    }
                    ((PartfxEffectState*)eff)->sourceAlphaCurrent =
                        ((PartfxEffectState*)eff)->sourceAlphaCurrent + ((PartfxEffectState*)eff)->sourceAlphaStep;
                    if (((PartfxEffectState*)eff)->sourceAlphaCurrent > 255.0f)
                    {
                        ((PartfxEffectState*)eff)->sourceAlphaCurrent = 255.0f;
                    }
                    else if (((PartfxEffectState*)eff)->sourceAlphaCurrent < MODGFX_ZERO)
                    {
                        ((PartfxEffectState*)eff)->sourceAlphaCurrent = MODGFX_ZERO;
                    }
                    (*(GameObject**)&((PartfxEffectState*)eff)->sourceObject)->anim.alpha =
                        ((PartfxEffectState*)eff)->sourceAlphaCurrent;
                }
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x400000)
                {
                    ((ExpFn4)modgfx_stepPosition)(eff, PENDING_SPAWNS + emOff, active, 0);
                }
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x80000000)
                {
                    ModgfxPendingSpawn* em = (ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff);
                    ((PartfxEffectState*)eff)->posStepX =
                        em->posX * gModgfxMotionStep + ((PartfxEffectState*)eff)->posStepX;
                    ((PartfxEffectState*)eff)->posStepY =
                        em->posY * gModgfxMotionStep + ((PartfxEffectState*)eff)->posStepY;
                    ((PartfxEffectState*)eff)->posStepZ =
                        em->posZ * gModgfxMotionStep + ((PartfxEffectState*)eff)->posStepZ;
                }
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x800000)
                {
                    if ((((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x1000000) &&
                        MODGFX_ZERO == ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->posY)
                    {
                        for (k = 0; k < (int)((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->posX; k++)
                        {
                            if (randomGetRange(0, (int)((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->posZ) == 0)
                            {
                                if ((int)((PartfxEffectState*)eff)->flags & 1)
                                {
                                    (*gPartfxInterface)
                                        ->spawnObject((int*)((PartfxEffectState*)eff)->sourceObject,
                                                      ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->param14, NULL, 0x10001, -1,
                                                      NULL);
                                }
                                else
                                {
                                    (*gPartfxInterface)
                                        ->spawnObject((int*)((PartfxEffectState*)eff)->sourceObject,
                                                      ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->param14, NULL, 0x10001, -1,
                                                      NULL);
                                }
                            }
                        }
                    }
                    else if (MODGFX_ZERO == ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->posY)
                    {
                        for (k = 0; k < (int)((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->posX; k++)
                        {
                            if ((int)((PartfxEffectState*)eff)->flags & 1)
                            {
                                (*gPartfxInterface)
                                    ->spawnObject((int*)((PartfxEffectState*)eff)->sourceObject,
                                                  ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->param14, eff + 3, 0x10002, -1,
                                                  NULL);
                            }
                            else
                            {
                                (*gPartfxInterface)
                                    ->spawnObject((int*)((PartfxEffectState*)eff)->sourceObject,
                                                  ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->param14, NULL, 0x10002, -1,
                                                  NULL);
                            }
                        }
                    }
                    else if (MODGFX_ONE == ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->posY)
                    {
                        if (((int)((PartfxEffectState*)eff)->flags & 1) == 0)
                        {
                            tmpl.posX = ((GameObject*)((PartfxEffectState*)eff)->sourceObject)->anim.worldPosX +
                                     ((PartfxEffectState*)eff)->drawPosX;
                            tmpl.posY = ((GameObject*)((PartfxEffectState*)eff)->sourceObject)->anim.worldPosY +
                                     ((PartfxEffectState*)eff)->drawPosY;
                            tmpl.posZ = ((GameObject*)((PartfxEffectState*)eff)->sourceObject)->anim.worldPosZ +
                                     ((PartfxEffectState*)eff)->drawPosZ;
                            if ((int*)((PartfxEffectState*)eff)->sourceObject != NULL)
                            {
                                (*gPartfxInterface)
                                    ->spawnObject((int*)((PartfxEffectState*)eff)->sourceObject,
                                                  ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->param14, &tmpl, 0x10001, -1,
                                                  NULL);
                            }
                        }
                        else
                        {
                            tmpl.posX = ((PartfxEffectState*)eff)->drawPosX;
                            tmpl.posY = ((PartfxEffectState*)eff)->drawPosY;
                            tmpl.posZ = ((PartfxEffectState*)eff)->drawPosZ;
                            if ((int*)((PartfxEffectState*)eff)->sourceObject != NULL)
                            {
                                (*gPartfxInterface)
                                    ->spawnObject((int*)((PartfxEffectState*)eff)->sourceObject,
                                                  ((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->param14, &tmpl, 0x10001, -1,
                                                  NULL);
                            }
                        }
                    }
                }
                if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x4000000)
                {
                    res = Resource_Acquire((u16)(((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->param14 + 0x58), 1);
                    if (((ModgfxPendingSpawn*)(PENDING_SPAWNS + emOff))->modelOrResource & 0x1000000)
                    {
                        for (k = 0; k < (int)*(f32*)((emOff + (int)PENDING_SPAWNS) + 0x4); k++)
                        {
                            if (randomGetRange(0, 5) == 0)
                            {
                                if ((int)((PartfxEffectState*)eff)->flags & 1)
                                {
                                    (*(ExpResFn6*)(*(int*)res + 4))(NULL, 0, eff + 3, 1, -1, NULL);
                                }
                                else
                                {
                                    ((ExpResFn6)(*(ObjectInterface**)res)->init)((int*)((PartfxEffectState*)eff)->sourceObject, 0,
                                                                    NULL, 1, -1, NULL);
                                }
                            }
                        }
                    }
                    else
                    {
                        for (k = 0; k < (int)*(f32*)((emOff + (int)PENDING_SPAWNS) + 0x4); k++)
                        {
                            if ((int)((PartfxEffectState*)eff)->flags & 1)
                            {
                                (*(ExpResFn6*)(*(int*)res + 4))(NULL, 0, eff + 3, 1, -1, NULL);
                            }
                            else
                            {
                                ((ExpResFn6)(*(ObjectInterface**)res)->init)((int*)((PartfxEffectState*)eff)->sourceObject, 0, NULL,
                                                                1, -1, NULL);
                            }
                        }
                    }
                    Resource_Release(res);
                }
            }
            if (feFlag == 0)
            {
                ((PartfxEffectState*)eff)->stageFrameCountdown = ((PartfxEffectState*)eff)->stageFrameCountdown - framesThisStep;
            }
        }
        gExpgfxUpdatingActivePools = 0;
    }
}

s16 dll_0B_spawnEffect(ModgfxSpawnContext* context, int unused, int vertexCount, s16* vertexData, int colorCount,
                       s16* colorData, int textureAssetId, void* textureResource)
{
    int off;
    int i;
    int spawnCount;
    int divThresh;
    int slot;
    f32 fz434;
    f32 fz430;
    PartfxEffectState** arr;
    int emitterAddress;
    int base0;
    int total;

    total = 0;
    i = 0;
    off = i;
    slot = modgfx_findFreeEffectSlot(gPartfxActiveEffects, off, i);
    if (slot == -1)
    {
        return 0;
    }
    {
        off = 0;
        spawnCount = context->pendingSpawnCount;
        for (i = 0; i < spawnCount; i++, off += 0x18)
        {
            ModgfxPendingSpawn* item = (ModgfxPendingSpawn*)((u8*)context->pendingSpawns + off);
            if ((item->modelOrResource & 0xf7fff180) == 0 && item->param14 != 0)
            {
                total += item->param14;
            }
        }
    }

    base0 = 0;
    if ((context->flags & 0x800) == 0)
    {
        base0 = (int)(long)((colorCount * 3) << 4) + ((vertexCount * 3) << 4);
    }

    arr = (PartfxEffectState**)gPartfxActiveEffects;
    arr[slot] = (PartfxEffectState*)mmAlloc(
        sizeof(PartfxEffectState) + base0 + 0x100 + spawnCount * sizeof(ModgfxPendingSpawn) + total * 2,
        0x15, 0);
    if (arr[slot] == NULL)
    {
        partfx_freeEffectsBySequence(0, 0);
        return -1;
    }

    arr[slot]->inlineData =
        (u8*)arr[slot] + sizeof(PartfxEffectState);
    {
        u8* bufp = arr[slot]->inlineData;
        if ((context->flags & 0x800) == 0)
        {
            arr[slot]->colorBuffers[0] = bufp;
            bufp += colorCount * 16;
            arr[slot]->colorBuffers[1] = bufp;
            bufp += colorCount * 16;
            arr[slot]->colorBuffers[2] = bufp;
            bufp += colorCount * 16;
            arr[slot]->vertexBuffers[0] = bufp;
            bufp += vertexCount * 16;
            arr[slot]->vertexBuffers[1] = bufp;
            bufp += vertexCount * 16;
            arr[slot]->vertexBuffers[2] = bufp;
            bufp += vertexCount * 16;
        }
        arr[slot]->baseVertexBuffer = bufp;
        arr[slot]->baseColorBuffer = bufp + 0x80;
    }

    if (context->drawGroupCount != 0)
    {
        divThresh = colorCount / context->drawGroupCount;
    }
    else
    {
        divThresh = colorCount;
    }
    if ((context->flags & 0x800) == 0)
    {
        for (i = 0, off = i; i < 3; off += 4, i++)
        {
            s16* sd;
            int j;
            int bias;
            u8* dstc;

            dstc = (u8*)((PartfxEffectState*)((u8*)arr[slot] + off))->colorBuffers[0];
            bias = 0;
            j = 0;
            sd = colorData;
            for (; j < colorCount; j++)
            {
                if ((context->flags & 0x8000000) && j == divThresh)
                {
                    bias = context->drawGroupStride;
                }
                dstc[1] = sd[0] - bias;
                dstc[2] = sd[1] - bias;
                dstc[3] = sd[2] - bias;
                dstc += 0x10;
                sd += 3;
            }
        }
    }

    arr[slot]->textureResource = NULL;
    arr[slot]->textureIsBorrowed = 0;
    if (textureResource != NULL)
    {
        arr[slot]->textureResource = textureResource;
        arr[slot]->textureIsBorrowed = 1;
    }
    else if (textureAssetId != 0)
    {
        arr[slot]->textureResource = textureLoadAsset(textureAssetId);
        arr[slot]->textureIsBorrowed = 0;
    }

    if ((context->flags & 0x800) == 0)
    {
        for (i = 0, off = i; i < 3; off += 4, i++)
        {
            int j;
            s16* sb;
            u8* dstv;
            dstv = (u8*)((PartfxEffectState*)((u8*)arr[slot] + off))->vertexBuffers[0];
            sb = vertexData;
            for (j = 0; j < vertexCount; j++)
            {
                *(s16*)(dstv + 0) = sb[0];
                *(s16*)(dstv + 2) = sb[1];
                *(s16*)(dstv + 4) = sb[2];
                if (arr[slot]->textureResource != NULL)
                {
                    *(s16*)(dstv + 8) =
                        128.0f *
                        ((f32)sb[3] / (f32)((Texture*)arr[slot]->textureResource)->width);
                    *(s16*)(dstv + 0xa) =
                        128.0f *
                        ((f32)sb[4] / (f32)((Texture*)arr[slot]->textureResource)->height);
                }
                dstv[0xc] = 0xff;
                dstv[0xd] = 0xff;
                dstv[0xe] = 0xff;
                dstv[0xf] = 0xff;
                sb += 5;
                dstv += 0x10;
            }
        }
    }

    arr[slot]->emitterCount = context->pendingSpawnCount;
    arr[slot]->word114 = 0;
    arr[slot]->word118 = 0;
    arr[slot]->word11C = 0;
    arr[slot]->auxAllocation = NULL;
    arr[slot]->releaseRequested = 0;
    arr[slot]->byte13D = 0;
    arr[slot]->stageTimer = 0;
    arr[slot]->nextStage = -1;
    arr[slot]->requestedStage = 0;
    arr[slot]->stageDurations[0] = context->sequenceParams[0];
    arr[slot]->stageDurations[1] = context->sequenceParams[1];
    arr[slot]->stageDurations[2] = context->sequenceParams[2];
    arr[slot]->stageDurations[3] = context->sequenceParams[3];
    arr[slot]->stageDurations[4] = context->sequenceParams[4];
    arr[slot]->stageDurations[5] = context->sequenceParams[5];
    arr[slot]->stageDurations[6] = context->sequenceParams[6];
    emitterAddress = base0;
    emitterAddress += (int)arr[slot]->inlineData;
    emitterAddress += 0x100;
    arr[slot]->emitterCommands = (u8*)emitterAddress;
    arr[slot]->auxSequenceBuffer = NULL;
    if (total != 0)
    {
        arr[slot]->auxSequenceBuffer =
            (u8*)arr[slot]->emitterCommands +
            context->pendingSpawnCount * sizeof(ModgfxPendingSpawn);
    }

    {
        u8* dst = arr[slot]->auxSequenceBuffer;
        for (i = 0, off = i; i < arr[slot]->emitterCount; off += 0x18, i++)
        {
            ((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands + off))
                ->sequenceIndex = ((ModgfxPendingSpawn*)((u8*)context->pendingSpawns + off))->sequenceIndex;
            ((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands + off))
                ->param14 = ((ModgfxPendingSpawn*)((u8*)context->pendingSpawns + off))->param14;
            ((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands + off))
                ->param10 = 0;
            ((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands + off))
                ->modelOrResource =
                ((ModgfxPendingSpawn*)((u8*)context->pendingSpawns + off))->modelOrResource;
            if ((((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands + off))
                     ->modelOrResource &
                 0xf7fff180) == 0 &&
                ((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands + off))
                        ->param14 != 0)
            {
                int k;
                ((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands + off))
                    ->param10 = 0;
                *(u8**)&((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands +
                                               off))
                     ->param10 = dst;
                dst += ((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands +
                                              off))
                           ->param14 *
                       2;
                for (k = 0;
                     k <
                     ((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands +
                                            off))
                         ->param14;
                     k++)
                {
                    *(s16*)(*(u8**)&((ModgfxPendingSpawn*)((u8*)arr[slot]
                                                               ->emitterCommands +
                                                           off))
                                 ->param10 +
                            k * 2) =
                        *(s16*)(*(u8**)((u8*)&((ModgfxPendingSpawn*)context->pendingSpawns)->param10 + off) + k * 2);
                }
            }
            ((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands + off))
                ->posX = ((ModgfxPendingSpawn*)((u8*)context->pendingSpawns + off))->posX;
            ((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands + off))
                ->posY = ((ModgfxPendingSpawn*)((u8*)context->pendingSpawns + off))->posY;
            ((ModgfxPendingSpawn*)((u8*)arr[slot]->emitterCommands + off))
                ->posZ = ((ModgfxPendingSpawn*)((u8*)context->pendingSpawns + off))->posZ;
        }
    }

    arr[slot]->currentStage = -1;
    arr[slot]->stageFrameCountdown =
        arr[slot]
            ->stageDurations[arr[slot]->currentStage];
    arr[slot]->flags = context->flags;
    arr[slot]->drawPosX = context->posX;
    arr[slot]->drawPosY = context->posY;
    arr[slot]->drawPosZ = context->posZ;
    arr[slot]->renderScale = context->scale;
    if ((int)arr[slot]->flags & 1)
    {
        arr[slot]->sourcePosX = context->posX;
        arr[slot]->sourcePosY = context->posY;
        arr[slot]->sourcePosZ = context->posZ;
    }
    fz430 = MODGFX_ZERO;
    arr[slot]->posStepX = fz430;
    arr[slot]->posStepY = fz430;
    arr[slot]->posStepZ = fz430;
    fz434 = MODGFX_ONE;
    arr[slot]->scaleVectors[0].x = fz434;
    arr[slot]->scaleVectors[0].y = fz434;
    arr[slot]->scaleVectors[0].z = fz434;
    arr[slot]->scaleVectors[1].y = fz430;
    arr[slot]->scaleVectors[1].z = fz430;
    arr[slot]->scaleVectors[1].x = fz430;
    arr[slot]->scaleVectors[2].z = fz434;
    arr[slot]->scaleVectors[2].x = fz434;
    arr[slot]->scaleVectors[2].y = fz434;
    arr[slot]->scaleVectors[3].z = fz430;
    arr[slot]->scaleVectors[3].x = fz430;
    arr[slot]->scaleVectors[3].y = fz430;
    arr[slot]->rotOffsetZ = 0;
    arr[slot]->rotOffsetY = 0;
    arr[slot]->rotOffsetX = 0;
    arr[slot]->vec120 = 0;
    arr[slot]->vec122 = 0;
    arr[slot]->vec124 = 0;
    arr[slot]->alphaValues[0] = fz430;
    arr[slot]->alphaValues[1] = fz430;
    arr[slot]->alphaValues[2] = fz430;
    arr[slot]->alphaValues[3] = fz430;
    arr[slot]->blendColorR = fz430;
    arr[slot]->blendColorG = fz430;
    arr[slot]->blendColorB = fz430;
    arr[slot]->blendColorStepR = fz430;
    arr[slot]->blendColorStepG = fz430;
    arr[slot]->blendColorStepB = fz430;
    arr[slot]->velocityX = context->vecX;
    arr[slot]->velocityY = context->vecY;
    arr[slot]->velocityZ = context->vecZ;
    gPartfxSequenceIdCounter += 1;
    if (gPartfxSequenceIdCounter > 0x4e20)
    {
        gPartfxSequenceIdCounter = 0;
    }
    arr[slot]->sequenceId = gPartfxSequenceIdCounter;
    arr[slot]->byte126 = lbl_803DD282;
    arr[slot]->vertexCount = vertexCount;
    arr[slot]->colorVertexCount = colorCount;
    arr[slot]->sourceObject = context->attachedSource;
    arr[slot]->instanceObject = NULL;
    *(u8*)&arr[slot]->sourceYawIndex = context->sourceYawIndex;
    arr[slot]->drawGroupCount = context->drawGroupCount;
    arr[slot]->drawGroupStride = context->drawGroupStride;
    arr[slot]->initialStateByte = context->initialStateByte;
    arr[slot]->soundHandle = 0;
    arr[slot]->activeVertexBufferIndex = 0;
    arr[slot]->byte13B = 0;
    arr[slot]->frameUpdated = 0;
    arr[slot]->textureFrameTimer = context->textureFrameTimer;
    if (arr[slot]->textureFrameTimer != 0)
    {
        arr[slot]->textureFrameStep =
            0x3c / arr[slot]->textureFrameTimer;
    }
    else
    {
        arr[slot]->textureFrameStep = 0;
    }
    if (arr[slot]->textureFrameStep != 0)
    {
        arr[slot]->textureFrameFadeStep =
            0xff / arr[slot]->textureFrameStep;
    }
    else
    {
        arr[slot]->textureFrameFadeStep = 0;
    }
    arr[slot]->textureFrame = 0;
    arr[slot]->initialDelayFrames = context->sourceModeCopy;
    return arr[slot]->sequenceId;
}

void dll_0B_onMapSetup(void)
{
    int i;

    partfx_freeEffectsBySequence(0, 1);
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        gPartfxActiveEffects[i] = NULL;
    }
}

void dll_0B_release(void)
{
    partfx_freeEffectsBySequence(0, 1);
}

void dll_0B_initialise(void)
{
    PartfxEffectState** arr = (PartfxEffectState**)gPartfxActiveEffects;
    int i;
    for (i = 0; i < PARTFX_ACTIVE_EFFECT_COUNT; i++)
    {
        arr[i] = NULL;
    }
}

Dll0BDescriptorTable dll_0B_funcs = {{0x00000000,
                                      0x00000000,
                                      0x00000000,
                                      0x00180000,
                                      (u32)dll_0B_initialise,
                                      (u32)dll_0B_release,
                                      0x00000000,
                                      (u32)dll_0B_onMapSetup,
                                      (u32)dll_0B_spawnEffect,
                                      (u32)dll_0B_updateActiveEffects,
                                      (u32)dll_0B_releaseAll,
                                      (u32)dll_0B_freeSourceEffects,
                                      (u32)dll_0B_detachSource,
                                      (u32)dll_0B_renderEffects,
                                      (u32)dll_0B_releaseHandle,
                                      (u32)dll_0B_func0B,
                                      (u32)dll_0B_func0C,
                                      (u32)dll_0B_func0D,
                                      (u32)dll_0B_markSourceFrameUpdated,
                                      (u32)dll_0B_beginSequence,
                                      (u32)dll_0B_resetSequenceSpawns,
                                      (u32)dll_0B_addSequenceSpawn,
                                      (u32)dll_0B_nextSequenceParam,
                                      (u32)dll_0B_setSequenceParamIndex,
                                      (u32)dll_0B_setSequenceParamValue,
                                      (u32)dll_0B_setSequenceParams,
                                      (u32)dll_0B_spawnSequence,
                                      (u32)dll_0B_addSequenceFlags,
                                      (u32)dll_0B_getLastSpawnHandle,
                                      0x00000000}};
