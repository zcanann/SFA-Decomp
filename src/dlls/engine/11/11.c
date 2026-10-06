#include "main/dll/dll_000B_dll0b.h"
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
#include "MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/modgfx_interface.h"
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
#include "main/obj_list.h"
#include "dolphin/gx/GXEnum.h"
#include "main/render_mode_api.h"
#include "main/sky.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXTransform.h"
#include "track/intersect_api.h"

void modgfx_scrollTexCoords(ModgfxEffectState* state, ModgfxCommand* in, int unusedReinit, int unusedChannel);
void modgfx_captureFrameBaseVertices(ModgfxEffectState* state, int unused);
void modgfx_stepVertexColor(ModgfxEffectState* state, ModgfxCommand* p, int reinit, int unusedChannel);
void modgfx_stepPosition(ModgfxEffectState* state, ModgfxCommand* cmd, int reinit, int unusedChannel);
void modgfx_stepS16VectorLerp(ModgfxEffectState* state, ModgfxCommand* params, int reinit, int unusedChannel);
void modgfx_stepVertexAlpha(ModgfxEffectState* state, ModgfxCommand* command, int reinit, u8 channelIndex);
void modgfx_stepVertexScale(ModgfxEffectState* state, ModgfxCommand* command, int reinit, u8 channelIndex);
void modgfx_restoreBaseVertices(ModgfxEffectState* state, void* unusedCommand, int unusedReinit);

ModgfxCommand* gModgfxCommandStartCursor;
ModgfxCommand* gModgfxCommandWriteCursor;
s16 gModgfxStageIndex;
s16 gModgfxLastSpawnHandle;
f32 gModgfxMotionStep;
u8 gModgfxSpawnGeneration;
s16 gModgfxSequenceIdCounter;

/* Object spawned to back a modgfx effect slot; retail OBJECTS.bin name
   "InvHit" (DLL 0xF1). */
#define MODGFX_CHILD_OBJ_INVHIT 0x66

#define MODGFX_ACTIVE_EFFECT_COUNT 0x32

ModgfxSpawnContext gModgfxSpawnContext;
ModgfxCommand gModgfxCommandQueue[0x20];
void modgfx_freeEffectsBySequence(s16 sequenceId, int forceAll);
#define MODGFX_ZERO 0.0f
#define MODGFX_ONE  1.0f

s16 modgfx_spawnEffect(ModgfxSpawnContext* context, int unused, int vertexCount, ModgfxEffectVertex* vertexData,
                       int triangleCount, s16* triangleIndices, int textureAssetId, Texture* textureResource);

s16 modgfx_getLastSpawnHandle(void) {
    return gModgfxLastSpawnHandle;
}

void modgfx_addSequenceFlags(u32 flags) {
    gModgfxSpawnContext.flags |= flags;
}

void modgfx_spawnSequence(PartFxSpawnParams* spawnParams, ModgfxEffectVertex* vertices, int vertexCount,
                          s16* triangleIndices, int triangleCount, int textureAssetId, Texture* texture) {
    gModgfxSpawnContext.commands = gModgfxCommandQueue;
    gModgfxSpawnContext.commandCount = gModgfxCommandWriteCursor - gModgfxCommandStartCursor;
    if (texture == NULL && textureAssetId == 0) {
        gModgfxSpawnContext.flags |= 0x2000000;
    } else {
        gModgfxSpawnContext.flags |= 0x4000000;
    }
    if (gModgfxSpawnContext.flags & 1) {
        if (gModgfxSpawnContext.sourceObject != NULL) {
            gModgfxSpawnContext.position[0] += gModgfxSpawnContext.sourceObject->anim.worldPosX;
            gModgfxSpawnContext.position[1] += gModgfxSpawnContext.sourceObject->anim.worldPosY;
            gModgfxSpawnContext.position[2] += gModgfxSpawnContext.sourceObject->anim.worldPosZ;
        } else {
            gModgfxSpawnContext.position[0] += spawnParams->posX;
            gModgfxSpawnContext.position[1] += spawnParams->posY;
            gModgfxSpawnContext.position[2] += spawnParams->posZ;
        }
    }
    gModgfxLastSpawnHandle = modgfx_spawnEffect(&gModgfxSpawnContext, 0, vertexCount, vertices, triangleCount,
                                                triangleIndices, textureAssetId, texture);
}

void modgfx_setStageDurations(s16* params) {
    memcpy(gModgfxSpawnContext.stageDurations, params, sizeof(gModgfxSpawnContext.stageDurations));
}

void modgfx_setStageDuration(s16 value) {
    gModgfxSpawnContext.stageDurations[gModgfxStageIndex] = value;
}

void modgfx_setStageIndex(s16 x) {
    gModgfxStageIndex = x;
}

void modgfx_nextStage(void) {
    gModgfxStageIndex++;
}

void modgfx_addSequenceCommand(int flags, float valueX, float valueY, float valueZ, s16 parameter, s16* vertexIndices) {
    u32 stageIndex = gModgfxStageIndex;
    gModgfxCommandWriteCursor->stageIndex = stageIndex;
    gModgfxCommandWriteCursor->parameter = parameter;
    gModgfxCommandWriteCursor->vertexIndices = vertexIndices;
    gModgfxCommandWriteCursor->flags = flags;
    gModgfxCommandWriteCursor->valueX = valueX;
    gModgfxCommandWriteCursor->valueY = valueY;
    gModgfxCommandWriteCursor->valueZ = valueZ;
    gModgfxCommandWriteCursor++;
}

void modgfx_resetSequenceCommands(void) {
    ModgfxCommand* cursor = gModgfxCommandQueue;
    gModgfxCommandStartCursor = cursor;
    gModgfxCommandWriteCursor = cursor;
    gModgfxStageIndex = 0;
}

void modgfx_beginSequence(GameObject* source, u8 variant, u8 initialStateByte, int drawGroupCount,
                          int drawGroupStride) {
    f32 fz;
    f32 fz2;
    memset(&gModgfxSpawnContext, 0, sizeof(gModgfxSpawnContext));
    gModgfxSpawnContext.modeByte = variant;
    gModgfxSpawnContext.sourceObject = source;
    gModgfxSpawnContext.variant = variant;
    fz = MODGFX_ZERO;
    gModgfxSpawnContext.position[0] = fz;
    gModgfxSpawnContext.position[1] = fz;
    gModgfxSpawnContext.position[2] = fz;
    gModgfxSpawnContext.velocity[0] = fz;
    gModgfxSpawnContext.velocity[1] = fz;
    gModgfxSpawnContext.velocity[2] = fz;
    fz2 = MODGFX_ONE;
    gModgfxSpawnContext.scale = fz2;
    gModgfxSpawnContext.drawGroupCount = drawGroupCount;
    gModgfxSpawnContext.drawGroupStride = drawGroupStride;
    gModgfxSpawnContext.initialStateByte = initialStateByte;
    gModgfxSpawnContext.byte5A = 0;
    gModgfxSpawnContext.textureFrameTimer = 0;
}

/* Per-bone particle vertex update + draw. */

void modgfx_scrollTexCoords(ModgfxEffectState* state, ModgfxCommand* in, int unusedReinit, int unusedChannel) {
    int i;
    s32 dy, dx;
    LightmapVertex* slot;
    LightmapVertex* cur;
    LightmapVertex* prev;
    u8 ovx, ovy;
    int j;

    dx = (s32)(4.0f * (in->valueX * gModgfxMotionStep));
    dy = (s32)(4.0f * (in->valueY * gModgfxMotionStep));

    cur = state->vertexBuffers[state->activeVertexBufferIndex];
    prev = state->vertexBuffers[1 - state->activeVertexBufferIndex];

    ovx = 0;
    ovy = 0;
    for (i = 0; i < state->vertexCount; i++) {
        cur->s = prev->s;
        cur->t = prev->t;
        cur->s = (s16)(cur->s + dx);
        if ((s32)cur->s > 0x100) {
            ovx++;
        }
        if ((s32)cur->s < -0x100) {
            ovx++;
        }
        cur->t = (s16)(cur->t + dy);
        if ((s32)cur->t > 0x100) {
            ovy++;
        }
        if ((s32)cur->t < -0x100) {
            ovy++;
        }
        cur++;
        prev++;
    }

    slot = state->vertexBuffers[state->activeVertexBufferIndex];
    for (j = 0; j < state->vertexCount; j++) {
        if ((s32)ovx == state->vertexCount) {
            if ((s32)slot->s > 0x100) {
                slot->s -= 0x100;
            } else {
                slot->s += 0x100;
            }
        }
        if ((s32)ovy == state->vertexCount) {
            if ((s32)slot->t > 0x100) {
                slot->t -= 0x100;
            } else {
                slot->t += 0x100;
            }
        }
        slot++;
    }
}

ModgfxEffectState* gModgfxActiveEffects[MODGFX_ACTIVE_EFFECT_COUNT];

void modgfx_captureFrameBaseVertices(ModgfxEffectState* state, int unused) {
    int i;
    LightmapVertex* dst;
    LightmapVertex* src;
    f32 one;
    f32 zero;
    src = state->vertexBuffers[1 - state->activeVertexBufferIndex];
    dst = state->vertexBuffers[2];
    for (i = 0; i < state->vertexCount; i++) {
        dst->x = src->x;
        dst->y = src->y;
        dst->z = src->z;
        dst->r = src->r;
        dst->g = src->g;
        dst->b = src->b;
        dst->a = src->a;
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

void modgfx_stepVertexColor(ModgfxEffectState* state, ModgfxCommand* p, int reinit, int unusedChannel) {
    LightmapVertex* vertices = state->vertexBuffers[state->activeVertexBufferIndex];
    int j;

    if (reinit == 1) {
        f32 tr = p->valueX;
        f32 tg = p->valueY;
        f32 tb = p->valueZ;
        if (state->stageFrameCountdown != 0) {
            state->blendColorR = (f32)(u32)vertices[p->vertexIndices[0]].r;
            state->blendColorG = (f32)(u32)vertices[p->vertexIndices[0]].g;
            state->blendColorB = (f32)(u32)vertices[p->vertexIndices[0]].b;
            state->blendColorStepR = (tr - (f32)(u32)vertices[p->vertexIndices[0]].r) / (f32)state->stageFrameCountdown;
            state->blendColorStepG = (tg - (f32)(u32)vertices[p->vertexIndices[0]].g) / (f32)state->stageFrameCountdown;
            state->blendColorStepB = (tb - (f32)(u32)vertices[p->vertexIndices[0]].b) / (f32)state->stageFrameCountdown;
        } else {
            state->blendColorR = tr;
            state->blendColorG = tg;
            state->blendColorB = tb;
            {
                f32 z = MODGFX_ZERO;
                state->blendColorStepR = z;
                state->blendColorStepG = z;
                state->blendColorStepB = z;
            }
        }
    }
    state->blendColorR += state->blendColorStepR;
    state->blendColorG += state->blendColorStepG;
    state->blendColorB += state->blendColorStepB;
    if (state->blendColorR < MODGFX_ZERO) {
        state->blendColorR = MODGFX_ZERO;
    } else if (state->blendColorR > 255.0f) {
        state->blendColorR = 255.0f;
    }
    if (state->blendColorG < MODGFX_ZERO) {
        state->blendColorG = MODGFX_ZERO;
    } else if (state->blendColorG > 255.0f) {
        state->blendColorG = 255.0f;
    }
    if (state->blendColorB < MODGFX_ZERO) {
        state->blendColorB = MODGFX_ZERO;
    } else if (state->blendColorB > 255.0f) {
        state->blendColorB = 255.0f;
    }
    for (j = 0; j < p->parameter; j++) {
        vertices[p->vertexIndices[j]].r = (int)state->blendColorR;
        vertices[p->vertexIndices[j]].g = (int)state->blendColorG;
        vertices[p->vertexIndices[j]].b = (int)state->blendColorB;
    }
}

void modgfx_stepPosition(ModgfxEffectState* state, ModgfxCommand* cmd, int reinit, int unusedChannel) {

    if (reinit == 1) {
        s16* cf = state->stageDurations;
        if (cf[state->currentStage] == 0) {
            int flags = state->flags;
            if ((flags & 0x4) != 0 || (flags & 0x80000) != 0) {
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
        } else {
            state->posStepX = cmd->valueX / (f32)(s32)state->stageFrameCountdown;
            state->posStepY = cmd->valueY / (f32)(s32)state->stageFrameCountdown;
            state->posStepZ = cmd->valueZ / (f32)(s32)state->stageFrameCountdown;
        }
        state->drawPosX += state->posStepX;
        state->drawPosY += state->posStepY;
        state->drawPosZ += state->posStepZ;
    } else {
        state->drawPosX = state->posStepX * gModgfxMotionStep + state->drawPosX;
        state->drawPosY = state->posStepY * gModgfxMotionStep + state->drawPosY;
        state->drawPosZ = state->posStepZ * gModgfxMotionStep + state->drawPosZ;
    }
}

/* Integer-vector lerp setup. On the reinit step, snap or step-interpolate the rotation offset triple
 * toward the rounded params, then advance it by the per-step delta. */
void modgfx_stepS16VectorLerp(ModgfxEffectState* state, ModgfxCommand* params, int reinit, int unusedChannel) {
    if (reinit == 1) {
        s16 tx = params->valueX;
        s16 ty = params->valueY;
        s16 tz = params->valueZ;
        if (state->stageFrameCountdown != 0) {
            state->rotStepZ = (s16)((tx - state->rotOffsetZ) / state->stageFrameCountdown);
            state->rotStepY = (s16)((ty - state->rotOffsetY) / state->stageFrameCountdown);
            state->rotStepX = (s16)((tz - state->rotOffsetX) / state->stageFrameCountdown);
        } else {
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

void modgfx_stepVertexAlpha(ModgfxEffectState* state, ModgfxCommand* command, int reinit, u8 channelIndex) {
    int alphaIndex = channelIndex * 2;
    LightmapVertex* vertices = state->vertexBuffers[state->activeVertexBufferIndex];
    LightmapVertex* baseVertices = state->vertexBuffers[2];
    int i;

    if (reinit == 1) {
        f32 target = command->valueX;
        s16 frames = state->stageFrameCountdown;

        if (frames != 0) {
            state->alphaValues[alphaIndex] = (target - (f32)baseVertices[command->vertexIndices[0]].a) / frames;
            state->alphaValues[alphaIndex + 1] = (f32)baseVertices[command->vertexIndices[0]].a;
        } else {
            for (i = 0; i < command->parameter; i++) {
                baseVertices[command->vertexIndices[i]].a = target;
                vertices[command->vertexIndices[i]].a = baseVertices[command->vertexIndices[i]].a;
            }
            return;
        }
    }

    state->alphaValues[alphaIndex + 1] += state->alphaValues[alphaIndex] * gModgfxMotionStep;
    if (state->alphaValues[alphaIndex + 1] < 0.0f) {
        state->alphaValues[alphaIndex + 1] = 0.0f;
    } else if (state->alphaValues[alphaIndex + 1] > 255.0f) {
        state->alphaValues[alphaIndex + 1] = 255.0f;
    }

    for (i = 0; i < command->parameter; i++) {
        vertices[command->vertexIndices[i]].a = state->alphaValues[alphaIndex + 1];
        baseVertices[command->vertexIndices[i]].a = vertices[command->vertexIndices[i]].a;
    }
}

void modgfx_stepVertexScale(ModgfxEffectState* state, ModgfxCommand* command, int reinit, u8 channelIndex) {
    int scaleIndex = channelIndex * 2;
    int i;
    LightmapVertex* vertices;
    LightmapVertex* baseVertices;

    if (reinit == 1) {
        f32 targetX = command->valueX;
        f32 targetY = command->valueY;
        f32 targetZ = command->valueZ;

        if (state->stageFrameCountdown != 0) {
            state->scaleVectors[scaleIndex + 1].x =
                (targetX - state->scaleVectors[scaleIndex].x) / (f32)state->stageFrameCountdown;
            state->scaleVectors[scaleIndex + 1].y =
                (targetY - state->scaleVectors[scaleIndex].y) / (f32)state->stageFrameCountdown;
            state->scaleVectors[scaleIndex + 1].z =
                (targetZ - state->scaleVectors[scaleIndex].z) / (f32)state->stageFrameCountdown;
        } else {
            baseVertices = state->vertexBuffers[2];
            vertices = state->vertexBuffers[state->activeVertexBufferIndex];

            for (i = 0; i < command->parameter; i++) {
                baseVertices[command->vertexIndices[i]].x *= targetX;
                baseVertices[command->vertexIndices[i]].y *= targetY;
                baseVertices[command->vertexIndices[i]].z *= targetZ;
                vertices[command->vertexIndices[i]].x = baseVertices[command->vertexIndices[i]].x;
                vertices[command->vertexIndices[i]].y = baseVertices[command->vertexIndices[i]].y;
                vertices[command->vertexIndices[i]].z = baseVertices[command->vertexIndices[i]].z;
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

        for (i = 0; i < command->parameter; i++) {
            if (state->scaleVectors[scaleIndex].x != 1.0f) {
                vertices[command->vertexIndices[i]].x =
                    state->scaleVectors[scaleIndex].x * baseVertices[command->vertexIndices[i]].x;
            }
            if (state->scaleVectors[scaleIndex].y != 1.0f) {
                vertices[command->vertexIndices[i]].y =
                    state->scaleVectors[scaleIndex].y * baseVertices[command->vertexIndices[i]].y;
            }
            if (state->scaleVectors[scaleIndex].z != 1.0f) {
                vertices[command->vertexIndices[i]].z =
                    state->scaleVectors[scaleIndex].z * baseVertices[command->vertexIndices[i]].z;
            }
        }
    }
}

void modgfx_restoreBaseVertices(ModgfxEffectState* state, void* unusedCommand, int unusedReinit) {
    int i;
    LightmapVertex* src;
    LightmapVertex* dst = state->vertexBuffers[state->activeVertexBufferIndex];
    src = state->vertexBuffers[2];
    for (i = 0; i < state->vertexCount; i++) {
        dst->x = src->x;
        dst->y = src->y;
        dst->z = src->z;
        dst->r = src->r;
        dst->g = src->g;
        dst->b = src->b;
        dst->a = src->a;
        dst++;
        src++;
    }
}

void modgfx_freeEffectsBySequence(s16 sequenceId, int forceAll) {
    ModgfxEffectState** arr = gModgfxActiveEffects;
    int i;
    for (i = 0; i < MODGFX_ACTIVE_EFFECT_COUNT; i++) {
        if (arr[i] == NULL) {
            continue;
        }
        if (sequenceId != arr[i]->sequenceId && forceAll == 0) {
            continue;
        }
        if (arr[i]->auxAllocation != NULL) {
            mm_free(arr[i]->auxAllocation);
        }
        if (arr[i]->instanceObject != NULL) {
            Obj_FreeObject(arr[i]->instanceObject);
        }
        arr[i]->inlineData = NULL;
        if (arr[i]->textureIsBorrowed == 0 && arr[i]->textureResource != NULL) {
            textureFree((Texture*)(arr[i]->textureResource));
        }
        if (arr[i]->textureIsBorrowed == 0) {
            arr[i]->textureResource = NULL;
        }
        mm_free(arr[i]);
        arr[i] = NULL;
    }
}
/* Flag every active effect whose owner object has the 0x800 state bit
 * by setting its frameUpdated flag. */
void modgfx_markSourceFrameUpdated(void* unused) {
    ModgfxEffectState* effect;
    GameObject* sourceObject;
    int i;
    ModgfxEffectState** effects = gModgfxActiveEffects;

    for (i = 0; i < MODGFX_ACTIVE_EFFECT_COUNT; i++) {
        effect = effects[i];
        if (effect != NULL) {
            sourceObject = effect->sourceObject;
            if (sourceObject != NULL && (sourceObject->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
                effect->frameUpdated = 1;
            }
        }
    }
}

void modgfx_requestSourceRelease(GameObject* source) {
    ModgfxEffectState** arr = gModgfxActiveEffects;
    int i;
    for (i = 0; i < MODGFX_ACTIVE_EFFECT_COUNT; i++) {
        if (arr[i] != NULL && arr[i]->sourceObject == source) {
            arr[i]->releaseRequested = 1;
        }
    }
}

void modgfx_setSourceByte13B(GameObject* source, char value) {
    ModgfxEffectState** arr = gModgfxActiveEffects;
    int i;
    for (i = 0; i < MODGFX_ACTIVE_EFFECT_COUNT; i++) {
        if (arr[i] != NULL && arr[i]->sourceObject == source) {
            arr[i]->byte13B = value;
        }
    }
}
void modgfx_nextSpawnGeneration(void) {
    gModgfxSpawnGeneration++;
}

void modgfx_releaseHandle(s16* p) {
    ModgfxEffectState** arr = gModgfxActiveEffects;
    int i;
    for (i = 0; i < MODGFX_ACTIVE_EFFECT_COUNT; i++) {
        if (arr[i] != NULL && *p == arr[i]->sequenceId) {
            arr[i]->releaseRequested = 1;
        }
    }
    *p = -1;
}

int modgfx_renderEffects(void* drawContext, int unused1, int unused2, u8 sourceOnly, GameObject* sourceObject) {
    u8 ar;
    u8 ag;
    u8 ab;
    f32 pos[3];
    f32 rot[3];
    MatrixTransform xf;
    Mtx44 mtxB;
    Mtx mtxA;
    ModgfxEffectState** p;
    int slot;
    Camera* view;
    u8 textureFrameCount;
    LightmapVertex* vertexBuffer;
    LightmapTriangle* triangleBuffer;
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
        skyGetSunColor(sourceObject->lightColorSlot, &ar, &ag, &ab);
    } else {
        skyGetSunColor(0, &ar, &ag, &ab);
    }
    GXSetCullMode(GX_CULL_NONE);
    if (renderModeSetOrGet(-1) == 1) {
        return 1;
    }
    view = Camera_GetCurrent();
    p = gModgfxActiveEffects;
    for (slot = 0; slot < MODGFX_ACTIVE_EFFECT_COUNT; slot++) {
        if (p[slot] == NULL) {
            continue;
        }
        if (p[slot]->sequenceId == -1) {
            continue;
        }
        if (sourceOnly) {
            if (((int)p[slot]->flags & 0x2000) == 0) {
                continue;
            }
        }
        if (sourceOnly) {
            if (p[slot]->sourceObject != sourceObject) {
                continue;
            }
        }
        if (!sourceOnly) {
            if ((int)p[slot]->flags & 0x2000) {
                continue;
            }
        }
        if ((int)p[slot]->flags & 0x800) {
            p[slot]->frameUpdated = 0;
        }
        aligned = 0;
        vertexBuffer = p[slot]->vertexBuffers[p[slot]->activeVertexBufferIndex];
        triangleBuffer = p[slot]->triangleBuffers[p[slot]->activeVertexBufferIndex];
        xf.x = MODGFX_ZERO;
        xf.y = MODGFX_ZERO;
        xf.z = MODGFX_ZERO;
        xf.scale = MODGFX_ONE;
        xf.rotZ = 0;
        xf.rotY = 0;
        pos[0] = p[slot]->drawPosX;
        pos[1] = p[slot]->drawPosY;
        pos[2] = p[slot]->drawPosZ;
        if ((int)p[slot]->flags & 0x4) {
            if (MODGFX_ZERO == pos[2] + (pos[0] + pos[1])) {
                aligned = 1;
            }
        }
        if ((int)p[slot]->flags & 0x4) {
            if (!aligned) {
                if (p[slot]->sourceObject != NULL) {
                    xf.rotX = p[slot]->sourceObject->anim.rotX;
                    xf.rotY = p[slot]->sourceObject->anim.rotY;
                    xf.rotZ = p[slot]->sourceObject->anim.rotZ;
                    vecRotateZXY(&xf.rotX, &pos[0]);
                }
            }
        }
        rot[0] = MODGFX_ZERO;
        rot[1] = MODGFX_ZERO;
        rot[2] = MODGFX_ZERO;
        if (((int)p[slot]->flags & 1) == 0) {
            if (p[slot]->sourceObject != NULL) {
                rot[0] = p[slot]->sourceObject->anim.worldPosX;
                rot[1] = p[slot]->sourceObject->anim.worldPosY;
                rot[2] = p[slot]->sourceObject->anim.worldPosZ;
            } else {
                rot[0] = p[slot]->sourceTransform.posX;
                rot[1] = p[slot]->sourceTransform.posY;
                rot[2] = p[slot]->sourceTransform.posZ;
                Obj_RotateLocalOffsetByYaw(&p[slot]->sourceTransform.posX, &rot[0], p[slot]->sourceYawIndex);
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
        if ((int)p[slot]->flags & 0x400000) {
            dscale = 0.5f * p[slot]->renderScale;
            xf.scale = dscale + dscale / randomGetRange(1, 10);
        } else {
            xf.scale = 0.01f * p[slot]->renderScale;
        }
        if ((int)p[slot]->flags & 0x80000) {
            xf.rotZ = p[slot]->sourceObject->anim.rotZ;
            xf.rotY = p[slot]->sourceObject->anim.rotY;
            xf.rotX = p[slot]->sourceObject->anim.rotX;
        } else if (aligned && p[slot]->sourceObject != NULL) {
            xf.rotZ = p[slot]->rotOffsetZ + p[slot]->sourceObject->anim.rotZ;
            xf.rotY = p[slot]->rotOffsetY + p[slot]->sourceObject->anim.rotY;
            xf.rotX = p[slot]->rotOffsetX + p[slot]->sourceObject->anim.rotX;
        } else if (aligned) {
            xf.rotZ = p[slot]->rotOffsetZ + p[slot]->sourceTransform.rotZ;
            xf.rotY = p[slot]->rotOffsetY + p[slot]->sourceTransform.rotY;
            xf.rotX = p[slot]->rotOffsetX + p[slot]->sourceTransform.rotX;
        } else {
            xf.rotZ = p[slot]->rotOffsetZ;
            xf.rotY = p[slot]->rotOffsetY;
            xf.rotX = p[slot]->rotOffsetX;
        }
        if ((int)p[slot]->flags & 0x1000) {
            if (p[slot]->sourceObject != NULL) {
                dirX = view->worldX - p[slot]->sourceObject->anim.worldPosX;
                dirZ = view->worldZ - p[slot]->sourceObject->anim.worldPosZ;
                dscale = sqrtf(dirX * dirX + dirZ * dirZ);
                if (dscale) {
                    dirX /= dscale;
                    dirZ /= dscale;
                }
                dscale = (u16)getAngle(dirX, dirZ);
                xf.rotX += (s16)dscale;
            }
        }
        xf.x -= playerMapOffsetX;
        xf.z -= playerMapOffsetZ;
        setMatrixFromObjectPos(mtxB[0], &xf);
        mtx44Transpose(mtxB[0], mtxA[0]);
        PSMTXConcat((MtxPtr)Camera_GetViewMatrix(), mtxA, mtxA);
        GXLoadPosMtxImm(mtxA, GX_PNMTX0);
        texture = p[slot]->textureResource;
        if (texture != NULL) {
            textureFrameCount = (u8)(texture->animationFrameCountFixed >> 8);
        }
        if (texture != NULL && p[slot]->textureFrameTimer != 0) {
            p[slot]->textureFrameStep -= 1;
            if (p[slot]->textureFrameStep == 0) {
                p[slot]->textureFrameStep = 0x3c / p[slot]->textureFrameTimer;
                p[slot]->textureFrame += 1;
                if (p[slot]->textureFrame >= (u32)textureFrameCount) {
                    p[slot]->textureFrame = 0;
                }
            }
        }
        if ((int)p[slot]->flags & 0x10000000) {
            setTextColor(drawContext, ar, ag, ab, 0xff);
        } else if (p[slot]->sourceObject != NULL && ((int)p[slot]->flags & 0x4000)) {
            setTextColor(drawContext, 0xff, 0xff, 0xff, p[slot]->sourceObject->anim.renderAlpha);
        } else {
            setTextColor(drawContext, 0xff, 0xff, 0xff, 0xff);
        }
        texture = p[slot]->textureResource;
        if (texture != NULL) {
            textureFrame = p[slot]->textureFrame;
            nextTextureFrame = (textureFrame + 1) & 0xff;
            if (nextTextureFrame > textureFrameCount - 1) {
                nextTextureFrame = 0;
            }
        }
        if (((int)p[slot]->flags & 0x1000000) && (p[slot]->frameUpdated != 0 || ((int)p[slot]->flags & 0x400))) {
            {
                for (frameIndex = 0; frameIndex < (nextTextureFrame & 0xff); frameIndex++) {
                    texture = texture->nextAnimationFrame;
                }
                _textSetColor(drawContext, 0xff, 0xff, 0xff,
                              (u8)(0xff - p[slot]->textureFrameStep * p[slot]->textureFrameFadeStep));
                gxTevResetStages();
                gxTevAddTextureFrameBlendStages();
                gxTevModulateRasStage();
                gxTevCommitStages();
                selectTexture(texture, 1);
            }
        } else if ((int)p[slot]->flags & 0x2000000) {
            gxTevResetStages();
            gxTevRasTimesColor1Stage();
            gxTevCommitStages();
        } else if ((int)p[slot]->flags & 0x4000000) {
            gxTevResetStages();
            gxTevTextureTimesRasStage();
            gxTevModulateColor1Stage();
            gxTevCommitStages();
        }
        if (((int)p[slot]->flags & 0x05000000) && (p[slot]->frameUpdated != 0 || ((int)p[slot]->flags & 0x400))) {
            {
                texture = p[slot]->textureResource;
                for (frameIndex = 0; frameIndex < (textureFrame & 0xff); frameIndex++) {
                    texture = texture->nextAnimationFrame;
                }
                selectTexture(texture, 0);
            }
        }
        if ((int)p[slot]->flags & 0x100) {
            gxSetAlphaBlendZTest();
        } else if (((int)p[slot]->flags & 0x10) && ((int)p[slot]->flags & 0x80)) {
            gxSetAlphaBlendNoZTest();
        } else if ((int)p[slot]->flags & 0x80) {
            gxSetAlphaBlendZTest();
        } else if ((int)p[slot]->flags & 0x10) {
            gxSetAlphaBlendNoZTest();
        } else {
            gxSetAlphaBlendZTest();
        }
        if ((int)p[slot]->flags & 0x40) {
            GXSetCullMode(GX_CULL_FRONT);
        } else {
            GXSetCullMode(GX_CULL_NONE);
        }
        if (p[slot]->frameUpdated != 0 || ((int)p[slot]->flags & 0x400)) {
            int di;
            for (di = 0; di < p[slot]->drawGroupCount; di++) {
                if ((int)p[slot]->flags & 0x8000000) {
                    lightmapDrawTriangleList(vertexBuffer, (u8*)triangleBuffer,
                                             p[slot]->triangleCount / p[slot]->drawGroupCount);
                } else {
                    lightmapDrawTriangleList(vertexBuffer, (u8*)triangleBuffer, p[slot]->triangleCount);
                }
                vertexBuffer += p[slot]->drawGroupStride;
                if ((int)p[slot]->flags & 0x8000000) {
                    triangleBuffer += p[slot]->triangleCount / p[slot]->drawGroupCount;
                }
            }
        }
        Rcp_ResetRenderState();
        p[slot]->activeVertexBufferIndex = 1 - p[slot]->activeVertexBufferIndex;
    }
    return 0;
}

void modgfx_detachSource(GameObject* param) {
    ModgfxEffectState** arr = gModgfxActiveEffects;
    int i;

    for (i = 0; i < MODGFX_ACTIVE_EFFECT_COUNT; i++) {
        if (arr[i] != NULL && arr[i]->sourceObject == param) {
            if ((int)arr[i]->flags & 0x10000) {
                modgfx_freeEffectsBySequence(arr[i]->sequenceId, 0);
            } else {
                arr[i]->sourceTransform.posX = arr[i]->sourceObject->anim.worldPosX;
                arr[i]->sourceTransform.posY = arr[i]->sourceObject->anim.worldPosY;
                arr[i]->sourceTransform.posZ = arr[i]->sourceObject->anim.worldPosZ;
                arr[i]->sourceTransform.scale = arr[i]->sourceObject->anim.rootMotionScale;
                arr[i]->sourceTransform.rotZ = arr[i]->sourceObject->anim.rotZ;
                arr[i]->sourceTransform.rotY = arr[i]->sourceObject->anim.rotY;
                arr[i]->sourceTransform.rotX = arr[i]->sourceObject->anim.rotX;
                if ((int)arr[i]->flags & 0x2) {
                    arr[i]->velocityX += arr[i]->sourceObject->anim.velocityX;
                    arr[i]->velocityY += arr[i]->sourceObject->anim.velocityY;
                    arr[i]->velocityZ += arr[i]->sourceObject->anim.velocityZ;
                }
                if (!((int)arr[i]->flags & 0x200000)) {
                    arr[i]->flags |= 0x200000u;
                }
                arr[i]->sourceObject = 0;
            }
        }
    }
}

void modgfx_freeSourceEffects(GameObject* source) {
    ModgfxEffectState** arr = gModgfxActiveEffects;
    int i;
    for (i = 0; i < MODGFX_ACTIVE_EFFECT_COUNT; i++) {
        if (arr[i] == NULL) {
            continue;
        }
        if (arr[i]->sourceObject != source) {
            continue;
        }
        if (arr[i]->instanceObject != NULL) {
            Obj_FreeObject(arr[i]->instanceObject);
        }
        arr[i]->inlineData = NULL;
        if (arr[i]->textureIsBorrowed == 0 && arr[i]->textureResource != NULL) {
            textureFree((Texture*)(arr[i]->textureResource));
        }
        if (arr[i]->textureIsBorrowed == 0) {
            arr[i]->textureResource = NULL;
        }
        mm_free(arr[i]);
        arr[i] = NULL;
    }
}

static inline int modgfx_findFreeEffectSlot(ModgfxEffectState** p, int found, int i) {
    for (; i < MODGFX_ACTIVE_EFFECT_COUNT && found == 0; p++, i++) {
        if (*p == NULL) {
            found = 1;
        }
    }
    if (found) {
        return i - 1;
    }
    return -1;
}

void modgfx_releaseAll(void) {
    modgfx_freeEffectsBySequence(0, 1);
}

#define PENDING_SPAWNS ((char*)eff->emitterCommands)

void modgfx_updateActiveEffects(int unused0, int unused1, int unused2) {
    ModgfxCommand* spawnCommand;
    struct {
        int commandIndex;
        int byteOffset;
    } cursor;

    ModgfxEffectState* eff;
    int reprocess;
    int active;
    ModgfxEffectState** pp;
    int slot;
    int feFlag;
    int alphaGroupIndex;
    int scaleGroupIndex;
    int k;
    ModgfxResource* res;
    PartFxSpawnParams tmpl;
    Vec3f* spawnPosition;
    MatrixTransform rot;
    int objCount;
    int objIdx;

    cursor.commandIndex = 0;
    gExpgfxUpdatingActivePools = 2;
    if (renderModeSetOrGet(-1) == 1) {
        return;
    }
    gModgfxMotionStep = timeDelta;
    pp = gModgfxActiveEffects;
    for (slot = 0; slot < MODGFX_ACTIVE_EFFECT_COUNT; slot++) {
        reprocess = 1;
        while (reprocess) {
            spawnPosition = &tmpl.pos;
            reprocess = 0;
            eff = pp[slot];
            if (eff == NULL) {
                continue;
            }
            if (eff->sequenceId == -1) {
                continue;
            }
            active = 0;
            eff->frameUpdated = 0;
            if (eff->stageFrameCountdown < 0 || eff->currentStage == -1) {
                eff->currentStage += 1;
                if (eff->currentStage > 6) {
                    modgfx_freeEffectsBySequence(eff->sequenceId, 0);
                    break;
                }
                eff->stageFrameCountdown = eff->stageDurations[eff->currentStage];
                active = 1;
                modgfx_captureFrameBaseVertices(eff, 0);
            } else if (eff->requestedStage != 0) {
                eff->currentStage = eff->requestedStage;
                eff->requestedStage = 0;
                if (eff->currentStage > 6) {
                    modgfx_freeEffectsBySequence(eff->sequenceId, 0);
                    break;
                }
                eff->stageFrameCountdown = eff->stageDurations[eff->currentStage];
                active = 1;
                modgfx_captureFrameBaseVertices(eff, 0);
            }
            scaleGroupIndex = 0;
            alphaGroupIndex = 0;
            modgfx_restoreBaseVertices(eff, PENDING_SPAWNS + cursor.commandIndex * sizeof(ModgfxCommand), active);
            feFlag = 0;
            for (cursor.byteOffset = cursor.commandIndex = 0; cursor.commandIndex < eff->emitterCount;
                 cursor.byteOffset += sizeof(ModgfxCommand), cursor.commandIndex++) {

                int flags;

                if (eff->currentStage !=
                    ((ModgfxCommand*)((u8*)eff->emitterCommands + cursor.byteOffset))->stageIndex) {
                    continue;
                }
                flags = ((ModgfxCommand*)((u8*)eff->emitterCommands + cursor.byteOffset))->flags;
                if ((flags & 0x1000) &&
                    ((ModgfxCommand*)((u8*)eff->emitterCommands + cursor.byteOffset))->valueX > MODGFX_ZERO &&
                    eff->currentStage > 0) {
                    eff->currentStage =
                        ((ModgfxCommand*)(PENDING_SPAWNS + cursor.commandIndex * sizeof(ModgfxCommand)))->parameter;
                    ((ModgfxCommand*)(PENDING_SPAWNS + cursor.commandIndex * sizeof(ModgfxCommand)))->valueX =
                        ((ModgfxCommand*)(PENDING_SPAWNS + cursor.commandIndex * sizeof(ModgfxCommand)))->valueX -
                        MODGFX_ONE;
                    eff->stageFrameCountdown = -1;
                    break;
                }
                if (flags & 0x2000) {
                    if (eff->releaseRequested != 0) {
                        eff->releaseRequested = 0;
                        ((ModgfxCommand*)(PENDING_SPAWNS + cursor.commandIndex * sizeof(ModgfxCommand)))->flags = 0;
                        ((ModgfxCommand*)(PENDING_SPAWNS + cursor.commandIndex * sizeof(ModgfxCommand)))->flags = 0x20;
                        eff->stageFrameCountdown = -1;
                        reprocess = 1;
                        feFlag = 0;
                        break;
                    }
                    if (eff->currentStage > 0) {
                        feFlag = 1;
                        eff->currentStage = (eff->emitterCommands + cursor.commandIndex)->parameter;
                        eff->stageFrameCountdown = -1;
                        reprocess = 1;
                        break;
                    }
                }
                if (flags & 0x10000000) {
                    tmpl.posX = eff->drawPosX;
                    tmpl.posY = eff->drawPosY;
                    tmpl.posZ = eff->drawPosZ;
                    rot.x = MODGFX_ZERO;
                    rot.y = MODGFX_ZERO;
                    rot.z = MODGFX_ZERO;
                    rot.scale = MODGFX_ONE;
                    if ((int)eff->flags & 1) {
                        rot.rotX = eff->sourceTransform.rotX;
                    } else {
                        rot.rotX = eff->sourceObject->anim.rotX;
                    }
                    rot.rotY = 0;
                    rot.rotZ = 0;
                    vecRotateZXY(&rot.rotX, (f32*)spawnPosition);
                    if (eff->instanceObject == NULL && (u8)Obj_CanSetupObject()) {
                        ObjPlacement* o;
                        if (((int)eff->flags & 1) == 0) {
                            tmpl.posX = eff->sourceObject->anim.worldPosX + tmpl.posX;
                            tmpl.posY = eff->sourceObject->anim.worldPosY + tmpl.posY;
                            tmpl.posZ = eff->sourceObject->anim.worldPosZ + tmpl.posZ;
                        } else {
                            tmpl.posX = eff->sourceTransform.posX + tmpl.posX;
                            tmpl.posY = eff->sourceTransform.posY + tmpl.posY;
                            tmpl.posZ = eff->sourceTransform.posZ + tmpl.posZ;
                        }
                        o = Obj_AllocObjectSetup(0x20, MODGFX_CHILD_OBJ_INVHIT);
                        o->posX = tmpl.posX;
                        o->posY = tmpl.posY;
                        o->posZ = tmpl.posZ;
                        eff->instanceObject = objSetupObject(o, 5, -1, -1, NULL);
                        eff->instanceObject->userData2 = 1;
                    } else if (eff->instanceObject != NULL) {
                        if (((int)eff->flags & 1) == 0) {
                            tmpl.posX = eff->sourceObject->anim.worldPosX + tmpl.posX;
                            tmpl.posY = eff->sourceObject->anim.worldPosY + tmpl.posY;
                            tmpl.posZ = eff->sourceObject->anim.worldPosZ + tmpl.posZ;
                        } else {
                            tmpl.posX = eff->sourceTransform.posX + tmpl.posX;
                            tmpl.posY = eff->sourceTransform.posY + tmpl.posY;
                            tmpl.posZ = eff->sourceTransform.posZ + tmpl.posZ;
                        }
                        eff->instanceObject->anim.worldPosX = tmpl.posX;
                        eff->instanceObject->anim.worldPosY = tmpl.posY;
                        eff->instanceObject->anim.worldPosZ = tmpl.posZ;
                    }
                    if (eff->instanceObject != NULL) {
                        GameObject* o = eff->instanceObject;
                        GameObject* hitObject = (GameObject*)ObjAnim_GetPriorityHitState(&o->anim)->lastHitObject;
                        if (hitObject != NULL) {
                            if (hitObject->anim.classId ==
                                (int)((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->valueX) {
                                Obj_FreeObject(o);
                                eff->instanceObject = NULL;
                                ((ModgfxCommand*)(PENDING_SPAWNS + cursor.commandIndex * 0x18))->flags ^= 0x10000000;
                                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.commandIndex * 0x18))->valueZ >=
                                        MODGFX_ZERO &&
                                    eff->sourceObject != NULL) {
                                    (*gPartfxInterface)
                                        ->spawnObject(
                                            eff->sourceObject,
                                            (int)((ModgfxCommand*)(PENDING_SPAWNS +
                                                                   cursor.commandIndex * sizeof(ModgfxCommand)))
                                                ->valueZ,
                                            &tmpl, 0x200001, -1, 0);
                                }
                                eff->requestedStage =
                                    ((ModgfxCommand*)(PENDING_SPAWNS + cursor.commandIndex * 0x18))->valueY;
                                break;
                            }
                        }
                    }
                }
                ObjList_GetObjects(&objIdx, &objCount);
                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x2) {
                    modgfx_stepVertexScale(eff, (ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset), active,
                                           scaleGroupIndex);
                    scaleGroupIndex++;
                }
                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x4) {
                    modgfx_stepVertexAlpha(eff, (ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset), active,
                                           alphaGroupIndex);
                    alphaGroupIndex++;
                }
                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x8) {
                    modgfx_stepVertexColor(eff, (ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset), active, 0);
                }
                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x100) {
                    ModgfxCommand* em = (ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset);
                    eff->rotOffsetZ += (s16)(em->valueX * gModgfxMotionStep);
                    eff->rotOffsetY += (s16)(em->valueY * gModgfxMotionStep);
                    eff->rotOffsetX += (s16)(em->valueZ * gModgfxMotionStep);
                }
                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x80) {
                    modgfx_stepS16VectorLerp(eff, (ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset), active, 0);
                }
                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x8000000) {
                    ((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->valueZ = randomGetRange(0, 0xffff);
                    modgfx_stepS16VectorLerp(eff, (ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset), active, 0);
                }
                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x4000) {
                    modgfx_scrollTexCoords(eff, (ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset), active, 0);
                }
                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x10000 && active != 0) {
                    if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->parameter == -1) {
                        Sfx_StopObjectChannel((GameObject*)eff->sourceObject, 0x40);
                    } else {
                        Sfx_PlayFromObject((GameObject*)eff->sourceObject,
                                           (u16)((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->parameter);
                    }
                }
                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x100000) {
                    if (active == 1) {
                        if (eff->stageFrameCountdown != 0) {
                            eff->sourceAlphaStep = (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->valueX -
                                                    (f32)(u32)eff->sourceObject->anim.alpha) /
                                                   (f32)eff->stageFrameCountdown;
                            eff->sourceAlphaCurrent = (f32)(u32)eff->sourceObject->anim.alpha;
                        } else {
                            eff->sourceAlphaStep = ((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->valueX -
                                                   (f32)(u32)eff->sourceObject->anim.alpha;
                            eff->sourceAlphaCurrent = MODGFX_ZERO;
                        }
                    }
                    eff->sourceAlphaCurrent = eff->sourceAlphaCurrent + eff->sourceAlphaStep;
                    if (eff->sourceAlphaCurrent > 255.0f) {
                        eff->sourceAlphaCurrent = 255.0f;
                    } else if (eff->sourceAlphaCurrent < MODGFX_ZERO) {
                        eff->sourceAlphaCurrent = MODGFX_ZERO;
                    }
                    eff->sourceObject->anim.alpha = eff->sourceAlphaCurrent;
                }
                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x400000) {
                    modgfx_stepPosition(eff, (ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset), active, 0);
                }
                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x80000000) {
                    ModgfxCommand* em = (ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset);
                    eff->posStepX = em->valueX * gModgfxMotionStep + eff->posStepX;
                    eff->posStepY = em->valueY * gModgfxMotionStep + eff->posStepY;
                    eff->posStepZ = em->valueZ * gModgfxMotionStep + eff->posStepZ;
                }
                if ((spawnCommand = ((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset)))->flags & 0x800000) {
                    if ((((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x1000000) &&
                        MODGFX_ZERO == spawnCommand->valueY) {
                        for (k = 0;
                             k <
                             (int)(spawnCommand = (ModgfxCommand*)(cursor.byteOffset + (int)PENDING_SPAWNS))->valueX;
                             k++) {
                            if (randomGetRange(0, (int)spawnCommand->valueZ) == 0) {
                                if ((int)eff->flags & 1) {
                                    (*gPartfxInterface)
                                        ->spawnObject(eff->sourceObject,
                                                      *(s16*)(cursor.byteOffset + (int)PENDING_SPAWNS +
                                                              offsetof(ModgfxCommand, parameter)),
                                                      NULL, 0x10001, -1, NULL);
                                } else {
                                    (*gPartfxInterface)
                                        ->spawnObject(eff->sourceObject,
                                                      *(s16*)(cursor.byteOffset + (int)PENDING_SPAWNS +
                                                              offsetof(ModgfxCommand, parameter)),
                                                      NULL, 0x10001, -1, NULL);
                                }
                            }
                        }
                    } else if (MODGFX_ZERO == spawnCommand->valueY) {
                        for (k = 0;
                             k <
                             (int)(spawnCommand = (ModgfxCommand*)(cursor.byteOffset + (int)PENDING_SPAWNS))->valueX;
                             k++) {
                            if ((int)eff->flags & 1) {
                                (*gPartfxInterface)
                                    ->spawnObject(eff->sourceObject, spawnCommand->parameter, &eff->sourceTransform,
                                                  0x10002, -1, NULL);
                            } else {
                                (*gPartfxInterface)
                                    ->spawnObject(eff->sourceObject, spawnCommand->parameter, NULL, 0x10002, -1, NULL);
                            }
                        }
                    } else if (MODGFX_ONE == spawnCommand->valueY) {
                        if (((int)eff->flags & 1) == 0) {
                            tmpl.posX = eff->sourceObject->anim.worldPosX + eff->drawPosX;
                            tmpl.posY = eff->sourceObject->anim.worldPosY + eff->drawPosY;
                            tmpl.posZ = eff->sourceObject->anim.worldPosZ + eff->drawPosZ;
                            if (eff->sourceObject != NULL) {
                                (*gPartfxInterface)
                                    ->spawnObject(eff->sourceObject,
                                                  ((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->parameter,
                                                  &tmpl, 0x10001, -1, NULL);
                            }
                        } else {
                            tmpl.posX = eff->drawPosX;
                            tmpl.posY = eff->drawPosY;
                            tmpl.posZ = eff->drawPosZ;
                            if (eff->sourceObject != NULL) {
                                (*gPartfxInterface)
                                    ->spawnObject(eff->sourceObject,
                                                  ((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->parameter,
                                                  &tmpl, 0x10001, -1, NULL);
                            }
                        }
                    }
                }
                if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x4000000) {
                    res = Resource_Acquire(
                        (u16)(((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->parameter + 0x58), 1);
                    if (((ModgfxCommand*)(PENDING_SPAWNS + cursor.byteOffset))->flags & 0x1000000) {
                        for (k = 0; k < (int)*(f32*)((cursor.byteOffset + (int)PENDING_SPAWNS) + 0x4); k++) {
                            if (randomGetRange(0, 5) == 0) {
                                if ((int)eff->flags & 1) {
                                    res->vtable->spawnEffect(NULL, 0, &eff->sourceTransform, 1, -1, NULL);
                                } else {
                                    res->vtable->spawnEffect(eff->sourceObject, 0, NULL, 1, -1, NULL);
                                }
                            }
                        }
                    } else {
                        for (k = 0; k < (int)*(f32*)((cursor.byteOffset + (int)PENDING_SPAWNS) + 0x4); k++) {
                            if ((int)eff->flags & 1) {
                                res->vtable->spawnEffect(NULL, 0, &eff->sourceTransform, 1, -1, NULL);
                            } else {
                                res->vtable->spawnEffect(eff->sourceObject, 0, NULL, 1, -1, NULL);
                            }
                        }
                    }
                    Resource_Release(res);
                }
            }
            if (feFlag == 0) {
                eff->stageFrameCountdown = eff->stageFrameCountdown - framesThisStep;
            }
        }
        gExpgfxUpdatingActivePools = 0;
    }
}

s16 modgfx_spawnEffect(ModgfxSpawnContext* context, int unused, int vertexCount, ModgfxEffectVertex* vertexData,
                       int triangleCount, s16* triangleIndices, int textureAssetId, Texture* textureResource) {
    int off;
    ModgfxCommand* item;
    struct {
        int index;
        s16* triangleSource;
        int elementIndex;
    } copy;
    int spawnCount;
    int divThresh;
    int slot;
    f32 fz434;
    f32 fz430;
    int emitterAddress;
    int base0;
    int total;

    total = 0;
    copy.index = 0;
    off = copy.index;
    slot = modgfx_findFreeEffectSlot(gModgfxActiveEffects, off, copy.index);
    if (slot == -1) {
        return 0;
    }
    {
        off = 0;
        spawnCount = context->commandCount;
        for (copy.index = 0; copy.index < spawnCount; copy.index++, off += 0x18) {
            item = (ModgfxCommand*)((u8*)context->commands + off);
            if ((item->flags & 0xf7fff180) == 0 && item->parameter != 0) {
                total += item->parameter;
            }
        }
    }

    base0 = 0;
    if ((context->flags & 0x800) == 0) {
        base0 = (int)(long)((triangleCount * 3) << 4) + ((vertexCount * 3) << 4);
    }

    gModgfxActiveEffects[slot] = (ModgfxEffectState*)mmAlloc(
        sizeof(ModgfxEffectState) + base0 + 0x100 + spawnCount * sizeof(ModgfxCommand) + total * 2, 0x15, 0);
    if (gModgfxActiveEffects[slot] == NULL) {
        modgfx_freeEffectsBySequence(0, 0);
        return -1;
    }

    gModgfxActiveEffects[slot]->inlineData = (u8*)gModgfxActiveEffects[slot] + sizeof(ModgfxEffectState);
    {
        u8* bufp = gModgfxActiveEffects[slot]->inlineData;
        if ((context->flags & 0x800) == 0) {
            gModgfxActiveEffects[slot]->triangleBuffers[0] = (LightmapTriangle*)bufp;
            bufp += triangleCount * 16;
            gModgfxActiveEffects[slot]->triangleBuffers[1] = (LightmapTriangle*)bufp;
            bufp += triangleCount * 16;
            gModgfxActiveEffects[slot]->triangleBuffers[2] = (LightmapTriangle*)bufp;
            bufp += triangleCount * 16;
            gModgfxActiveEffects[slot]->vertexBuffers[0] = (LightmapVertex*)bufp;
            bufp += vertexCount * 16;
            gModgfxActiveEffects[slot]->vertexBuffers[1] = (LightmapVertex*)bufp;
            bufp += vertexCount * 16;
            gModgfxActiveEffects[slot]->vertexBuffers[2] = (LightmapVertex*)bufp;
            bufp += vertexCount * 16;
        }
        gModgfxActiveEffects[slot]->baseVertexBuffer = bufp;
        gModgfxActiveEffects[slot]->baseTriangleBuffer = bufp + 0x80;
    }

    if (context->drawGroupCount != 0) {
        divThresh = triangleCount / context->drawGroupCount;
    } else {
        divThresh = triangleCount;
    }
    if ((context->flags & 0x800) == 0) {
        for (copy.index = 0; copy.index < 3; copy.index++) {
            int j;
            int bias;
            LightmapTriangle* triangle;

            triangle = (LightmapTriangle*)gModgfxActiveEffects[slot]->triangleBuffers[copy.index];
            bias = 0;
            j = 0;
            copy.triangleSource = triangleIndices;
            for (; j < triangleCount; j++) {
                if ((context->flags & 0x8000000) && j == divThresh) {
                    bias = context->drawGroupStride;
                }
                triangle->vertexIndices[0] = copy.triangleSource[0] - bias;
                triangle->vertexIndices[1] = copy.triangleSource[1] - bias;
                triangle->vertexIndices[2] = copy.triangleSource[2] - bias;

                copy.triangleSource += 3;
                triangle++;
            }
        }
    }

    gModgfxActiveEffects[slot]->textureResource = NULL;
    gModgfxActiveEffects[slot]->textureIsBorrowed = 0;
    if (textureResource != NULL) {
        gModgfxActiveEffects[slot]->textureResource = textureResource;
        gModgfxActiveEffects[slot]->textureIsBorrowed = 1;
    } else if (textureAssetId != 0) {
        gModgfxActiveEffects[slot]->textureResource = textureLoadAsset(textureAssetId);
        gModgfxActiveEffects[slot]->textureIsBorrowed = 0;
    }

    if ((context->flags & 0x800) == 0) {
        for (copy.index = 0; copy.index < 3; copy.index++) {
            LightmapVertex* dstv;
            dstv = gModgfxActiveEffects[slot]->vertexBuffers[copy.index];
            for (copy.elementIndex = 0; copy.elementIndex < vertexCount; copy.elementIndex++) {
                dstv->x = vertexData[copy.elementIndex].positionX;
                dstv->y = vertexData[copy.elementIndex].positionY;
                dstv->z = vertexData[copy.elementIndex].positionZ;
                if (gModgfxActiveEffects[slot]->textureResource != NULL) {
                    dstv->s = 128.0f * ((f32)vertexData[copy.elementIndex].texCoordS /
                                        (f32)((Texture*)gModgfxActiveEffects[slot]->textureResource)->width);
                    dstv->t = 128.0f * ((f32)vertexData[copy.elementIndex].texCoordT /
                                        (f32)((Texture*)gModgfxActiveEffects[slot]->textureResource)->height);
                }
                dstv->r = 0xff;
                dstv->g = 0xff;
                dstv->b = 0xff;
                dstv->a = 0xff;
                dstv++;
            }
        }
    }

    gModgfxActiveEffects[slot]->emitterCount = context->commandCount;
    gModgfxActiveEffects[slot]->word114 = 0;
    gModgfxActiveEffects[slot]->word118 = 0;
    gModgfxActiveEffects[slot]->word11C = 0;
    gModgfxActiveEffects[slot]->auxAllocation = NULL;
    gModgfxActiveEffects[slot]->releaseRequested = 0;
    gModgfxActiveEffects[slot]->byte13D = 0;
    gModgfxActiveEffects[slot]->stageTimer = 0;
    gModgfxActiveEffects[slot]->nextStage = -1;
    gModgfxActiveEffects[slot]->requestedStage = 0;
    gModgfxActiveEffects[slot]->stageDurations[0] = context->stageDurations[0];
    gModgfxActiveEffects[slot]->stageDurations[1] = context->stageDurations[1];
    gModgfxActiveEffects[slot]->stageDurations[2] = context->stageDurations[2];
    gModgfxActiveEffects[slot]->stageDurations[3] = context->stageDurations[3];
    gModgfxActiveEffects[slot]->stageDurations[4] = context->stageDurations[4];
    gModgfxActiveEffects[slot]->stageDurations[5] = context->stageDurations[5];
    gModgfxActiveEffects[slot]->stageDurations[6] = context->stageDurations[6];
    emitterAddress = base0;
    emitterAddress += (int)gModgfxActiveEffects[slot]->inlineData;
    emitterAddress += 0x100;
    gModgfxActiveEffects[slot]->emitterCommands = (ModgfxCommand*)emitterAddress;
    gModgfxActiveEffects[slot]->auxSequenceBuffer = NULL;
    if (total != 0) {
        gModgfxActiveEffects[slot]->auxSequenceBuffer =
            (u8*)gModgfxActiveEffects[slot]->emitterCommands + context->commandCount * sizeof(ModgfxCommand);
    }

    {
        u8* dst = gModgfxActiveEffects[slot]->auxSequenceBuffer;
        for (copy.index = 0, off = copy.index; copy.index < gModgfxActiveEffects[slot]->emitterCount;
             off += 0x18, copy.index++) {
            ((ModgfxCommand*)((u8*)gModgfxActiveEffects[slot]->emitterCommands + off))->stageIndex =
                ((ModgfxCommand*)((u8*)context->commands + off))->stageIndex;
            ((ModgfxCommand*)((u8*)gModgfxActiveEffects[slot]->emitterCommands + off))->parameter =
                ((ModgfxCommand*)((u8*)context->commands + off))->parameter;
            ((ModgfxCommand*)((u8*)gModgfxActiveEffects[slot]->emitterCommands + off))->vertexIndices = NULL;
            ((ModgfxCommand*)((u8*)gModgfxActiveEffects[slot]->emitterCommands + off))->flags =
                ((ModgfxCommand*)((u8*)context->commands + off))->flags;
            if ((((ModgfxCommand*)((u8*)gModgfxActiveEffects[slot]->emitterCommands + off))->flags & 0xf7fff180) == 0 &&
                ((ModgfxCommand*)((u8*)gModgfxActiveEffects[slot]->emitterCommands + off))->parameter != 0) {
                ((ModgfxCommand*)((u8*)gModgfxActiveEffects[slot]->emitterCommands + off))->vertexIndices = NULL;
                ((ModgfxCommand*)((u8*)gModgfxActiveEffects[slot]->emitterCommands + off))->vertexIndices = (s16*)dst;
                dst += ((ModgfxCommand*)((u8*)gModgfxActiveEffects[slot]->emitterCommands + off))->parameter * 2;
                for (copy.elementIndex = 0;
                     copy.elementIndex <
                     ((ModgfxCommand*)(off + (int)gModgfxActiveEffects[slot]->emitterCommands))->parameter;
                     copy.elementIndex++) {
                    ((ModgfxCommand*)(off + (int)gModgfxActiveEffects[slot]->emitterCommands))
                        ->vertexIndices[copy.elementIndex] =
                        (*(s16**)(off + (int)context->commands +
                                  offsetof(ModgfxCommand, vertexIndices)))[copy.elementIndex];
                }
            }
            ((ModgfxCommand*)((u8*)gModgfxActiveEffects[slot]->emitterCommands + off))->valueX =
                ((ModgfxCommand*)((u8*)context->commands + off))->valueX;
            ((ModgfxCommand*)((u8*)gModgfxActiveEffects[slot]->emitterCommands + off))->valueY =
                ((ModgfxCommand*)((u8*)context->commands + off))->valueY;
            ((ModgfxCommand*)((u8*)gModgfxActiveEffects[slot]->emitterCommands + off))->valueZ =
                ((ModgfxCommand*)((u8*)context->commands + off))->valueZ;
        }
    }

    gModgfxActiveEffects[slot]->currentStage = -1;
    gModgfxActiveEffects[slot]->stageFrameCountdown =
        gModgfxActiveEffects[slot]->stageDurations[gModgfxActiveEffects[slot]->currentStage];
    gModgfxActiveEffects[slot]->flags = context->flags;
    gModgfxActiveEffects[slot]->drawPosX = context->position[0];
    gModgfxActiveEffects[slot]->drawPosY = context->position[1];
    gModgfxActiveEffects[slot]->drawPosZ = context->position[2];
    gModgfxActiveEffects[slot]->renderScale = context->scale;
    if ((int)gModgfxActiveEffects[slot]->flags & 1) {
        gModgfxActiveEffects[slot]->sourceTransform.posX = context->position[0];
        gModgfxActiveEffects[slot]->sourceTransform.posY = context->position[1];
        gModgfxActiveEffects[slot]->sourceTransform.posZ = context->position[2];
    }
    fz430 = MODGFX_ZERO;
    gModgfxActiveEffects[slot]->posStepX = fz430;
    gModgfxActiveEffects[slot]->posStepY = fz430;
    gModgfxActiveEffects[slot]->posStepZ = fz430;
    fz434 = MODGFX_ONE;
    gModgfxActiveEffects[slot]->scaleVectors[0].x = fz434;
    gModgfxActiveEffects[slot]->scaleVectors[0].y = fz434;
    gModgfxActiveEffects[slot]->scaleVectors[0].z = fz434;
    gModgfxActiveEffects[slot]->scaleVectors[1].y = fz430;
    gModgfxActiveEffects[slot]->scaleVectors[1].z = fz430;
    gModgfxActiveEffects[slot]->scaleVectors[1].x = fz430;
    gModgfxActiveEffects[slot]->scaleVectors[2].z = fz434;
    gModgfxActiveEffects[slot]->scaleVectors[2].x = fz434;
    gModgfxActiveEffects[slot]->scaleVectors[2].y = fz434;
    gModgfxActiveEffects[slot]->scaleVectors[3].z = fz430;
    gModgfxActiveEffects[slot]->scaleVectors[3].x = fz430;
    gModgfxActiveEffects[slot]->scaleVectors[3].y = fz430;
    gModgfxActiveEffects[slot]->rotOffsetZ = 0;
    gModgfxActiveEffects[slot]->rotOffsetY = 0;
    gModgfxActiveEffects[slot]->rotOffsetX = 0;
    gModgfxActiveEffects[slot]->vec120 = 0;
    gModgfxActiveEffects[slot]->vec122 = 0;
    gModgfxActiveEffects[slot]->vec124 = 0;
    gModgfxActiveEffects[slot]->alphaValues[0] = fz430;
    gModgfxActiveEffects[slot]->alphaValues[1] = fz430;
    gModgfxActiveEffects[slot]->alphaValues[2] = fz430;
    gModgfxActiveEffects[slot]->alphaValues[3] = fz430;
    gModgfxActiveEffects[slot]->blendColorR = fz430;
    gModgfxActiveEffects[slot]->blendColorG = fz430;
    gModgfxActiveEffects[slot]->blendColorB = fz430;
    gModgfxActiveEffects[slot]->blendColorStepR = fz430;
    gModgfxActiveEffects[slot]->blendColorStepG = fz430;
    gModgfxActiveEffects[slot]->blendColorStepB = fz430;
    gModgfxActiveEffects[slot]->velocityX = context->velocity[0];
    gModgfxActiveEffects[slot]->velocityY = context->velocity[1];
    gModgfxActiveEffects[slot]->velocityZ = context->velocity[2];
    gModgfxSequenceIdCounter += 1;
    if (gModgfxSequenceIdCounter > 0x4e20) {
        gModgfxSequenceIdCounter = 0;
    }
    gModgfxActiveEffects[slot]->sequenceId = gModgfxSequenceIdCounter;
    gModgfxActiveEffects[slot]->spawnGeneration = gModgfxSpawnGeneration;
    gModgfxActiveEffects[slot]->vertexCount = vertexCount;
    gModgfxActiveEffects[slot]->triangleCount = triangleCount;
    gModgfxActiveEffects[slot]->sourceObject = context->sourceObject;
    gModgfxActiveEffects[slot]->instanceObject = NULL;
    *(u8*)&gModgfxActiveEffects[slot]->sourceYawIndex = context->sourceYawIndex;
    gModgfxActiveEffects[slot]->drawGroupCount = context->drawGroupCount;
    gModgfxActiveEffects[slot]->drawGroupStride = context->drawGroupStride;
    gModgfxActiveEffects[slot]->initialStateByte = context->initialStateByte;
    gModgfxActiveEffects[slot]->soundHandle = 0;
    gModgfxActiveEffects[slot]->activeVertexBufferIndex = 0;
    gModgfxActiveEffects[slot]->byte13B = 0;
    gModgfxActiveEffects[slot]->frameUpdated = 0;
    gModgfxActiveEffects[slot]->textureFrameTimer = context->textureFrameTimer;
    if (gModgfxActiveEffects[slot]->textureFrameTimer != 0) {
        gModgfxActiveEffects[slot]->textureFrameStep = 0x3c / gModgfxActiveEffects[slot]->textureFrameTimer;
    } else {
        gModgfxActiveEffects[slot]->textureFrameStep = 0;
    }
    if (gModgfxActiveEffects[slot]->textureFrameStep != 0) {
        gModgfxActiveEffects[slot]->textureFrameFadeStep = 0xff / gModgfxActiveEffects[slot]->textureFrameStep;
    } else {
        gModgfxActiveEffects[slot]->textureFrameFadeStep = 0;
    }
    gModgfxActiveEffects[slot]->textureFrame = 0;
    gModgfxActiveEffects[slot]->variant = context->variant;
    return gModgfxActiveEffects[slot]->sequenceId;
}

void modgfx_onMapSetup(void) {
    int i;

    modgfx_freeEffectsBySequence(0, 1);
    for (i = 0; i < MODGFX_ACTIVE_EFFECT_COUNT; i++) {
        gModgfxActiveEffects[i] = NULL;
    }
}

void modgfx_release(void) {
    modgfx_freeEffectsBySequence(0, 1);
}

void modgfx_initialise(void) {
    ModgfxEffectState** arr = gModgfxActiveEffects;
    int i;
    for (i = 0; i < MODGFX_ACTIVE_EFFECT_COUNT; i++) {
        arr[i] = NULL;
    }
}

ModgfxDescriptor gModgfxDescriptor = {
    {0, 0, 0},
    0x00180000,
    modgfx_initialise,
    modgfx_release,
    {
        0,
        modgfx_onMapSetup,
        modgfx_spawnEffect,
        modgfx_updateActiveEffects,
        modgfx_releaseAll,
        modgfx_freeSourceEffects,
        modgfx_detachSource,
        modgfx_renderEffects,
        modgfx_releaseHandle,
        modgfx_nextSpawnGeneration,
        modgfx_setSourceByte13B,
        modgfx_requestSourceRelease,
        modgfx_markSourceFrameUpdated,
        modgfx_beginSequence,
        modgfx_resetSequenceCommands,
        modgfx_addSequenceCommand,
        modgfx_nextStage,
        modgfx_setStageIndex,
        modgfx_setStageDuration,
        modgfx_setStageDurations,
        modgfx_spawnSequence,
        modgfx_addSequenceFlags,
        modgfx_getLastSpawnHandle,
    },
    0,
};
