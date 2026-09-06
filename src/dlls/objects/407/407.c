/* DLL 0x197. */
#include "dlls/objects/407.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/resource.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "main/voxmaps.h"
#include "sys/objects.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/objhits.h"

#define DLL197_EFFECT_RESOURCE_ID        0x69
#define DLL197_EFFECT_SPAWN_FLAGS        0x10004
#define DLL197_PARTFX_SPARK              0x1A3
#define DLL197_PARTFX_SPARK_COUNT        200
#define DLL197_PARTFX_SPARKLE            0x1F7
#define DLL197_PROXIMITY_DISTANCE        90.0f
#define DLL197_PROXIMITY_SFX_CHANNEL     0x40
#define DLL197_SHUTDOWN_SFX_CHANNEL      0x7F
#define DLL197_STAGE_COMPLETE_GAMEBIT    0x472
#define DLL197_STAGE_EFFECT_PARAM1_BASE  0x19D
#define DLL197_STAGE_EFFECT_PARAM2_BASE  0x19E
#define DLL197_STAGE_RESET_GATE_GAMEBIT  0x474
#define DLL197_VISIBILITY_TRACE_DISTANCE 50.0f

typedef struct Dll197EffectSpawnParams {
    u8 unknown00[0x10];
    f32 scale;
} Dll197EffectSpawnParams;

STATIC_ASSERT(sizeof(Dll197EffectSpawnParams) == 0x14);
STATIC_ASSERT(offsetof(Dll197EffectSpawnParams, unknown00) == 0x00);
STATIC_ASSERT(offsetof(Dll197EffectSpawnParams, scale) == 0x10);

const Dll69EffectParams gDll197EffectParamTemplate = {0x3E7, 0x8C, 0x8D, 0x28};
s8 gDll197PuzzleProgress;

int dll407_getExtraSize(void) {
    return sizeof(Dll197State);
}

int dll407_getObjectTypeId(void) {
    return 1;
}

void dll407_free(GameObject* obj) {
    (*gModgfxInterface)->detachSource(obj);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dll407_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    f32 originOffset = 0.0f;
    PartFxSpawnParams particleParams;
    f32 dir[3];
    f32 objTrace[3];
    f32 cameraTrace[3];
    s16 startGrid[4];
    s16 endGrid[4];
    u8 traceOut[8];
    Dll197State* state = obj->extra;
    Camera* camera;
    f32 dist;
    f32 scale;
    void* dirAlias = dir;

    (void)dirAlias;
    if (visible == 0) {
        state->sparkTimer = 0;
        state->visibleToCamera = 0;
        return;
    }

    if (state->active == 0) {
        return;
    }

    state->visibleToCamera = 1;
    camera = Camera_GetCurrent();
    dir[0] = camera->x - obj->anim.localPosX;
    dir[1] = camera->y - obj->anim.localPosY;
    dir[2] = camera->z - obj->anim.localPosZ;

    dist = sqrtf(dir[2] * dir[2] + (dir[0] * dir[0] + dir[1] * dir[1]));
    if (dist > DLL197_VISIBILITY_TRACE_DISTANCE) {
        scale = 1.0f / dist;
        dir[0] *= scale;
        dir[1] *= scale;
        dir[2] *= scale;

        objTrace[0] = 32.0f * dir[0];
        objTrace[1] = 32.0f * dir[1];
        objTrace[2] = 32.0f * dir[2];
        objTrace[0] += obj->anim.localPosX;
        objTrace[1] += obj->anim.localPosY;
        objTrace[2] += obj->anim.localPosZ;
        cameraTrace[0] = -20.0f * dir[0];
        cameraTrace[1] = -20.0f * dir[1];
        cameraTrace[2] = -20.0f * dir[2];
        cameraTrace[0] += camera->x;
        cameraTrace[1] += camera->y;
        cameraTrace[2] += camera->z;

        voxmaps_worldToGrid(objTrace, startGrid);
        voxmaps_worldToGrid(cameraTrace, endGrid);
        if (voxmaps_traceLine((VoxPos*)startGrid, (VoxPos*)endGrid, (VoxPos*)traceOut, NULL, 0) == 0) {
            state->visibleToCamera = 0;
            (*gExpgfxInterface)->freeSource((u32)obj);
        }
    }

    if (state->sparkTimer > 0) {
        state->sparkTimer -= framesThisStep;
        return;
    }

    if (state->visibleToCamera != 0) {
        particleParams.posX = originOffset;
        particleParams.posY = 5.0f;
        particleParams.posZ = originOffset;
        (*gPartfxInterface)->spawnObject((void*)obj, DLL197_PARTFX_SPARKLE, &particleParams, 0x12, -1, NULL);
    }

    state->sparkTimer = randomGetRange(-10, 10) + 0x3C;
}

void dll407_hitDetect(void) {
}

void dll407_update(GameObject* objectAddress) {
    Dll197State* state = objectAddress->extra;
    Dll69EffectParams resourceParams;
    Dll197EffectSpawnParams effectSpawnParams;
    GameObject* player;
    f32 distance;
    Dll69Interface** resource;
    int effect;
    int stageEffectBase;

    resourceParams = gDll197EffectParamTemplate;

    player = Obj_GetPlayerObject();
    distance = Vec_distance(&player->anim.worldPosX, &objectAddress->anim.worldPosX);
    if (Sfx_IsPlayingFromObjectChannel(objectAddress, DLL197_PROXIMITY_SFX_CHANNEL) != 0) {
        if (distance >= DLL197_PROXIMITY_DISTANCE && state->active != 0) {
            Sfx_StopObjectChannel(objectAddress, DLL197_PROXIMITY_SFX_CHANNEL);
        }
    } else if (distance < DLL197_PROXIMITY_DISTANCE && state->active != 0) {
        Sfx_PlayFromObject(objectAddress, SFXTRIG_mushdizzylp12);
    }

    objUpdateOpacity(objectAddress);

    if (state->hitCooldown > 0) {
        state->hitCooldown -= framesThisStep;
    }

    switch (state->mode) {
    case 1:
        break;
    case 0:
    default:
        return;
    }

    effectSpawnParams.scale = -2.0f;
    state->previousActive = state->active;
    if (ObjHits_GetPriorityHit(objectAddress, 0, 0, 0) != 0 ||
        (state->hitCooldown != 0 && state->hitCooldown <= 0x14)) {
        state->active = 1 - state->active;
        if (state->active != 0) {
            state->activeTimer = 1000;
        }
        if (state->hitCooldown != 0) {
            state->hitCooldown = 0;
            gDll197PuzzleProgress = 3;
            state->activeTimer = 300;
            if (state->stage == 2) {
                mainSetBits(DLL197_STAGE_COMPLETE_GAMEBIT, 1);
            }
        }
    }

    if (state->active != 0 && state->activeTimer != 0) {
        state->activeTimer -= framesThisStep;
        if (state->activeTimer <= 0) {
            state->activeTimer = 0;
            state->active = 0;
        }
    }

    if (state->active != 0 && state->sparkTimer <= 0 && state->sparkArmed != 0) {
        state->sparkArmed = 0;
        Sfx_PlayFromObject(objectAddress, SFXTRIG_cvdrip1c);
    }

    if (state->active == state->previousActive) {
        return;
    }

    if (state->active != 0) {
        resource = Resource_Acquire(DLL197_EFFECT_RESOURCE_ID, 1);
        stageEffectBase = state->stage * 2;
        resourceParams.param1 = stageEffectBase + DLL197_STAGE_EFFECT_PARAM1_BASE;
        resourceParams.param2 = stageEffectBase + DLL197_STAGE_EFFECT_PARAM2_BASE;
        (*resource)->spawn(objectAddress, 1, &effectSpawnParams, DLL197_EFFECT_SPAWN_FLAGS, -1,
                           &resourceParams);
        Resource_Release(resource);

        for (effect = 0; effect < DLL197_PARTFX_SPARK_COUNT; effect++) {
            (*gPartfxInterface)->spawnObject((void*)objectAddress, DLL197_PARTFX_SPARK, NULL, 0, -1, NULL);
        }

        if (state->gameBit != -1 && mainGetBit(state->gameBit) == 0) {
            mainSetBits(state->gameBit, 1);
        }
        if (gDll197PuzzleProgress == 0 && state->stage == 0 && mainGetBit(state->gameBit) != 0) {
            gDll197PuzzleProgress = 1;
        }
        if (gDll197PuzzleProgress == 1 && state->stage == 1 && mainGetBit(state->gameBit) != 0) {
            gDll197PuzzleProgress = 2;
        }
        if (gDll197PuzzleProgress == 2 && state->stage == 2 && mainGetBit(state->gameBit) != 0) {
            mainSetBits(DLL197_STAGE_COMPLETE_GAMEBIT, 1);
            gDll197PuzzleProgress = 3;
        }
        state->sparkArmed = 1;
        state->sparkTimer = 1;
    } else {
        Sfx_StopObjectChannel(objectAddress, DLL197_SHUTDOWN_SFX_CHANNEL);
        (*gModgfxInterface)->detachSource((void*)objectAddress);
        (*gExpgfxInterface)->freeSource((u32)objectAddress);
        if (state->gameBit != -1 && mainGetBit(state->gameBit) != 0) {
            mainSetBits(state->gameBit, 0);
        }
        if (gDll197PuzzleProgress == 1 && state->stage == 0) {
            gDll197PuzzleProgress = 0;
        }
        if (gDll197PuzzleProgress == 2 && state->stage == 1) {
            gDll197PuzzleProgress = 0;
        }
        if (gDll197PuzzleProgress == 3 && state->stage == 2 && mainGetBit(DLL197_STAGE_RESET_GATE_GAMEBIT) == 0) {
            mainSetBits(DLL197_STAGE_COMPLETE_GAMEBIT, 0);
            gDll197PuzzleProgress = 0;
        }
    }
}

void dll407_init(GameObject* obj, const Dll197Placement* placement) {
    Dll197State* state;
    Dll69Interface** resource;
    Dll197EffectSpawnParams effectSpawnParams;

    state = obj->extra;
    obj->anim.rotX = (s16)((placement->rotationParam & 0x3Fu) << 10);
    if (placement->scale > 0) {
        obj->anim.rootMotionScale = placement->scale / 8192.0f;
    } else {
        obj->anim.rootMotionScale = 0.1f;
    }
    state->mode = placement->mode;
    state->active = 0;
    state->stage = 0;
    state->gameBit = placement->gameBit;
    effectSpawnParams.scale = -2.0f;
    switch (state->mode) {
    case 0:
        state->active = 1;
        resource = Resource_Acquire(DLL197_EFFECT_RESOURCE_ID, 1);
        if (placement->stage == 0) {
            (*resource)->spawn(obj, 0, &effectSpawnParams, DLL197_EFFECT_SPAWN_FLAGS, -1, NULL);
        }
        break;
    case 1:
        state->stage = (u8)placement->stage;
        state->sparkArmed = 0;
        state->hitCooldown = (s16)(state->stage * 0x28 + 0x398);
        state->previousActive = 0;
        break;
    }
    state->sparkTimer = 0;
}

void dll407_release(void) {
}

void dll407_initialise(void) {
}

ObjectDescriptor gDll197ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll407_initialise,
    (ObjectDescriptorCallback)dll407_release,
    0,
    (ObjectDescriptorCallback)dll407_init,
    (ObjectDescriptorCallback)dll407_update,
    (ObjectDescriptorCallback)dll407_hitDetect,
    (ObjectDescriptorCallback)dll407_render,
    (ObjectDescriptorCallback)dll407_free,
    (ObjectDescriptorCallback)dll407_getObjectTypeId,
    dll407_getExtraSize,
};
