/*
 * DLL 0x1F4 (slot 500) drives a set-dressing object that follows a looping
 * path and emits particle and sound effects.
 */
#include "dlls/objects/500.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/obj_path.h"
#include "main/objseq.h"

#define DLL1F4_OBJECT_SFX_CHANNEL 0x40
#define DLL1F4_OBJECT_SFX_RANGE   100.0f

#define DLL1F4_STATIC_SEQUENCE_ID 0x3E4

#define DLL1F4_PARTICLE_SCALE 0.35f
#define DLL1F4_PARTICLE_ARG3  0xC0D

#define DLL1F4_BODY_PARTICLE_ID   0x7A8
#define DLL1F4_BODY_PARTICLE_MODE 6

#define DLL1F4_PATH_PARTICLE_ID   0x7C7
#define DLL1F4_PATH_PARTICLE_MODE 2

#define DLL1F4_MOVE_PROGRESS_RANDOM_MIN 0
#define DLL1F4_MOVE_PROGRESS_RANDOM_MAX 90
#define DLL1F4_MOVE_PROGRESS_DIVISOR    100.0f
#define DLL1F4_MOVE_SPEED               0.003f

#define DLL1F4_PATH_POINT_INDEX 0
#define DLL1F4_PATH_POINT_X     0.0f
#define DLL1F4_PATH_POINT_Y     -12.0f
#define DLL1F4_PATH_POINT_Z     0.0f

int dll500_getExtraSize(void) {
    return sizeof(Dll1F4State);
}

void dll500_free(GameObject* obj) {
    Sfx_StopObjectChannel(obj, DLL1F4_OBJECT_SFX_CHANNEL);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dll500_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

int dll500_processAnimEvents(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    PartFxSpawnParams spawnParams;
    int frameIndex;

    (void)unused;
    if ((s32)randomGetRange(0, 1) != 0) {
        animUpdate->sequenceControlFlags = OBJSEQ_CONTROL_SET_LATCH_A;
    } else {
        animUpdate->sequenceControlFlags = OBJSEQ_CONTROL_CLEAR_LATCH_A;
    }
    animUpdate->movementState = 0;
    animUpdate->flags = -1;
    animUpdate->flags &= ~0x20;

    if (Obj_GetPlayerObject() == NULL) {
        return 0;
    }
    if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
        spawnParams.scale = DLL1F4_PARTICLE_SCALE;
        spawnParams.arg3 = DLL1F4_PARTICLE_ARG3;
        spawnParams.posX -= obj->anim.worldPosX;
        spawnParams.posY -= obj->anim.worldPosY;
        spawnParams.posZ -= obj->anim.worldPosZ;
        for (frameIndex = 0; frameIndex < framesThisStep; frameIndex++) {
            (*gPartfxInterface)
                ->spawnObject(obj, DLL1F4_BODY_PARTICLE_ID, &spawnParams, DLL1F4_BODY_PARTICLE_MODE, -1, NULL);
        }
    }
    return 0;
}

void dll500_update(GameObject* obj) {
    PartFxSpawnParams spawnParams;
    f32 playerDistance;
    int frameIndex;

    playerDistance = Vec_distance(&Obj_GetPlayerObject()->anim.worldPosX, &obj->anim.worldPosX);
    if (Sfx_IsPlayingFromObjectChannel(obj, DLL1F4_OBJECT_SFX_CHANNEL) == 0) {
        if (playerDistance < DLL1F4_OBJECT_SFX_RANGE) {
            Sfx_PlayFromObject(obj, SFXTRIG_mushdizzylp12);
        }
    } else if (playerDistance >= DLL1F4_OBJECT_SFX_RANGE) {
        Sfx_StopObjectChannel(obj, DLL1F4_OBJECT_SFX_CHANNEL);
    }

    if (obj->anim.romDefNo != DLL1F4_STATIC_SEQUENCE_ID) {
        if (obj->userData2 == 0) {
            obj->userData2 = 1;
            ObjAnim_SetMoveProgress(&obj->anim, (f32)(s32)randomGetRange(DLL1F4_MOVE_PROGRESS_RANDOM_MIN,
                                                                                     DLL1F4_MOVE_PROGRESS_RANDOM_MAX) /
                                                                DLL1F4_MOVE_PROGRESS_DIVISOR);
        }
        ObjAnim_AdvanceCurrentMove(obj, DLL1F4_MOVE_SPEED, timeDelta, NULL);
    }

    if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
        spawnParams.scale = DLL1F4_PARTICLE_SCALE;
        spawnParams.arg3 = DLL1F4_PARTICLE_ARG3;
        spawnParams.posX = DLL1F4_PATH_POINT_X;
        spawnParams.posY = DLL1F4_PATH_POINT_Y;
        spawnParams.posZ = DLL1F4_PATH_POINT_Z;
        ObjPath_GetPointWorldPosition(obj, DLL1F4_PATH_POINT_INDEX, &spawnParams.posX, &spawnParams.posY,
                                      &spawnParams.posZ, 1);
        if (obj->anim.parent != NULL) {
            spawnParams.posX -= obj->anim.worldPosX;
            spawnParams.posY -= obj->anim.worldPosY;
            spawnParams.posZ -= obj->anim.worldPosZ;
        } else {
            spawnParams.posX -= obj->anim.localPosX;
            spawnParams.posY -= obj->anim.localPosY;
            spawnParams.posZ -= obj->anim.localPosZ;
        }
        for (frameIndex = 0; frameIndex < framesThisStep; frameIndex++) {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, DLL1F4_PATH_PARTICLE_ID, &spawnParams, DLL1F4_PATH_PARTICLE_MODE, -1, NULL);
        }
    }
}

void dll500_init(GameObject* obj, const Dll1F4PlacementView* placement) {
    Dll1F4State* state = obj->extra;

    if (obj->anim.romDefNo == DLL1F4_STATIC_SEQUENCE_ID) {
        obj->anim.rotX = (s16)((u32)placement->rotXStatic << 8);
    } else {
        obj->anim.rotX = (s16)((s32)placement->rotXSwing << 8);
    }
    obj->anim.rotY = 0;
    obj->anim.rotZ = 0;
    obj->userData2 = 0;
    state->active = 1;
    obj->animEventCallback = dll500_processAnimEvents;
}

ObjectDescriptor gDll1F4ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dll500_init,
    (ObjectDescriptorCallback)dll500_update,
    0,
    (ObjectDescriptorCallback)dll500_render,
    (ObjectDescriptorCallback)dll500_free,
    0,
    dll500_getExtraSize,
};
