#include "main/dll/CAM/dll_0001_camcontrol.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx/vec.h"
#include "dolphin/os.h"
#include "dolphin/pad.h"
#include "main/dll/dll_0044_cameramodeviewfinder.h"
#include "main/dll/dll_0048_cameramodestatic.h"
#include "main/dll/dll_0049_cameramodecombat.h"
#include "main/dll/dll_02C0_front_api.h"
#include "main/dll/savegame.h"
#include "dlls/objects/201_Baddie.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/obj_query.h"
#include "main/pad.h"
#include "main/voxmaps.h"
#include "dlls/objects/261_LargeCrate.h"
#include "main/dll/objfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/resource.h"
#include "main/dll/dll_0019_dll19func0.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/dll_B7.h"
#include "main/dll/player_api.h"
#include "main/dll/tricky_api.h"
#include "main/camera.h"
#include "main/camera_interface.h"
#include "main/model.h"
#include "main/model_light.h"
#include "main/mldf_fileid.h"
#include "main/obj_list.h"
#include "main/object_render.h"
#include "main/rcp_dolphin_api.h"
#include "main/shader_map_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "track/intersect_api.h"
#include "track/intersect_depth_state_api.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "main/asset_load.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "string.h"

struct CamcontrolTriggeredAction {
    s8 actionKind;
    u8 pad01[0x0C];
    u8 triggerMode;
    u8 pad0E[2];
};

STATIC_ASSERT(sizeof(CamcontrolTriggeredAction) == 0x10);
STATIC_ASSERT(offsetof(CamcontrolTriggeredAction, triggerMode) == 0x0D);

typedef struct CamcontrolQueuedActionParam {
    u32 actionIndex;
    u8 noBlendFlag;
} CamcontrolQueuedActionParam;

STATIC_ASSERT(sizeof(CamcontrolQueuedActionParam) == 0x08);
STATIC_ASSERT(offsetof(CamcontrolQueuedActionParam, noBlendFlag) == 0x04);

enum CamcontrolTriggeredActionKind {
    CAMCONTROL_TRIGGERED_ACTION_KIND_DEFAULT,
    CAMCONTROL_TRIGGERED_ACTION_KIND_TRIGGERED
};

enum CamcontrolActionConstants {
    CAMCONTROL_ACTION_NO_NONE,
    CAMCONTROL_FALLBACK_ACTION_NO = 1,
    CAMCONTROL_ACTION_HEAP = 0x0F,
    CAMCONTROL_DEFAULT_BLEND_FRAMES = 0x78,
    CAMCONTROL_SAVED_ACTION_NONE = -1
};

typedef struct CamcontrolHandlerEntry {
    u16 actionId;
    u8 pad02[2];
    CamcontrolHandler* handler;
    u8 priority;
    u8 pad09[3];
} CamcontrolHandlerEntry;

STATIC_ASSERT(sizeof(CamcontrolHandlerVTable) == 0x14);
STATIC_ASSERT(sizeof(CamcontrolHandler) == 0x04);
STATIC_ASSERT(sizeof(CamcontrolHandlerEntry) == 0x0C);
STATIC_ASSERT(offsetof(CamcontrolHandlerEntry, handler) == 0x04);
STATIC_ASSERT(offsetof(CamcontrolHandlerEntry, priority) == 0x08);

enum CamcontrolHandlerConstants {
    CAMCONTROL_HANDLER_PRIORITY_DYNAMIC = 1,
    CAMCONTROL_HANDLER_RESOURCE_TYPE = 4,
    CAMCONTROL_HANDLER_CAPACITY = 20
};

typedef struct CamcontrolStateStorage {
    CamcontrolCameraState state;
    u8 pad144[4];
} CamcontrolStateStorage;

STATIC_ASSERT(sizeof(CamcontrolStateStorage) == 0x148);
STATIC_ASSERT(offsetof(CamcontrolStateStorage, state) == 0x00);

enum CamcontrolReticleBank {
    CAMCONTROL_RETICLE_BANK_LOCKON,
    CAMCONTROL_RETICLE_BANK_DEFAULT,
    CAMCONTROL_RETICLE_BANK_CONTEXT
};

enum CamcontrolReticleState {
    CAMCONTROL_TARGET_RETICLE_STATE_INACTIVE,
    CAMCONTROL_TARGET_RETICLE_STATE_ACTIVE = 3
};

enum CamcontrolTargetConstants {
    CAMCONTROL_HELP_TEXT_NONE = -1
};

enum CamcontrolReticleConstants {
    CAMCONTROL_RETICLE_ICON_VARIANT_PRESS_A = 1,
    CAMCONTROL_RETICLE_DIM_ALPHA_SCALE = 0x60,
    CAMCONTROL_RETICLE_SPIN_STEP = 0x400,
    CAMCONTROL_RETICLE_OBJECT_ID = 0x1FE
};

enum CamcontrolTargetScanFlags {
    CAMCONTROL_INTERACT_FLAG_TARGET_EXCLUDED = 0x20,
    CAMCONTROL_TARGET_FLAG_IGNORE_VERTICAL_DELTA = 0x80,
    CAMCONTROL_HIT_VOLUME_FLAG_TRACE_LOS = 0x20
};

enum CamcontrolTargetScanConstants {
    CAMCONTROL_TARGET_CANDIDATE_COUNT = 8,
    CAMCONTROL_TARGET_RANGE_SHIFT = 2,
    CAMCONTROL_VOX_OCCUPANCY_CLEAR = 1
};

#define CAMCONTROL_TARGET_SCAN_BLOCKED_FLAGS (INTERACT_FLAG_DISABLED | CAMCONTROL_INTERACT_FLAG_TARGET_EXCLUDED)
#define CAMCONTROL_TARGET_MIN_Y_DELTA        -100.0f
#define CAMCONTROL_TARGET_MAX_Y_DELTA        20.0f
#define CAMCONTROL_TARGET_TRACE_HEIGHT       20.0f

extern char sCamcontrolTriggeredCamActionLoadWarning[];

s16 gCamcontrolTargetHelpTextId = -1;
u16 gCamcontrolTargetClassMask = 0xFFFF;
char sCamcontrolBlendDebugFormat[] = "t=%f\n";

CamcontrolCameraState* gCamcontrolCamera;
u8 gCamcontrolHandlerCount;
CamcontrolHandlerEntry* gCamcontrolCurrentHandler;
s32 gCamcontrolActiveActionId;
int gCamcontrolCurrentHandlerIndex;
s32 gCamcontrolQueuedActionId;
int gCamcontrolActiveActionPriority;
int gCamcontrolActiveActionStartFlags;
void* gCamcontrolQueuedActionData;
u8 gCamcontrolQueuedActionPending;
s8 gCamcontrolQueuedActionStartFlags;
s8 gCamcontrolQueuedActionPriority;
s32 gCamcontrolQueuedActionBlendFrames;
u8 gCamcontrolQueuedActionMode;
int gCamcontrolSavedActionId;
int gCamcontrolSavedActionPriority;
int gCamcontrolSavedActionStartFlags;
f32 gCamcontrolSavedFocusLocalX;
f32 gCamcontrolSavedFocusLocalY;
f32 gCamcontrolSavedFocusLocalZ;
f32 gCamcontrolSavedFocusWorldX;
f32 gCamcontrolSavedFocusWorldY;
f32 gCamcontrolSavedFocusWorldZ;
f32 gCamcontrolFovY;
u32 lbl_803DD4CC;
s8 lbl_803DD4CB;
s8 gCamcontrolTargetState;
u16 gCamcontrolReticleSpin;
void* gCamcontrolReticleLight;
s16 gCamcontrolLetterboxYOffset;
GameObject* gCamcontrolTargetReticle;
s8 gCamcontrolTargetChanged;

CamcontrolStateStorage gCamcontrolStateStorage;
CamcontrolHandlerEntry* gCamcontrolHandlerEntries[CAMCONTROL_HANDLER_CAPACITY];

CamcontrolResourceDescriptor gCamcontrolResourceDescriptor = {
    {
        0x00000000,
        0x00000000,
        0x00000000,
        0x001d0000,
    },
    (ResourceDescriptorCallback)Camera_initialise,
    (ResourceDescriptorCallback)Camera_release,
    {
        {0},
        Camera_init,
        Camera_update,
        Camera_get,
        Camera_getMode,
        Camera_getActiveHandler,
        Camera_getDefaultHandlerEntry,
        (CameraSetModeFn)Camera_setMode,
        (void* (*)(int))Camera_getCamActionsBinEntry,
        camcontrol_loadTriggeredCamAction,
        Camera_setFocus,
        Camera_overridePos,
        Camera_moveBy,
        camcontrol_initialise,
        camcontrol_getRelativePosition,
        Camera_getOverrideTarget,
        Camera_getTarget,
        Camera_setTargetFlag2,
        Camera_setTarget,
        Camera_setTargetReticleOverride,
        Camera_isZooming,
        camcontrol_updateTargetFeedback,
        Camera_minimapShowHelpTextForTarget,
        Camera_setLetterbox,
        camcontrol_release,
        Camera_getMinimapInfoText,
        Camera_applyFrameFlags,
        Camera_applyTargetFlags,
    },
    camcontrol_queueSavedAction,
};

int Camera_getTargetKind(void) {
    return gCamcontrolCamera->targetKind;
}

int Camera_getMinimapInfoText(void) {
    return gCamcontrolTargetHelpTextId;
}

void camcontrol_updateTargetReticle(GameObject* fallbackTarget, int unused2, u32 renderArg2, u32 renderArg3,
                                    u32 renderArg4, u32 renderArg5) {
    int savedReticleState;
    u8 savedReticleAlpha;
    GameObject* reticle;
    GameObject* target;
    ObjHitVolumeRuntimeTransform* slot;
    ObjModel* activeModel;
    u8 idx;
    int bank;
    int paletteIdx;

    reticle = gCamcontrolTargetReticle;
    target = fallbackTarget;
    if (gCamcontrolCamera->targetReticleOverride != NULL) {
        target = gCamcontrolCamera->targetReticleOverride;
        savedReticleState = gCamcontrolTargetState;
        gCamcontrolTargetState = CAMCONTROL_TARGET_RETICLE_STATE_ACTIVE;
        savedReticleAlpha = reticle->anim.alpha;
        reticle->anim.alpha = 0xFF;
    }

    if (target != NULL) {
        if (target->anim.hitVolumeTransforms == NULL) {
            return;
        }

        idx = target->hitVolumeIndex;
        slot = &target->anim.hitVolumeTransforms[idx];

        switch (target->anim.hitVolumeBounds[idx].flags & CAMCONTROL_TARGET_KIND_MASK) {
        case CAMCONTROL_TARGET_KIND_LOCKON:
            bank = CAMCONTROL_RETICLE_BANK_LOCKON;
            break;
        case CAMCONTROL_TARGET_KIND_CONTEXT_A:
        case CAMCONTROL_TARGET_KIND_CONTEXT_B:
            bank = CAMCONTROL_RETICLE_BANK_CONTEXT;
            break;
        default:
            bank = CAMCONTROL_RETICLE_BANK_DEFAULT;
            break;
        }

        paletteIdx = target->hintTextIdx;
        if (paletteIdx >= 4) {
            paletteIdx = 0;
        }
        gCamcontrolTargetHelpTextId = target->anim.modelInstance->helpTextIds[paletteIdx];

        reticle->anim.worldPosX = slot->jointX;
        reticle->anim.worldPosY = slot->jointY;
        reticle->anim.worldPosZ = slot->jointZ;
        reticle->anim.bankIndex = bank;

        reticle->anim.parent = target->anim.parent;
        if (reticle->anim.parent != NULL) {
            Obj_TransformWorldPointToLocal(reticle->anim.worldPosX, reticle->anim.worldPosY, reticle->anim.worldPosZ,
                                           &reticle->anim.localPosX, &reticle->anim.localPosY, &reticle->anim.localPosZ,
                                           reticle->anim.parent);
        } else {
            reticle->anim.localPosX = reticle->anim.worldPosX;
            reticle->anim.localPosY = reticle->anim.worldPosY;
            reticle->anim.localPosZ = reticle->anim.worldPosZ;
        }
        reticle->anim.rotY = 0;
        reticle->anim.rotZ = 0;
        reticle->anim.rootMotionScale = 0.4f;
        reticle->anim.renderAlpha = reticle->anim.alpha;
        objRenderModelAndHitVolumes(reticle, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    } else {
        reticle->anim.parent = NULL;
    }

    activeModel = reticle->anim.modelBanks[reticle->anim.bankIndex];
    activeModel->bufferFlags = (u16)(activeModel->bufferFlags & ~8);

    if (gCamcontrolCamera->targetReticleOverride != NULL) {
        gCamcontrolTargetState = savedReticleState;
        reticle->anim.alpha = savedReticleAlpha;
    }
}

int camcontrol_aButtonIconTextureCallback(GameObject* obj, ObjModel* model, u32 renderOpIdx) {
    Shader* renderOp;
    GXColor color; /* r/g/b intentionally left unset: callee reads only alpha for this op */

    renderOp = ObjModel_GetRenderOp(model->file, renderOpIdx);
    Rcp_ResetTextureStageState();
    if (renderOp->layers[0].materialId == CAMCONTROL_RETICLE_ICON_VARIANT_PRESS_A) {
        if ((gCamcontrolCamera->targetFlags & CAMCONTROL_CAMERA_TARGET_FLAG_PROMPT_SUPPRESSED) == 0) {
            color.a = 0;
        } else {
            color.a = obj->anim.alpha;
        }
    } else {
        color.a = obj->anim.alpha;
    }
    if (gCamcontrolCamera->targetKind == CAMCONTROL_TARGET_KIND_SUPPRESSED) {
        color.a = 0;
    }
    addTexLayerStageKAlpha(textureIdxToPtr(renderOp->layers[0].textureIndex), NULL, 0, &color);
    Rcp_ApplyTextureStageCounts();
    if (color.a < 0xff) {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 0);
    } else {
        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 1);
    }
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetCullMode(GX_CULL_BACK);
    return 1;
}

int camcontrol_lockIconTextureCallback(GameObject* obj, ObjModel* model, int renderOpIdx) {
    Shader* renderOp;
    u8 tier;
    GXColor color;
    f32 dist;
    int alphaVal;

    renderOp = ObjModel_GetRenderOp(model->file, renderOpIdx);
    dist = gCamcontrolCamera->targetDistance;
    if (dist <= 0.0f) {
        tier = 4;
    } else if (dist <= 0.25f) {
        tier = 3;
    } else if (dist <= 0.5f) {
        tier = 2;
    } else if (dist <= 0.75f) {
        tier = 1;
    } else {
        tier = 0;
    }
    Rcp_ResetTextureStageState();
    if (renderOp->layers[0].materialId <= tier) {
        color.r = 0;
        color.g = 0;
        color.b = 0;
        alphaVal = ((obj->anim.alpha + 1) * CAMCONTROL_RETICLE_DIM_ALPHA_SCALE) >> 8;
        color.a = alphaVal;
        addTexLayerStageKAlpha(textureIdxToPtr(renderOp->layers[0].textureIndex), NULL, 0, &color);
    } else {
        color.r = 0xff;
        color.g = 0xff;
        color.b = 0xff;
        color.a = obj->anim.alpha;
        addTexLayerStageKAlpha(textureIdxToPtr(renderOp->layers[0].textureIndex), NULL, 0, &color);
    }
    Rcp_ApplyTextureStageCounts();
    if (obj->anim.alpha < 0xff || renderOp->layers[0].materialId <= tier) {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 0);
    } else {
        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
        gxSetZMode_(1, GX_LEQUAL, 1);
    }
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetCullMode(GX_CULL_BACK);
    return 1;
}

void camcontrol_initialiseTargetReticle(void) {
    if (gCamcontrolTargetReticle == NULL) {
        gCamcontrolTargetReticle =
            objSetupObject(Obj_AllocObjectSetup(0x18, CAMCONTROL_RETICLE_OBJECT_ID), 4, -1, -1, NULL);
        ObjModel_SetRenderCallback((u8*)Obj_GetActiveModel(gCamcontrolTargetReticle),
                                   camcontrol_lockIconTextureCallback);
        gCamcontrolTargetReticle->anim.bankIndex = CAMCONTROL_RETICLE_BANK_DEFAULT;
        ObjModel_SetRenderCallback((u8*)Obj_GetActiveModel(gCamcontrolTargetReticle),
                                   camcontrol_aButtonIconTextureCallback);
        gCamcontrolTargetReticle->anim.bankIndex = CAMCONTROL_RETICLE_BANK_CONTEXT;
        ObjModel_SetRenderCallback((u8*)Obj_GetActiveModel(gCamcontrolTargetReticle),
                                   camcontrol_aButtonIconTextureCallback);
        lightSetColor(1, 0x32, 0x3C, 0x28);
        gCamcontrolReticleLight = objCreateLight(NULL, 1);
        if (gCamcontrolReticleLight != NULL) {
            modelLightStruct_setLightKind(gCamcontrolReticleLight, MODEL_LIGHT_KIND_DIRECTIONAL);
            modelLightStruct_setObjectLightMaskIndex(gCamcontrolReticleLight, 1);
            modelLightStruct_setTransformMode(gCamcontrolReticleLight, 1);
            modelLightStruct_setDirection(gCamcontrolReticleLight, 1.0f, 0.0f, -0.78f);
            modelLightStruct_setDiffuseColor(gCamcontrolReticleLight, 0xB4, 0xC8, 0xFF, 0xFF);
        }
    }
}

static inline int camcontrol_isTargetCandidate(GameObject* obj, ObjHitVolumeRuntimeBounds* bounds) {
    int accept;
    if (bounds != NULL && obj->anim.alpha == 0xff &&
        !(obj->anim.resetHitboxFlags & CAMCONTROL_TARGET_SCAN_BLOCKED_FLAGS) &&
        ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) || (obj->anim.modelInstance->flags & OBJDEF_FLAG_HAS_MODELS)) &&
        !(obj->anim.flags & OBJANIM_FLAG_HIDDEN) && !(obj->objectFlags & OBJECT_OBJFLAG_FREED) &&
        (gCamcontrolTargetClassMask &
         ((accept = 1) << (bounds[obj->hitVolumeIndex].flags & CAMCONTROL_TARGET_KIND_MASK)))) {
        return accept;
    }
    return 0;
}

GameObject* camcontrol_findBestTarget(CamcontrolCameraState* cameraState, ObjAnimComponent* focus) {
    int objIndex;
    int objCount;
    u8 occOut[4];
    f32 worldFrom[3];
    f32 worldTo[3];
    int gridFromStorage[3];
    int gridToStorage[3];
    int traceOutStorage[3];
    GameObject* targets[CAMCONTROL_TARGET_CANDIDATE_COUNT];
    f32 dist[CAMCONTROL_TARGET_CANDIDATE_COUNT];
    GameObject** ptr;
    int bestPri;
    GameObject* obj;
    int idx;
    int count;
    GameObject* player;
    u8 canTarget;
    ObjHitVolumeRuntimeBounds* bounds;
    ObjHitVolumeRuntimeBounds* entry;
    ObjDefHitVolume* row;
    GameObject* best;
    int i;
    int k;
    int accept;
    f32 dx, dz, dy, distsq, range;

    (void)cameraState;
    bestPri = -1;
    count = 0;
    player = Obj_GetPlayerObject();
    if (player == NULL || focus == NULL || gCamcontrolActiveActionId == CAMERA_MODE_VIEWFINDER_RESOURCE_ID ||
        playerCanUseCombatTargeting(player) == 0) {
        return NULL;
    }
    ptr = ObjList_GetObjects(&objIndex, &objCount);
    idx = objIndex;
    ptr += idx;
    for (; idx < objCount; ptr++, idx++) {
        obj = *ptr;
        bounds = obj->anim.hitVolumeBounds;
        accept = camcontrol_isTargetCandidate(obj, bounds);
        if (accept == 0) {
            continue;
        }
        if ((int)obj->anim.modelInstance->hitVolumes[obj->hitVolumeIndex].priorityUnsigned < bestPri) {
            continue;
        }
        if ((obj->anim.resetHitboxFlags & CAMCONTROL_TARGET_FLAG_IGNORE_VERTICAL_DELTA) ||
            (bounds[obj->hitVolumeIndex].flags & CAMCONTROL_TARGET_FLAG_IGNORE_VERTICAL_DELTA)) {
            dy = 0.0f;
        } else {
            dy = focus->worldPosY - obj->anim.hitVolumeTransforms[obj->hitVolumeIndex].centerY;
        }
        if (!(dy > CAMCONTROL_TARGET_MIN_Y_DELTA)) {
            continue;
        }
        if (!(dy < CAMCONTROL_TARGET_MAX_Y_DELTA)) {
            continue;
        }
        dx = focus->worldPosX - obj->anim.hitVolumeTransforms[obj->hitVolumeIndex].centerX;
        dz = focus->worldPosZ - obj->anim.hitVolumeTransforms[obj->hitVolumeIndex].centerZ;
        distsq = dx * dx + dz * dz;
        entry = &bounds[obj->hitVolumeIndex];
        range = (f32)(int)(entry->bounds[2] << CAMCONTROL_TARGET_RANGE_SHIFT);
        if (!(distsq < range * range)) {
            continue;
        }
        canTarget = 1;
        if ((entry->flags & CAMCONTROL_TARGET_KIND_MASK) == CAMCONTROL_TARGET_KIND_A_BUTTON_HINT &&
            playerIsTargetSuppressed(player) != 0) {
            canTarget = 0;
        }
        if (canTarget == 0) {
            continue;
        }
        bestPri = obj->anim.modelInstance->hitVolumes[obj->hitVolumeIndex].priorityUnsigned;
        i = 0;
        while (i < count &&
               (int)targets[i]->anim.modelInstance->hitVolumes[targets[i]->hitVolumeIndex].priorityUnsigned > bestPri) {
            i++;
        }
        while (i < count && dist[i] < distsq &&
               bestPri ==
                   (int)targets[i]->anim.modelInstance->hitVolumes[targets[i]->hitVolumeIndex].priorityUnsigned) {
            i++;
        }
        for (k = count; k > i; k--) {
            dist[k] = dist[k - 1];
            targets[k] = targets[k - 1];
        }
        dist[i] = distsq;
        targets[i] = obj;
        count++;
        if (count == CAMCONTROL_TARGET_CANDIDATE_COUNT) {
            break;
        }
    }
    if (count > 0) {
        best = targets[0];
        row = best->anim.modelInstance->hitVolumes;
        row += best->hitVolumeIndex;
        if (row->flags & CAMCONTROL_HIT_VOLUME_FLAG_TRACE_LOS) {
            worldFrom[0] = focus->worldPosX;
            worldFrom[1] = CAMCONTROL_TARGET_TRACE_HEIGHT + focus->worldPosY;
            worldFrom[2] = focus->worldPosZ;
            worldTo[0] = best->anim.hitVolumeTransforms[best->hitVolumeIndex].jointX;
            worldTo[1] = best->anim.hitVolumeTransforms[best->hitVolumeIndex].jointY;
            worldTo[2] = best->anim.hitVolumeTransforms[best->hitVolumeIndex].jointZ;
            /* The voxmap APIs access only the leading three s16 coordinates. */
            voxmaps_worldToGrid(worldFrom, (s16*)gridFromStorage);
            voxmaps_worldToGrid(worldTo, (s16*)gridToStorage);
            if ((u8)voxmaps_traceLine((VoxPos*)gridFromStorage, (VoxPos*)gridToStorage, (VoxPos*)traceOutStorage,
                                      occOut, 0) == 0 &&
                occOut[0] != CAMCONTROL_VOX_OCCUPANCY_CLEAR) {
                return NULL;
            }
        }
        return targets[0];
    }
    return NULL;
}

void camcontrol_updateMoveAverage(CamcontrolCameraState* cameraState, ObjAnimComponent* focus) {
    Vec3f* velocity;
    f32 mag;
    f32 root;
    f32 minMove;
    f32 average;
    f32 move0;
    f32 move1;
    f32 move2;
    f32 move3;
    f32 move4;

    move1 = cameraState->focusMoveHistory[1];
    cameraState->focusMoveHistory[0] = move1;
    move2 = cameraState->focusMoveHistory[2];
    cameraState->focusMoveHistory[1] = move2;
    move3 = cameraState->focusMoveHistory[3];
    cameraState->focusMoveHistory[2] = move3;
    move4 = cameraState->focusMoveHistory[4];
    cameraState->focusMoveHistory[3] = move4;
    velocity = &focus->velocity;
    mag = PSVECMag(velocity);
    if (mag > 0.0f) {
        root = sqrtf(mag);
        mag = root;
    }
    cameraState->focusMoveHistory[4] = mag;
    minMove = 0.0f;
    cameraState->focusMoveAverage = minMove;
    move0 = cameraState->focusMoveHistory[0];
    cameraState->focusMoveAverage += move0;
    move1 = cameraState->focusMoveHistory[1];
    cameraState->focusMoveAverage += move1;
    move2 = cameraState->focusMoveHistory[2];
    cameraState->focusMoveAverage += move2;
    move3 = cameraState->focusMoveHistory[3];
    cameraState->focusMoveAverage += move3;
    move4 = cameraState->focusMoveHistory[4];
    cameraState->focusMoveAverage += move4;
    cameraState->focusMoveAverage *= 0.2f;
    average = cameraState->focusMoveAverage;
    if (average < minMove) {
        cameraState->focusMoveAverage = -average;
    }
}

static inline int camcontrol_findHandlerIndex(u16 actionId) {
    int handlerCount;
    register CamcontrolHandlerEntry** handlerEntry;
    int handlerIndex;

    handlerIndex = 0;
    handlerEntry = gCamcontrolHandlerEntries;
    for (handlerCount = gCamcontrolHandlerCount; 0 < handlerCount; handlerCount--) {
        if (actionId == (*handlerEntry)->actionId) {
            return handlerIndex;
        }
        handlerEntry++;
        handlerIndex++;
    }
    return -1;
}

void camcontrol_activateHandler(u16 actionId, void* actionData) {
    CamcontrolHandlerEntry* entry;
    int idx;
    int n;
    int priority;

    if (gCamcontrolCurrentHandler != NULL) {
        if (gCamcontrolActiveActionId != actionId) {
            gCamcontrolCurrentHandler->handler->vtable->release(gCamcontrolCamera);
            if (gCamcontrolCurrentHandler->priority == CAMCONTROL_HANDLER_PRIORITY_DYNAMIC) {
                idx = gCamcontrolCurrentHandlerIndex;
                Resource_Release(gCamcontrolHandlerEntries[idx]->handler);
                mm_free(gCamcontrolHandlerEntries[idx]);
                gCamcontrolHandlerEntries[idx] = gCamcontrolHandlerEntries[gCamcontrolHandlerCount - 1];
                gCamcontrolHandlerCount--;
                gCamcontrolCurrentHandler = NULL;
                gCamcontrolActiveActionId = -1;
                gCamcontrolCurrentHandlerIndex = -1;
            }
        }
    }

    idx = camcontrol_findHandlerIndex(actionId);
    gCamcontrolCurrentHandlerIndex = idx;

    if (idx == -1) {
        CamcontrolHandlerEntry* newEntry;
        priority = gCamcontrolQueuedActionPriority;
        newEntry = mmAlloc(sizeof(CamcontrolHandlerEntry), CAMCONTROL_ACTION_HEAP, 0);
        n = gCamcontrolHandlerCount;
        gCamcontrolHandlerEntries[n] = newEntry;
        gCamcontrolHandlerCount++;
        entry = gCamcontrolHandlerEntries[n];
        entry->actionId = actionId;
        entry->priority = priority;
        entry->handler = Resource_Acquire(actionId, CAMCONTROL_HANDLER_RESOURCE_TYPE);
        gCamcontrolCurrentHandlerIndex = gCamcontrolHandlerCount - 1;
    }

    if (gCamcontrolCurrentHandlerIndex != -1) {
        entry = gCamcontrolHandlerEntries[gCamcontrolCurrentHandlerIndex];
        gCamcontrolCurrentHandler = entry;
        gCamcontrolActiveActionId = entry->actionId;
        entry->handler->vtable->activate(gCamcontrolCamera, gCamcontrolQueuedActionStartFlags, actionData);
    } else {
        gCamcontrolCurrentHandler = NULL;
        gCamcontrolActiveActionId = -1;
    }

    gCamcontrolActiveActionPriority = gCamcontrolQueuedActionPriority;
    gCamcontrolActiveActionStartFlags = gCamcontrolQueuedActionStartFlags;
}

void firstPersonZoomOutOnExit(u8 blendFrames, u8 blendFlags) {
    Camera* vs;
    f32 blendProgress;

    Camera_GetCurrent();
    blendProgress = 1.0f;
    gCamcontrolCamera->blendProgress = blendProgress;
    gCamcontrolCamera->blendStep = blendProgress / (float)blendFrames;
    gCamcontrolCamera->queuedBlendFlags = blendFlags;

    vs = Camera_GetCurrent();
    gCamcontrolCamera->blendStartX = vs->x;
    gCamcontrolCamera->blendStartY = vs->y;
    gCamcontrolCamera->blendStartZ = vs->z;
    gCamcontrolCamera->blendStartYaw = vs->yaw;
    gCamcontrolCamera->blendStartPitch = vs->pitch;
    gCamcontrolCamera->blendStartRoll = vs->roll;

    gCamcontrolCamera->blendStartFovY = Camera_GetFovY();
}

void Camera_setBlendCurveMode(u8 mode) {
    gCamcontrolCamera->blendCurveMode = mode;
}

void camcontrol_applyState(CamcontrolCameraState* camera) {
    Camera* view;
    int blendedAngleDelta;
    f32 mag;
    f32 blendFactor;
    f32 worldDelta[3];

    Camera_SetCurrentViewIndex(0);
    view = Camera_GetCurrent();
    view->yaw = camera->yaw;
    view->pitch = camera->pitch;
    view->roll = camera->roll;
    if (camera->smoothingFlags.b0 != 0u) {
        PSVECSubtract((Vec*)&camera->worldX, (Vec*)&view->x, (Vec*)worldDelta);
        mag = PSVECMag((Vec*)worldDelta);
        if (mag > 0.0f) {
            PSVECNormalize((Vec*)worldDelta, (Vec*)worldDelta);
        }
        blendFactor = interpolate(mag, 0.22f, timeDelta);
        mag = (blendFactor < 0.0f) ? 0.0f : ((blendFactor > 3.0f * timeDelta) ? 3.0f * timeDelta : blendFactor);
        view->x = mag * worldDelta[0] + view->x;
        view->y = mag * worldDelta[1] + view->y;
        view->z = mag * worldDelta[2] + view->z;
    } else {
        view->x = camera->worldX;
        view->y = camera->worldY;
        view->z = camera->worldZ;
    }
    gCamcontrolFovY = camera->fovY;
    if (camera->blendProgress > 0.0f) {
        f32 prog;

        camera->blendProgress = -(camera->blendStep * timeDelta - camera->blendProgress);
        prog = camera->blendProgress;
        camera->blendProgress = (prog < 0.0f) ? 0.0f : ((prog > 1.0f) ? 1.0f : prog);
        if (gCamcontrolCamera->blendCurveMode == 2) {
            mag = 1.0f - camera->blendProgress * camera->blendProgress * camera->blendProgress;
        } else if (gCamcontrolCamera->blendCurveMode == 1) {
            mag = 1.0f - camera->blendProgress * camera->blendProgress;
        } else {
            mag = 1.0f - camera->blendProgress;
        }
        blendFactor = (mag < 0.0f) ? 0.0f : ((mag > 1.0f) ? 1.0f : mag);
        if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_X) != 0) {
            view->x = blendFactor * (view->x - camera->blendStartX) + camera->blendStartX;
        }
        if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_Y) != 0) {
            view->y = blendFactor * (view->y - camera->blendStartY) + camera->blendStartY;
        }
        if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_Z) != 0) {
            view->z = blendFactor * (view->z - camera->blendStartZ) + camera->blendStartZ;
        }
        OSReport(sCamcontrolBlendDebugFormat, blendFactor);
        if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_YAW) != 0) {
            camera->blendDeltaYaw = camera->blendStartYaw - (u16)view->yaw;
            if (camera->blendDeltaYaw > 0x8000) {
                camera->blendDeltaYaw = (camera->blendDeltaYaw - 0x10000) + 1;
            }
            if (camera->blendDeltaYaw < -0x8000) {
                camera->blendDeltaYaw = (camera->blendDeltaYaw + 0x10000) - 1;
            }
            blendedAngleDelta = (int)((f32)camera->blendDeltaYaw * blendFactor);
            view->yaw = camera->blendStartYaw - blendedAngleDelta;
        }
        if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_PITCH) != 0) {
            camera->blendDeltaPitch = camera->blendStartPitch - (u16)view->pitch;
            if (camera->blendDeltaPitch > 0x8000) {
                camera->blendDeltaPitch = (camera->blendDeltaPitch - 0x10000) + 1;
            }
            if (camera->blendDeltaPitch < -0x8000) {
                camera->blendDeltaPitch = (camera->blendDeltaPitch + 0x10000) - 1;
            }
            blendedAngleDelta = (int)((f32)camera->blendDeltaPitch * blendFactor);
            view->pitch = camera->blendStartPitch - blendedAngleDelta;
        }
        if ((camera->queuedBlendFlags & CAMCONTROL_BLEND_ROLL) != 0) {
            camera->blendDeltaRoll = camera->blendStartRoll - (u16)view->roll;
            if (camera->blendDeltaRoll > 0x8000) {
                camera->blendDeltaRoll = (camera->blendDeltaRoll - 0x10000) + 1;
            }
            if (camera->blendDeltaRoll < -0x8000) {
                camera->blendDeltaRoll = (camera->blendDeltaRoll + 0x10000) - 1;
            }
            blendedAngleDelta = (int)((f32)camera->blendDeltaRoll * blendFactor);
            view->roll = camera->blendStartRoll - blendedAngleDelta;
        }
    }
    Camera_SetFovY(gCamcontrolFovY);
    Camera_UpdateForObject(view);
    loadMapForCameraPos(camera->worldX, camera->worldY, camera->worldZ);
    gCamcontrolLetterboxYOffset = Camera_GetViewportYOffset();
    if ((int)gCamcontrolLetterboxYOffset != camera->letterboxTargetOffset) {
        if ((int)gCamcontrolLetterboxYOffset < camera->letterboxTargetOffset) {
            gCamcontrolLetterboxYOffset = gCamcontrolLetterboxYOffset + camera->letterboxStep * (int)timeDelta;
            if ((int)gCamcontrolLetterboxYOffset > camera->letterboxTargetOffset) {
                gCamcontrolLetterboxYOffset = camera->letterboxTargetOffset;
            }
        } else {
            gCamcontrolLetterboxYOffset = gCamcontrolLetterboxYOffset - camera->letterboxStep * (int)timeDelta;
            if ((int)gCamcontrolLetterboxYOffset < camera->letterboxTargetOffset) {
                gCamcontrolLetterboxYOffset = camera->letterboxTargetOffset;
            }
        }
        Camera_SetViewportYOffset(gCamcontrolLetterboxYOffset);
    }
    camera->letterboxTargetOffset = 0;
    Camera_UpdateViewMatrices();
}

void camcontrol_applyQueuedAction(void) {
    Camera* view;
    f32 blendStep;

    if (gCamcontrolQueuedActionPending != '\0') {
        if (gCamcontrolQueuedActionBlendFrames > 1) {
            blendStep = 1.0f / gCamcontrolQueuedActionBlendFrames;
            if ((blendStep <= 0.0f) || (blendStep > 1.0f)) {
                blendStep = 1.0f;
            }
            gCamcontrolCamera->blendProgress = 1.0f;
            gCamcontrolCamera->blendStep = blendStep;
            gCamcontrolCamera->queuedBlendFlags = gCamcontrolQueuedActionMode;
        } else {
            gCamcontrolCamera->blendProgress = 0.0f;
            gCamcontrolCamera->queuedBlendFlags = 0;
        }
        view = Camera_GetCurrent();
        if (1.0f == gCamcontrolCamera->blendProgress) {
            gCamcontrolCamera->blendStartX = view->x;
            gCamcontrolCamera->blendStartY = view->y;
            gCamcontrolCamera->blendStartZ = view->z;
            gCamcontrolCamera->blendStartYaw = view->yaw;
            gCamcontrolCamera->blendStartPitch = view->pitch;
            gCamcontrolCamera->blendStartRoll = view->roll;
            gCamcontrolCamera->blendStartFovY = Camera_GetFovY();
        } else {
            gCamcontrolCamera->yaw = view->yaw;
            gCamcontrolCamera->pitch = view->pitch;
            gCamcontrolCamera->roll = view->roll;
            gCamcontrolCamera->fovY = Camera_GetFovY();
        }
        gCamcontrolSavedActionId = gCamcontrolActiveActionId;
        gCamcontrolSavedActionPriority = gCamcontrolActiveActionPriority;
        gCamcontrolSavedActionStartFlags = gCamcontrolActiveActionStartFlags;
        camcontrol_activateHandler((u16)gCamcontrolQueuedActionId, gCamcontrolQueuedActionData);
        gCamcontrolQueuedActionPending = '\0';
        if (gCamcontrolQueuedActionData != NULL) {
            mm_free(gCamcontrolQueuedActionData);
            gCamcontrolQueuedActionData = NULL;
        }
    }
}

void Camera_applyTargetFlags(int targetFlagMode) {
    gCamcontrolCamera->targetFlags =
        (u8)(gCamcontrolCamera->targetFlags | ((targetFlagMode << 3) & CAMCONTROL_CAMERA_TARGET_FLAG_APPLY_MODE_MASK));
}

void Camera_setTargetFlag2(int enable) {
    if (enable != 0) {
        gCamcontrolCamera->targetFlags =
            (u8)(gCamcontrolCamera->targetFlags | CAMCONTROL_CAMERA_TARGET_FLAG_FORCE_COMBAT);
    } else {
        gCamcontrolCamera->targetFlags =
            (u8)(gCamcontrolCamera->targetFlags & ~CAMCONTROL_CAMERA_TARGET_FLAG_FORCE_COMBAT);
    }
}

void Camera_applyFrameFlags(int flags) {
    gCamcontrolCamera->frameFlags = (u8)(gCamcontrolCamera->frameFlags | flags);
}

void Camera_setLetterbox(int yOffset, int applyNow) {
    if (yOffset > gCamcontrolCamera->letterboxTargetOffset) {
        gCamcontrolCamera->letterboxTargetOffset = yOffset;
        gCamcontrolCamera->letterboxStep = 2;
        if (applyNow != 0) {
            Camera_SetViewportYOffset((s16)yOffset);
        }
    }
}

void Camera_minimapShowHelpTextForTarget(int renderArg2, int renderArg3, int renderArg4, int renderArg5) {
    if (isFrontEndUiActive() == 0) {
        gCamcontrolTargetHelpTextId = CAMCONTROL_HELP_TEXT_NONE;
        camcontrol_updateTargetReticle(gCamcontrolCamera->targetReticleFocus,
                                       gCamcontrolActiveActionId == CAMERA_MODE_COMBAT_RESOURCE_ID, renderArg2,
                                       renderArg3, renderArg4, renderArg5);
        gCamcontrolCamera->targetReticleOverride = NULL;
    }
}

void camcontrol_setAButtonIconForTarget(void) {
    GameObject* target = gCamcontrolCamera->currentTarget;
    int kind;

    if (isFrontEndUiActive() != 0) {
        return;
    }
    if (target == NULL) {
        return;
    }

    kind = target->anim.hitVolumeBounds[target->hitVolumeIndex].flags & CAMCONTROL_TARGET_KIND_MASK;
    if (kind == CAMCONTROL_TARGET_KIND_TALK_ICON) {
        if (target->anim.classId == 6) {
            setAButtonIcon(A_BUTTON_ICON_TALK_NPC);
        } else {
            setAButtonIcon(A_BUTTON_ICON_TALK_OBJECT);
        }
    } else if (kind == CAMCONTROL_TARGET_KIND_A_BUTTON_HINT) {
        setAButtonIcon(A_BUTTON_ICON_HINT);
    } else if (kind == CAMCONTROL_TARGET_KIND_CONTEXT_B_ICON) {
        setAButtonIcon(A_BUTTON_ICON_CONTEXT_B);
    }
}

static inline u32 camcontrol_getTargetKind(GameObject* target) {
    return target->anim.hitVolumeBounds[target->hitVolumeIndex].flags & CAMCONTROL_TARGET_KIND_MASK;
}

void camcontrol_updateTargetFeedback(void) {
    u32 targetKind;
    s16 objType;
    f32 alphaScale;
    GameObject* target;
    ObjAnimComponent* reticle;
    u8 buttonPressed;
    int result;
    u32 buttons;
    u32 buttonMask;
    f32 targetDistance;

    target = gCamcontrolCamera->currentTarget;
    reticle = &gCamcontrolTargetReticle->anim;
    buttonPressed = false;
    if (reticle == NULL) {
        return;
    }
    result = isFrontEndUiActive();
    switch (result) {
    case 0:
        if ((gCamcontrolTargetChanged != '\0') && (gCamcontrolTargetChanged = '\0', target != NULL)) {
            targetKind = gCamcontrolCamera->targetKind;
            if (targetKind == CAMCONTROL_TARGET_KIND_LOCKON) {
                Sfx_PlayFromObject(0, SFXTRIG_headcam_out);
                objShowButtonGlow(reticle, 1.0f, 2);
            } else if ((targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_A) ||
                       (targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_B)) {
                Sfx_PlayFromObject(0, SFXTRIG_lockon2_on);
                objShowButtonGlow(reticle, 1.0f, 3);
            } else if (targetKind != CAMCONTROL_TARGET_KIND_SUPPRESSED) {
                Sfx_PlayFromObject(0, SFXTRIG_sc_scabshortish32);
                objShowButtonGlow(reticle, 1.0f, 1);
            }
        }
        if (target != NULL) {
            target->anim.resetHitboxFlags = target->anim.resetHitboxFlags | INTERACT_FLAG_IN_RANGE;
            buttons = getButtonsJustPressed(0);
            buttonMask = PAD_BUTTON_A;
            targetKind = camcontrol_getTargetKind(target);
            if ((targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_A) || (targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_B)) {
                buttonMask = (PAD_BUTTON_A | PAD_BUTTON_Y);
            }
            if ((buttons & buttonMask) != 0) {
                buttonPressed = true;
            }
            if ((target->anim.resetHitboxFlags & INTERACT_FLAG_PROMPT_SUPPRESSED) == 0) {
                if (buttonPressed) {
                    target->anim.resetHitboxFlags = target->anim.resetHitboxFlags | INTERACT_FLAG_ACTIVATED;
                }
            } else if ((buttonPressed) && (result = isTalkingToNpc(), result == 0)) {
                Sfx_PlayFromObject(0, SFXTRIG_sc_clock_timesup);
            }
        }
        if (gCamcontrolTargetState == '\0') {
            if (reticle->currentMoveProgress <= 0.0f) {
                if (target != NULL) {
                    gCamcontrolCamera->targetReticleFocus = target;
                    gCamcontrolCamera->targetKind = camcontrol_getTargetKind(target);
                    gCamcontrolTargetState = CAMCONTROL_TARGET_RETICLE_STATE_ACTIVE;
                    gCamcontrolTargetChanged = true;
                } else {
                    gCamcontrolCamera->targetReticleFocus = NULL;
                }
            } else {
                ObjAnim_AdvanceCurrentMove(reticle, -0.04f, timeDelta, NULL);
            }
        } else if ((gCamcontrolCamera->targetReticleFocus != target) && (reticle->currentMoveProgress >= 1.0f)) {
            gCamcontrolTargetState = CAMCONTROL_TARGET_RETICLE_STATE_INACTIVE;
            if (target != NULL) {
                ObjAnim_SetMoveProgress(reticle, 0.0f);
            }
            if (target == NULL) {
                targetKind = gCamcontrolCamera->targetKind;
                if (targetKind == CAMCONTROL_TARGET_KIND_LOCKON) {
                    Sfx_PlayFromObject(0, SFXTRIG_strafe_active);
                } else if ((targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_A) ||
                           (targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_B)) {
                    Sfx_PlayFromObject(0, SFXTRIG_lockon2_off);
                } else if (targetKind != CAMCONTROL_TARGET_KIND_SUPPRESSED) {
                    Sfx_PlayFromObject(0, SFXTRIG_sc_gemrun1022);
                }
            }
        } else {
            ObjAnim_AdvanceCurrentMove(reticle, 0.04f, timeDelta, NULL);
        }
        result = Obj_IsObjectAlive(gCamcontrolCamera->targetReticleFocus);
        if (result == 0) {
            gCamcontrolCamera->targetReticleFocus = NULL;
        }
        if ((gCamcontrolTargetState == CAMCONTROL_TARGET_RETICLE_STATE_ACTIVE) &&
            (gCamcontrolCamera->targetReticleFocus != NULL)) {
            target = gCamcontrolCamera->targetReticleFocus;
            if ((target->anim.resetHitboxFlags & INTERACT_FLAG_PROMPT_SUPPRESSED) != 0) {
                gCamcontrolCamera->targetFlags =
                    gCamcontrolCamera->targetFlags | CAMCONTROL_CAMERA_TARGET_FLAG_PROMPT_SUPPRESSED;
            } else {
                gCamcontrolCamera->targetFlags =
                    gCamcontrolCamera->targetFlags & ~CAMCONTROL_CAMERA_TARGET_FLAG_PROMPT_SUPPRESSED;
            }
            target = gCamcontrolCamera->targetReticleFocus;
            objType = target->anim.romDefNo;
            switch (objType) {
            case 0x11:
            case 0xd8:
            case 0x13a:
            case 0x251:
            case 0x25d:
            case 0x281:
            case 0x369:
            case 0x3fe:
            case 0x427:
            case 0x457:
            case 0x458:
            case 0x4ac:
            case 0x4d7:
            case 0x58b:
            case 0x5b7:
            case 0x5b8:
            case 0x5b9:
            case 0x5e1:
            case 0x613:
            case 0x642:
            case 0x6a2:
            case 0x6a3:
            case 0x6a4:
            case 0x6a5:
            case 0x842:
            case 0x84b:
            case 0x851:
                targetDistance = enemy_getHealthFraction(target);
                break;
            case 0x3de:
            case 0x49f:
                targetDistance = LargeCrate_getReticleDistance(target);
                break;
            case 0x31:
                targetDistance = 1.0f;
                break;
            default:
                result = dll_19_isBaddieControlObject(target);
                if (result != 0) {
                    targetDistance = (*gBaddieControlInterface)->getHealthFraction(target);
                } else {
                    targetDistance = 1.0f;
                }
                break;
            }
            if (targetDistance <= 0.0f && gCamcontrolCamera->targetDistance > 0.0f) {
                objShowButtonGlow(reticle, 1.0f, 4);
            } else if (targetDistance <= 0.25f && gCamcontrolCamera->targetDistance > 0.25f) {
                objShowButtonGlow(reticle, 1.0f, 4);
            } else if (targetDistance <= 0.5f && gCamcontrolCamera->targetDistance > 0.5f) {
                objShowButtonGlow(reticle, 1.0f, 4);
            } else if (targetDistance <= 0.75f && gCamcontrolCamera->targetDistance > 0.75f) {
                objShowButtonGlow(reticle, 1.0f, 4);
            }
            gCamcontrolCamera->targetDistance = targetDistance;
        }
        alphaScale = 255.0f * reticle->currentMoveProgress;
        alphaScale = (alphaScale < 0.0f) ? 0.0f : ((alphaScale > 255.0f) ? 255.0f : alphaScale);
        reticle->alpha = alphaScale;
        gCamcontrolReticleSpin = CAMCONTROL_RETICLE_SPIN_STEP;
        reticle->rotX = (s16)(1024.0f * timeDelta + (float)reticle->rotX);
        break;
    }
}

int Camera_isZooming(void) {
    return gCamcontrolCamera->blendProgress > 0.0f;
}

void Camera_setTargetReticleOverride(GameObject* target) {
    gCamcontrolCamera->targetReticleOverride = target;
}

void Camera_setTarget(GameObject* target) {
    gCamcontrolCamera->overrideTarget = target;
    gCamcontrolCamera->currentTarget = target;
}

GameObject* Camera_getTarget(void) {
    return gCamcontrolCamera->currentTarget;
}

GameObject* Camera_getOverrideTarget(void) {
    return gCamcontrolCamera->overrideTarget;
}

void camcontrol_getRelativePosition(void* targetObj, f32* outX, f32* outY, f32* outZ, f32* outDistanceXZ,
                                    f32 heightOffset, int useLocalPosition) {
    ObjAnimComponent* focusObj;
    ObjAnimComponent* target;

    focusObj = gCamcontrolCamera->focusObj;
    target = targetObj;
    if (useLocalPosition != 0) {
        *outX = target->localPosX - focusObj->localPosX;
        *outY = target->localPosY - (focusObj->localPosY + heightOffset);
        *outZ = target->localPosZ - focusObj->localPosZ;
    } else {
        *outX = target->worldPosX - focusObj->worldPosX;
        *outY = target->worldPosY - (focusObj->worldPosY + heightOffset);
        *outZ = target->worldPosZ - focusObj->worldPosZ;
    }
    if (outDistanceXZ != NULL) {
        *outDistanceXZ = *outX * *outX + *outZ * *outZ;
        if (*outDistanceXZ > 0.0f) {
            *outDistanceXZ = sqrtf(*outDistanceXZ);
        }
        if (*outDistanceXZ < 5.0f) {
            *outDistanceXZ = 5.0f;
        }
    }
    return;
}

void camcontrol_initialise(f32 numerator, f32* dst, f32 denominator, f32 minValue, f32 y, f32 z) {
    f32 ratio;

    ratio = numerator / denominator;
    if (ratio < minValue) {
        ratio = minValue;
    }
    dst[0] = ratio;
    dst[1] = y;
    dst[2] = 0.0f;
    dst[3] = z;
}

void Camera_moveBy(f32 x, f32 y, f32 z) {
    gCamcontrolCamera->localX += x;
    gCamcontrolCamera->localY += y;
    gCamcontrolCamera->localZ += z;
}

void Camera_overridePos(f32 x, f32 y, f32 z) {
    gCamcontrolCamera->overrideWorldPosPending = 1;
    gCamcontrolCamera->overrideWorldX = x;
    gCamcontrolCamera->overrideWorldY = y;
    gCamcontrolCamera->overrideWorldZ = z;
}

void Camera_setFocus(void* target, int flags) {
    if (target == gCamcontrolCamera->focusObj) {
        return;
    }
    gCamcontrolCamera->focusObj = target;
}

static inline CamcontrolHandlerEntry* camcontrol_findDefaultHandler(void) {
    int handlerCount;
    register CamcontrolHandlerEntry** handlerEntry;
    int handlerIndex;

    handlerIndex = 0;
    handlerEntry = gCamcontrolHandlerEntries;
    for (handlerCount = gCamcontrolHandlerCount; 0 < handlerCount; handlerCount--) {
        if ((*handlerEntry)->actionId == CAMCONTROL_ACTION_DEFAULT) {
            return gCamcontrolHandlerEntries[handlerIndex];
        }
        handlerEntry++;
        handlerIndex++;
    }
    return NULL;
}

void camcontrol_loadTriggeredCamAction(int triggerType, int actionNo, int triggerMode) {
    CamcontrolHandlerEntry* defaultHandler;
    int blendFrames;
    CamcontrolTriggeredAction* camAction;
    int actionOffset;
    CamcontrolQueuedActionParam triggerType1Param;
    CamcontrolQueuedActionParam triggerType2Param;

    switch (triggerType) {
    case CAMCONTROL_TRIGGER_KIND_LOAD_ACTION:
        break;
    case CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE1:
        triggerType1Param.actionIndex = actionNo & CAMCONTROL_ACTION_INDEX_MASK;
        triggerType1Param.noBlendFlag = actionNo & CAMCONTROL_ACTION_FLAG_NO_BLEND;
        gCamcontrolCamera->blendCurveMode = 1;
        if (triggerType1Param.noBlendFlag != 0) {
            blendFrames = 0;
        } else {
            blendFrames = CAMCONTROL_DEFAULT_BLEND_FRAMES;
        }
        Camera_setMode(CAMCONTROL_ACTION_TRIGGER_TYPE1, 1, 0, sizeof(CamcontrolQueuedActionParam), &triggerType1Param,
                       blendFrames, CAMCONTROL_QUEUE_SENTINEL);
        return;
    case CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE2:
        triggerType2Param.actionIndex = actionNo & CAMCONTROL_ACTION_INDEX_MASK;
        triggerType2Param.noBlendFlag = (u8)(actionNo & CAMCONTROL_ACTION_FLAG_NO_BLEND);
        if (triggerType2Param.noBlendFlag != 0) {
            blendFrames = 0;
        } else {
            blendFrames = CAMCONTROL_DEFAULT_BLEND_FRAMES;
        }
        Camera_setMode(CAMCONTROL_ACTION_TRIGGER_TYPE2, 1, 0, sizeof(CamcontrolQueuedActionParam), &triggerType2Param,
                       blendFrames, CAMCONTROL_QUEUE_SENTINEL);
        return;
    case CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION:
        Camera_setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, 0, CAMCONTROL_DEFAULT_BLEND_FRAMES,
                       CAMCONTROL_QUEUE_SENTINEL);
        return;
    case CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION_OFFSET:
        Camera_setMode(actionNo + CAMCONTROL_ACTION_DEFAULT, 1, 0, 0, 0, CAMCONTROL_DEFAULT_BLEND_FRAMES,
                       CAMCONTROL_QUEUE_SENTINEL);
        return;
    }
    if (actionNo != CAMCONTROL_ACTION_NO_NONE) {
        if (actionNo == CAMCONTROL_ACTION_NO_NONE) {
            camAction = NULL;
        } else {
            camAction =
                (CamcontrolTriggeredAction*)mmAlloc(sizeof(CamcontrolTriggeredAction), CAMCONTROL_ACTION_HEAP, 0);
            if (camAction != NULL) {
                actionOffset = (actionNo - 1) * sizeof(CamcontrolTriggeredAction);
                getTabEntry(camAction, MLDF_FILEID_CAMACTIO_BIN, actionOffset, sizeof(CamcontrolTriggeredAction));
            }
        }
        if (camAction == NULL) {
            return;
        }
        camAction->triggerMode = triggerMode;
        SaveGame_setCamActionNo((short)actionNo);
        if (((((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_DEFAULT) &&
              ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGERED)) &&
             ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGER_TYPE1)) &&
            ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGER_TYPE2)) {
            defaultHandler = camcontrol_findDefaultHandler();
            defaultHandler->handler->vtable->actionCallback(camAction, sizeof(CamcontrolTriggeredAction));
        } else {
            switch (camAction->actionKind) {
            case CAMCONTROL_TRIGGERED_ACTION_KIND_DEFAULT:
            default:
                Camera_setMode(CAMCONTROL_ACTION_DEFAULT, 0, 2, sizeof(CamcontrolTriggeredAction), camAction, 0,
                               CAMCONTROL_QUEUE_SENTINEL);
                break;
            case CAMCONTROL_TRIGGERED_ACTION_KIND_TRIGGERED:
                Camera_setMode(CAMCONTROL_ACTION_TRIGGERED, 1, 2, sizeof(CamcontrolTriggeredAction), camAction, 0,
                               CAMCONTROL_QUEUE_SENTINEL);
                break;
            }
        }
        mm_free(camAction);
    } else {
        OSReport(sCamcontrolTriggeredCamActionLoadWarning, actionNo);
        camAction = (CamcontrolTriggeredAction*)mmAlloc(sizeof(CamcontrolTriggeredAction), CAMCONTROL_ACTION_HEAP, 0);
        if (camAction != NULL) {
            getTabEntry(camAction, MLDF_FILEID_CAMACTIO_BIN, 0, sizeof(CamcontrolTriggeredAction));
        }
        if (camAction == NULL) {
            return;
        }
        camAction->triggerMode = triggerMode;
        SaveGame_setCamActionNo(CAMCONTROL_FALLBACK_ACTION_NO);
        if (((((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_DEFAULT) &&
              ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGERED)) &&
             ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGER_TYPE1)) &&
            ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGER_TYPE2)) {
            defaultHandler = camcontrol_findDefaultHandler();
            defaultHandler->handler->vtable->actionCallback(camAction, sizeof(CamcontrolTriggeredAction));
        } else {
            switch (camAction->actionKind) {
            case CAMCONTROL_TRIGGERED_ACTION_KIND_DEFAULT:
            default:
                Camera_setMode(CAMCONTROL_ACTION_DEFAULT, 0, 2, sizeof(CamcontrolTriggeredAction), camAction, 0,
                               CAMCONTROL_QUEUE_SENTINEL);
                break;
            case CAMCONTROL_TRIGGERED_ACTION_KIND_TRIGGERED:
                Camera_setMode(CAMCONTROL_ACTION_TRIGGERED, 1, 2, sizeof(CamcontrolTriggeredAction), camAction, 0,
                               CAMCONTROL_QUEUE_SENTINEL);
                break;
            }
        }
        mm_free(camAction);
    }
    return;
}

CamcontrolTriggeredAction* Camera_getCamActionsBinEntry(int actionNo) {
    CamcontrolTriggeredAction* camAction;

    if (actionNo == CAMCONTROL_ACTION_NO_NONE) {
        return NULL;
    }
    camAction = mmAlloc(sizeof(CamcontrolTriggeredAction), CAMCONTROL_ACTION_HEAP, 0);
    if (camAction != NULL) {
        getTabEntry(camAction, MLDF_FILEID_CAMACTIO_BIN, (actionNo - 1) * sizeof(CamcontrolTriggeredAction),
                    sizeof(CamcontrolTriggeredAction));
    }
    return camAction;
}

void camcontrol_release(void* camAction, int recordSize) {
    CamcontrolHandlerEntry* currentHandler;

    currentHandler = gCamcontrolCurrentHandler;
    if (currentHandler != NULL) {
        currentHandler->handler->vtable->actionCallback(camAction, recordSize);
    }
}

void camcontrol_queueSavedAction(int blendFrames, u8 queueMode) {
    if (gCamcontrolSavedActionId != CAMCONTROL_SAVED_ACTION_NONE) {
        Camera_setMode(gCamcontrolSavedActionId, gCamcontrolSavedActionPriority, gCamcontrolSavedActionStartFlags, 0, 0,
                       blendFrames, queueMode);
    }
    return;
}

void Camera_setMode(s32 actionId, int priority, int startFlags, int dataSize, void* data, int blendFrames,
                    u8 queueMode) {
    if (gCamcontrolQueuedActionData != NULL) {
        mm_free(gCamcontrolQueuedActionData);
        gCamcontrolQueuedActionData = NULL;
        gCamcontrolQueuedActionPending = 0;
    }
    gCamcontrolQueuedActionId = actionId;
    gCamcontrolQueuedActionBlendFrames = blendFrames;
    if (data != NULL) {
        gCamcontrolQueuedActionData = mmAlloc(dataSize, CAMCONTROL_ACTION_HEAP, 0);
        memcpy(gCamcontrolQueuedActionData, data, dataSize);
    } else {
        gCamcontrolQueuedActionData = NULL;
    }
    if (actionId == CAMCONTROL_ACTION_DEFAULT) {
        gCamcontrolQueuedActionPriority = 0;
    } else {
        gCamcontrolQueuedActionPriority = priority;
    }
    gCamcontrolQueuedActionStartFlags = startFlags;
    gCamcontrolQueuedActionPending = 1;
    gCamcontrolQueuedActionMode = queueMode;
    return;
}

void* Camera_getDefaultHandlerEntry(void) {
    int i;

    i = 0;
    for (; i < gCamcontrolHandlerCount; i++) {
        if (gCamcontrolHandlerEntries[i]->actionId == CAMCONTROL_ACTION_DEFAULT) {
            return gCamcontrolHandlerEntries[i];
        }
    }
    return NULL;
}

void* Camera_getActiveHandler(void) {
    return gCamcontrolCurrentHandler;
}

int Camera_getMode(void) {
    return gCamcontrolActiveActionId;
}

void* Camera_get(void) {
    return gCamcontrolCamera;
}

void Camera_update(u8 framesThisStep) {
    ObjAnimComponent* focus;
    u8 textActive;
    GameObject* target;

    if (isFrontEndUiActive() != 0) {
        textActive = 1;
    } else {
        textActive = 0;
    }
    focus = gCamcontrolCamera->focusObj;
    if (focus == NULL) {
        gCamcontrolCamera->currentTarget = NULL;
        gCamcontrolCamera->overrideTarget = NULL;
    } else {
        gCamcontrolSavedFocusLocalX = focus->localPosX;
        gCamcontrolSavedFocusLocalY = focus->localPosY;
        gCamcontrolSavedFocusLocalZ = focus->localPosZ;
        gCamcontrolSavedFocusWorldX = focus->worldPosX;
        gCamcontrolSavedFocusWorldY = focus->worldPosY;
        gCamcontrolSavedFocusWorldZ = focus->worldPosZ;
        camcontrol_updateMoveAverage(gCamcontrolCamera, focus);
        if (gCamcontrolCamera->overrideWorldPosPending != 0) {
            focus->worldPosX = gCamcontrolCamera->overrideWorldX;
            focus->worldPosY = gCamcontrolCamera->overrideWorldY;
            focus->worldPosZ = gCamcontrolCamera->overrideWorldZ;
            Obj_TransformWorldPointToLocal(focus->worldPosX, focus->worldPosY, focus->worldPosZ, &focus->localPosX,
                                           &focus->localPosY, &focus->localPosZ, (GameObject*)focus->parent);
            gCamcontrolCamera->overrideWorldPosPending = 0;
        }
        if (gCamcontrolCamera->localFrameObj != focus->parent) {
            Obj_TransformLocalPointToWorld(gCamcontrolCamera->localX, gCamcontrolCamera->localY,
                                           gCamcontrolCamera->localZ, &gCamcontrolCamera->worldX,
                                           &gCamcontrolCamera->worldY, &gCamcontrolCamera->worldZ,
                                           gCamcontrolCamera->localFrameObj);
            Obj_TransformLocalPointToWorld(gCamcontrolCamera->prevLocalX, gCamcontrolCamera->prevLocalY,
                                           gCamcontrolCamera->prevLocalZ, &gCamcontrolCamera->prevWorldX,
                                           &gCamcontrolCamera->prevWorldY, &gCamcontrolCamera->prevWorldZ,
                                           gCamcontrolCamera->localFrameObj);
            Obj_TransformWorldPointToLocal(gCamcontrolCamera->worldX, gCamcontrolCamera->worldY,
                                           gCamcontrolCamera->worldZ, &gCamcontrolCamera->localX,
                                           &gCamcontrolCamera->localY, &gCamcontrolCamera->localZ,
                                           (GameObject*)focus->parent);
            Obj_TransformWorldPointToLocal(gCamcontrolCamera->prevWorldX, gCamcontrolCamera->prevWorldY,
                                           gCamcontrolCamera->prevWorldZ, &gCamcontrolCamera->prevLocalX,
                                           &gCamcontrolCamera->prevLocalY, &gCamcontrolCamera->prevLocalZ,
                                           (GameObject*)focus->parent);
            gCamcontrolCamera->localFrameObj = focus->parent;
        }
        if (focus->parent != NULL) {
            focus->rotX += ((ObjAnimComponent*)focus->parent)->rotX;
        }
        camcontrol_applyQueuedAction();
        if (gCamcontrolCurrentHandler != 0) {
            gCamcontrolCurrentHandler->handler->vtable->update(gCamcontrolCamera);
            Obj_TransformLocalPointToWorld(gCamcontrolCamera->localX, gCamcontrolCamera->localY,
                                           gCamcontrolCamera->localZ, &gCamcontrolCamera->worldX,
                                           &gCamcontrolCamera->worldY, &gCamcontrolCamera->worldZ,
                                           gCamcontrolCamera->localFrameObj);
            camcontrol_applyState(gCamcontrolCamera);
        }
        camcontrol_applyQueuedAction();
        if (textActive == 0) {
            if (gCamcontrolCamera->overrideTarget == NULL) {
                target = camcontrol_findBestTarget(gCamcontrolCamera, focus);
                gCamcontrolCamera->currentTarget = target;
            } else {
                gCamcontrolCamera->currentTarget = gCamcontrolCamera->overrideTarget;
            }
        }
        gCamcontrolCamera->prevLocalX = gCamcontrolCamera->localX;
        gCamcontrolCamera->prevLocalY = gCamcontrolCamera->localY;
        gCamcontrolCamera->prevLocalZ = gCamcontrolCamera->localZ;
        gCamcontrolCamera->prevWorldX = gCamcontrolCamera->worldX;
        gCamcontrolCamera->prevWorldY = gCamcontrolCamera->worldY;
        gCamcontrolCamera->prevWorldZ = gCamcontrolCamera->worldZ;
        gCamcontrolCamera->frameFlags = 0;
        focus->localPosX = gCamcontrolSavedFocusLocalX;
        focus->localPosY = gCamcontrolSavedFocusLocalY;
        focus->localPosZ = gCamcontrolSavedFocusLocalZ;
        focus->worldPosX = gCamcontrolSavedFocusWorldX;
        focus->worldPosY = gCamcontrolSavedFocusWorldY;
        focus->worldPosZ = gCamcontrolSavedFocusWorldZ;
        if (focus->parent != NULL) {
            focus->rotX -= ((ObjAnimComponent*)focus->parent)->rotX;
        }
    }
    return;
}

void Camera_init(void* focus, f32 x, f32 y, f32 z) {
    memset(gCamcontrolCamera, 0, sizeof(CamcontrolCameraState));
    gCamcontrolCamera->localX = x;
    gCamcontrolCamera->localY = y;
    gCamcontrolCamera->localZ = z;
    gCamcontrolCamera->worldX = x;
    gCamcontrolCamera->worldY = y;
    gCamcontrolCamera->worldZ = z;
    gCamcontrolCamera->prevLocalX = x;
    gCamcontrolCamera->prevLocalY = y;
    gCamcontrolCamera->prevLocalZ = z;
    gCamcontrolCamera->prevWorldX = x;
    gCamcontrolCamera->prevWorldY = y;
    gCamcontrolCamera->prevWorldZ = z;
    gCamcontrolCamera->focusObj = focus;
    gCamcontrolCamera->fovY = 60.0f;
    gCamcontrolTargetState = CAMCONTROL_TARGET_RETICLE_STATE_INACTIVE;
}

void Camera_release(void) {
    voxmaps_resetLoadedMaps();
    lbl_803DD4CB = -1;
}

void Camera_initialise(void) {
    gCamcontrolCamera = &gCamcontrolStateStorage.state;
    memset(gCamcontrolCamera, 0, sizeof(CamcontrolCameraState));
    voxmaps_initialise();
    gCamcontrolActiveActionId = -1;
    gCamcontrolCurrentHandlerIndex = -1;
    gCamcontrolQueuedActionId = -1;
    lbl_803DD4CC = 0;
    lbl_803DD4CB = -1;
    gCamcontrolTargetClassMask = 0xffff;
}

char sCamcontrolTriggeredCamActionLoadWarning[] = "<camcontrol.c>  failed to load triggered camaction actionno %d\n";
