#include "dlls/objects/364.h"

#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/obj_path.h"
#include "main/objtype.h"
#include "main/shader_api.h"
#include "main/objseq.h"

#define IM_SNOW_CLAW_SEQ_ID             0x16D
#define IM_SNOW_CLAW_MOUNT_SEQ_ID       0x16C
#define IM_SNOW_CLAW_2_SEQ_ID           0x170
#define IM_SNOW_CLAW_2_MOUNT_SEQ_ID     0x16F
#define IM_SNOW_CLAW_RENDER_GATE_SEQ_ID 0x373

#define IM_SNOW_CLAW_MOUNT_OBJECT_GROUP 10
#define IM_SNOW_CLAW_CHILD_SETUP_SIZE   0x18
#define IM_SNOW_CLAW_MOVE_ID            0x100
#define IM_SNOW_CLAW_FULL_ALPHA         0xFF
#define IM_SNOW_CLAW_MOUNT_ACTIVE_FLAG  0x8
#define IM_SNOW_CLAW_FADE_START         600.0f
#define IM_SNOW_CLAW_FADE_RANGE         50.0f

const IMSnowClawDropObjectTable gIMSnowClawDropObjectTable = {{0x23, 0x69, 0x33, 0x64, 0x1D}};

void imSnowClaw_syncMountTransform(GameObject* obj, GameObject* mount, int renderArg2, int renderArg3, int renderArg4,
                                   int renderArg5, int visible, int mountAlpha, int renderMount) {
    if (renderMount != 0 && (s8)visible != 0 && mountAlpha > 0) {
        u8 savedAlpha = mount->anim.renderAlpha;

        mount->anim.renderAlpha = mountAlpha;
        (*(IMSnowClawMountInterface**)mount->anim.dll)
            ->render(mount, renderArg2, renderArg3, renderArg4, renderArg5, -1);
        mount->anim.renderAlpha = savedAlpha;
    }

    obj->anim.previousWorldPosX = obj->anim.worldPosX;
    obj->anim.previousWorldPosY = obj->anim.worldPosY;
    obj->anim.previousWorldPosZ = obj->anim.worldPosZ;
    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosZ = obj->anim.localPosZ;
    {
        f32 positionX;
        f32 positionY;
        f32 positionZ;

        (*(IMSnowClawMountInterface**)mount->anim.dll)->getPosition(mount, &positionX, &positionY, &positionZ);
        obj->anim.localPosX = positionX;
        obj->anim.localPosY = positionY;
        obj->anim.localPosZ = positionZ;
    }

    obj->anim.rotX = mount->anim.rotX;
    obj->anim.rotY = mount->anim.rotY;
    obj->anim.rotZ = mount->anim.rotZ;
    obj->anim.worldPosX = obj->anim.localPosX;
    obj->anim.worldPosY = obj->anim.localPosY;
    obj->anim.worldPosZ = obj->anim.localPosZ;
    obj->anim.velocityX = mount->anim.velocityX;
    obj->anim.velocityY = mount->anim.velocityY;
    obj->anim.velocityZ = mount->anim.velocityZ;
}

static void imSnowClaw_advanceLinkedMove(GameObject* obj, GameObject* mount) {
    f32 moveAmount;
    f32 moveStep;
    int moveNegative;

    if (obj->anim.currentMove != IM_SNOW_CLAW_MOVE_ID) {
        ObjAnim_SetCurrentMove(obj, IM_SNOW_CLAW_MOVE_ID, 0.0f, 0);
    }
    (*(IMSnowClawMountInterface**)mount->anim.dll)->getNormalizedSpeed(mount, &moveStep);
    moveStep = 0.01f;
    (*(IMSnowClawMountInterface**)mount->anim.dll)->func12(mount, &moveAmount, &moveNegative);
    ObjAnim_AdvanceCurrentMove(obj, moveStep, (f32)(u32)framesThisStep, NULL);
}

int imSnowClaw_sequenceCallback(GameObject* obj, int unusedArg2, ObjSeqState* animUpdate) {
    GameObject* mount;
    IMSnowClawState* state = obj->extra;
    IMSnowClawDropObjectTable dropObjectTable;

    state->mountAlpha = IM_SNOW_CLAW_FULL_ALPHA;
    mount = state->mount;
    if (animUpdate->curEventId == 3) {
        state->dropObjectIndex = -1;
        animUpdate->curEventId = 0;
    }
    dropObjectTable = gIMSnowClawDropObjectTable;

    if (state->dropObjectIndex != state->appliedDropObjectIndex) {
        if (obj->childObjs[0] != NULL) {
            Obj_FreeObject((GameObject*)obj->childObjs[0]);
            obj->childObjs[0] = NULL;
            obj->childCount = 0;
        }
        if (Obj_IsLoadingLocked()) {
            s8 dropObjectIndex = state->dropObjectIndex;

            if (dropObjectIndex > 0) {
                obj->childObjs[0] = objSetupObject(
                    Obj_AllocObjectSetup(IM_SNOW_CLAW_CHILD_SETUP_SIZE, dropObjectTable.objectIds[dropObjectIndex - 1]),
                    4, -1, -1, obj->anim.parent);
                obj->childCount = 1;
            }
            state->appliedDropObjectIndex = state->dropObjectIndex;
        } else {
            state->appliedDropObjectIndex = 0;
        }
    }

    animUpdate->flags = animUpdate->savedFlags;

    if (mount != NULL && animUpdate->curEventId == 2) {
        state->unknown04 = 1.0f;
        state->mountSnapX = state->pathPointX;
        state->mountSnapY = state->pathPointY;
        state->mountSnapZ = state->pathPointZ;
        (*(IMSnowClawMountInterface**)mount->anim.dll)->setRiderMode(mount, 2);
        ObjAnim_SetCurrentMove(obj, IM_SNOW_CLAW_MOVE_ID, 0.0f, 1);
        if (obj->anim.modelState != NULL) {
            obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        animUpdate->flags &= ~4;
        animUpdate->curEventId = 0;
    } else if (mount != NULL && animUpdate->curEventId == 1) {
        (*(IMSnowClawMountInterface**)mount->anim.dll)->setRiderMode(mount, 0);
        animUpdate->curEventId = 0;
    }

    if (mount != NULL) {
        if ((*(IMSnowClawMountInterface**)mount->anim.dll)->getRiderMode(mount) == 2) {
            animUpdate->flags &= ~3;
        }
    }
    return 0;
}

int imSnowClaw_getExtraSize(void) {
    return sizeof(IMSnowClawState);
}

int imSnowClaw_getObjectTypeId(void) {
    return 3;
}

void imSnowClaw_free(GameObject* obj) {
    GameObject* child = obj->childObjs[0];

    if (child != NULL) {
        Obj_FreeObject(child);
    }
}

void imSnowClaw_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    IMSnowClawState* state;
    GameObject* mount;
    int mountActive;

    if (obj->anim.romDefNo != IM_SNOW_CLAW_RENDER_GATE_SEQ_ID) {
        if (mainGetBit(GAMEBIT_IM_TrickyRelated006E) != 0) {
            if (mainGetBit(GAMEBIT_IM_HutRelated0382) == 0) {
                return;
            }
        }

        state = obj->extra;
        mount = state->mount;
        mountActive = 0;
        if (mount != NULL) {
            if ((*(IMSnowClawMountInterface**)mount->anim.dll)->getRiderMode(mount) == 2) {
                mountActive = 1;
            }
        }
        if (mountActive != 0) {
            obj->anim.flags |= IM_SNOW_CLAW_MOUNT_ACTIVE_FLAG;
            visible = objUpdateOpacity(mount);
            ((void (*)(GameObject*, GameObject*, int, int, int, int, int, int, int))imSnowClaw_syncMountTransform)(
                obj, mount, renderArg2, renderArg3, renderArg4, renderArg5, visible, state->mountAlpha, 1);
        } else {
            obj->anim.flags &= ~IM_SNOW_CLAW_MOUNT_ACTIVE_FLAG;
        }
        if (visible != 0 && state->mountAlpha != 0) {
            u8 savedAlpha = obj->anim.renderAlpha;

            if (mountActive != 0) {
                obj->anim.renderAlpha = state->mountAlpha;
            }
            objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
            ObjPath_GetPointWorldPosition(obj, 1, &state->pathPointX, &state->pathPointY, &state->pathPointZ, 0);
            obj->anim.renderAlpha = savedAlpha;
        }
    } else {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void imSnowClaw_hitDetect(GameObject* obj) {
    IMSnowClawState* state = obj->extra;
    GameObject* mount = state->mount;

    if (mount != NULL) {
        if ((*(IMSnowClawMountInterface**)mount->anim.dll)->getRiderMode(mount) == 2) {
            ((void (*)(GameObject*, GameObject*, int, int, int, int, int, int, int))imSnowClaw_syncMountTransform)(
                obj, state->mount, 0, 0, 0, 0, 0, 0, 0);
        }
    }
}

void imSnowClaw_update(GameObject* obj) {
    IMSnowClawState* state = obj->extra;
    IMSnowClawDropObjectTable dropObjectTable;

    dropObjectTable = gIMSnowClawDropObjectTable;
    if (state->dropObjectIndex != state->appliedDropObjectIndex) {
        if (obj->childObjs[0] != NULL) {
            Obj_FreeObject((GameObject*)obj->childObjs[0]);
            obj->childObjs[0] = NULL;
            obj->childCount = 0;
        }
        if (Obj_IsLoadingLocked()) {
            s8 dropObjectIndex = state->dropObjectIndex;

            if (dropObjectIndex > 0) {
                obj->childObjs[0] = objSetupObject(
                    Obj_AllocObjectSetup(IM_SNOW_CLAW_CHILD_SETUP_SIZE, dropObjectTable.objectIds[dropObjectIndex - 1]),
                    4, -1, -1, obj->anim.parent);
                obj->childCount = 1;
            }
            state->appliedDropObjectIndex = state->dropObjectIndex;
        } else {
            state->appliedDropObjectIndex = 0;
        }
    }

    if (state->mount == NULL) {
        GameObject** objects;
        int objectCount;
        int objectIndex;
        int mountSeqId;

        objects = (GameObject**)objGetAllOfType(IM_SNOW_CLAW_MOUNT_OBJECT_GROUP, &objectCount);
        switch (obj->anim.romDefNo) {
        case IM_SNOW_CLAW_SEQ_ID:
        case IM_SNOW_CLAW_RENDER_GATE_SEQ_ID:
        default:
            mountSeqId = IM_SNOW_CLAW_MOUNT_SEQ_ID;
            break;
        case IM_SNOW_CLAW_2_SEQ_ID:
            mountSeqId = IM_SNOW_CLAW_2_MOUNT_SEQ_ID;
            break;
        }
        for (objectIndex = 0; objectIndex < objectCount; objectIndex++) {
            if (mountSeqId == objects[objectIndex]->anim.romDefNo) {
                state->mount = objects[objectIndex];
                objectIndex = objectCount;
            }
        }
    }

    if (obj->anim.romDefNo == IM_SNOW_CLAW_RENDER_GATE_SEQ_ID || mainGetBit(GAMEBIT_IM_BikeRelated03A2) != 0) {
        imSnowClaw_advanceLinkedMove(obj, state->mount);
        if (state->mount != NULL) {
            f32 distanceFade;
            GameObject* player = Obj_GetPlayerObject();

            distanceFade = Vec_distance(&state->mount->anim.worldPosX, &player->anim.worldPosX);
            distanceFade = (distanceFade - IM_SNOW_CLAW_FADE_START) / IM_SNOW_CLAW_FADE_RANGE;
            if (distanceFade < 0.0f) {
                distanceFade = 0.0f;
            } else if (distanceFade > 1.0f) {
                distanceFade = 1.0f;
            }
            distanceFade = 1.0f - distanceFade;
            state->mountAlpha = 255.0f * distanceFade;
            if (obj->anim.modelState != NULL) {
                obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
        } else {
            state->mountAlpha = IM_SNOW_CLAW_FULL_ALPHA;
            if (obj->anim.modelState != NULL) {
                obj->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
        }
    }
}

void imSnowClaw_init(GameObject* obj, IMSnowClawPlacement* placement) {
    IMSnowClawState* state;

    obj->animEventCallback = imSnowClaw_sequenceCallback;
    if (obj->anim.modelState != NULL) {
        obj->anim.modelState->flags |= OBJ_MODEL_STATE_UNREAD_4000;
        obj->anim.modelState->shadowTintA = 100;
        obj->anim.modelState->shadowTintB = 150;
    }
    state = obj->extra;
    state->mount = NULL;
    state->dropObjectIndex = placement->dropObjectIndex;
    state->mountAlpha = IM_SNOW_CLAW_FULL_ALPHA;
}

void imSnowClaw_release(void) {
}

void imSnowClaw_initialise(void) {
}

ObjectDescriptor gIMSnowClawObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imSnowClaw_initialise,
    (ObjectDescriptorCallback)imSnowClaw_release,
    0,
    (ObjectDescriptorCallback)imSnowClaw_init,
    (ObjectDescriptorCallback)imSnowClaw_update,
    (ObjectDescriptorCallback)imSnowClaw_hitDetect,
    (ObjectDescriptorCallback)imSnowClaw_render,
    (ObjectDescriptorCallback)imSnowClaw_free,
    (ObjectDescriptorCallback)imSnowClaw_getObjectTypeId,
    imSnowClaw_getExtraSize,
};
