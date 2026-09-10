/*
 * DFP_wallbar (DLL slot 560 / 0x230) displays the selected safe-floor tile
 * using model variants and rotation, reading the solution from the level
 * controller. The exported callback names retain their existing chuka prefix.
 */
#include "dlls/objects/560_DFP_wallbar.h"

#include "main/dll_000A_expgfx.h"
#include "dlls/objects/553_DFP_LevelCo.h"
#include "main/gamebits.h"
#include "main/obj_list.h"
#include "sys/objects.h"

int chuka_SeqFn(void) {
    return 0x0;
}
int chuka_getExtraSize(void) {
    return sizeof(DfpWallbarState);
}
int chuka_getObjectTypeId(void) {
    return 0x0;
}

void chuka_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((int)obj);
}

void chuka_render(void) {
}

void chuka_hitDetect(GameObject* obj) {
    GameObject* levelController;
    DfpWallbarState* state = obj->extra;
    levelController = state->levelController;
    if (levelController == NULL) {
        return;
    }
    if ((levelController->anim.flags & 0x40) == 0) {
        return;
    }
    state->levelController = 0;
}

void chuka_update(GameObject* obj) {
    DfpWallbarPlacementPrefix* data = (DfpWallbarPlacementPrefix*)obj->anim.placementData;
    DfpWallbarState* state = obj->extra;
    GameObject* levelController;
    GameObject** objList;
    GameObject* candidate;
    int i;
    int scaleDivisor;
    int firstIdx;
    int count;
    ObjAnimComponent* objAnim = &obj->anim;

    levelController = state->levelController;
    if (levelController != NULL) {
        if (levelController->anim.flags & 0x40) {
            state->levelController = 0;
            return;
        }
    }
    if ((void*)levelController == NULL) {
        objList = ObjList_GetObjects(&firstIdx, &count);
        for (i = firstIdx; i < count; i++) {
            candidate = (GameObject*)objList[i];
            if (candidate->anim.romDefNo == DFP_LEVEL_CONTROL_OBJECT_ID) {
                state->levelController = candidate;
                i = count;
            }
        }
        if (state->levelController == NULL) {
            return;
        }
    }
    levelController = state->levelController;
    DFP_LEVEL_CONTROL_INTERFACE(levelController)->copySafeFloorTiles(levelController, gDFPWallbarSafeFloorTiles);
    if (mainGetBit(GAMEBIT_OFP_PuzzlePadShowSolution) == 0) {
        state->safeTileIndex = 0;
    } else {
        state->safeTileIndex = gDFPWallbarSafeFloorTiles[state->rowIndex];
    }
    switch (state->safeTileIndex) {
    case 0:
        if (objAnim->bankIndex != 0) {
            Obj_SetActiveModelIndex(obj, 0);
        }
        scaleDivisor = data->motionScaleDivisor;
        if (scaleDivisor != 0) {
            obj->anim.rootMotionScale = 1.0f / ((f32)scaleDivisor / 1000.0f);
        }
        break;
    case 1:
        if (objAnim->bankIndex != 1) {
            Obj_SetActiveModelIndex(obj, 1);
        }
        scaleDivisor = data->motionScaleDivisor;
        if (scaleDivisor != 0) {
            obj->anim.rootMotionScale = 1.0f / ((f32)scaleDivisor / 1000.0f);
        }
        if (obj->anim.rotZ != 0) {
            obj->anim.rotZ = 0;
        }
        break;
    case 2:
        if (objAnim->bankIndex != 2) {
            Obj_SetActiveModelIndex(obj, 2);
        }
        scaleDivisor = data->motionScaleDivisor;
        if (scaleDivisor != 0) {
            obj->anim.rootMotionScale = 1.0f / ((f32)scaleDivisor / 1000.0f);
        }
        if (obj->anim.rotZ != 0) {
            obj->anim.rotZ = 0;
        }
        break;
    case 3:
        if (objAnim->bankIndex != 2) {
            Obj_SetActiveModelIndex(obj, 2);
        }
        scaleDivisor = data->motionScaleDivisor;
        if (scaleDivisor != 0) {
            obj->anim.rootMotionScale = 1.0f / ((f32)scaleDivisor / 1000.0f);
        }
        if (obj->anim.rotZ != 0x3fff) {
            obj->anim.rotZ = 0x7fff;
        }
        break;
    case 4:
        if (objAnim->bankIndex != 1) {
            Obj_SetActiveModelIndex(obj, 1);
        }
        scaleDivisor = data->motionScaleDivisor;
        if (scaleDivisor != 0) {
            obj->anim.rootMotionScale = 1.0f / ((f32)scaleDivisor / 1000.0f);
        }
        if (obj->anim.rotZ != 0x3fff) {
            obj->anim.rotZ = 0x7fff;
        }
        break;
    default:
        if (objAnim->bankIndex != 0) {
            Obj_SetActiveModelIndex(obj, 0);
        }
        scaleDivisor = data->motionScaleDivisor;
        if (scaleDivisor != 0) {
            obj->anim.rootMotionScale = 1.0f / ((f32)scaleDivisor / 1000.0f);
        }
        if (obj->anim.rotZ != 0) {
            obj->anim.rotZ = 0;
        }
        break;
    }
}

void chuka_init(GameObject* obj, DfpWallbarPlacementPrefix* params) {
    DfpWallbarState* state = obj->extra;
    DfpWallbarPlacementPrefix* placement = params;
    u8* safeFloorTiles;

    obj->anim.rotX = (s16)(placement->rotationHighByte << 8);
    obj->animEventCallback = chuka_SeqFn;
    state->initialLocalPosY = obj->anim.localPosY;
    state->rowIndex = placement->rowIndex;

    if (placement->motionScaleDivisor != 0) {
        obj->anim.rootMotionScale = 1.0f / ((f32)placement->motionScaleDivisor / 1000.0f);
    }

    if (placement->initialRotZ != 0) {
        obj->anim.rotZ = placement->initialRotZ;
    }

    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
    state->levelController = 0;

    safeFloorTiles = gDFPWallbarSafeFloorTiles;
    {
        int i;
        for (i = 9; i != 0; i--) {
            *safeFloorTiles = 0;
            safeFloorTiles++;
        }
    }
}

void chuka_release(void) {
}

void chuka_initialise(void) {
}

u8 gDFPWallbarSafeFloorTiles[9] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0,
};

ObjectDescriptor10WithPadding gChukaObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)chuka_initialise,
        (ObjectDescriptorCallback)chuka_release,
        0,
        (ObjectDescriptorCallback)chuka_init,
        (ObjectDescriptorCallback)chuka_update,
        (ObjectDescriptorCallback)chuka_hitDetect,
        (ObjectDescriptorCallback)chuka_render,
        (ObjectDescriptorCallback)chuka_free,
        (ObjectDescriptorCallback)chuka_getObjectTypeId,
        chuka_getExtraSize,
    },
    0,
};
