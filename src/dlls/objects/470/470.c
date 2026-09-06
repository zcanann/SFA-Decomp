/*
 * DLL 0x1D6 cycles a model blend channel, scrolls two textures, conditionally
 * enables player hit reporting, and loads a pair of per-instance action rows.
 */

#include "dlls/objects/470.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/mldf_fileid.h"
#include "main/model.h"
#include "main/mm.h"
#include "main/object_render.h"
#include "main/objtexture.h"
#include "sys/objects.h"
#include "main/vecmath.h"
#include "main/asset_load.h"
#include "main/audio/sfx_play_api.h"
#include "main/objhits.h"

#define DLL1D6_ACTION_SLOT_COUNT  4
#define DLL1D6_ACTION_DATA_SIZE   40
#define DLL1D6_HIT_ENABLE_GAMEBIT 496

s16 gDll1D6SlotTabIndex[4] = {0x10A, 0x14F, 0x151, 0x153};
u8 gDll1D6SlotInUse[8] = {0};

int dll_1D6_getExtraSize(void) {
    return sizeof(Dll1D6State);
}

int dll_1D6_getObjectTypeId(void) {
    return 0;
}

void dll_1D6_free(GameObject* obj) {
    Dll1D6State* state = obj->extra;

    if ((state->flags & DLL1D6_STATE_FLAG_BOB_ACTIVE) != 0) {
        state->flags = (u8)(state->flags & ~DLL1D6_STATE_FLAG_BOB_ACTIVE);
    }
    mm_free(state->actionDataA);
    mm_free(state->actionDataB);
    gDll1D6SlotInUse[state->actionSlot] = 0;
}

void dll_1D6_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dll_1D6_hitDetect(void) {
}

static inline ObjModel* dll1d6_getActiveModel(GameObject* obj) {
    return obj->anim.modelBanks[obj->anim.bankIndex];
}

void dll_1D6_update(GameObject* obj) {
    Dll1D6State* state;
    const Dll1D6PlacementView* placement;
    ObjModel* model;
    ObjTextureRuntimeSlot* texture;
    GameObject* player;
    f32 transformStorage[20];
    s16 inverseRotation[6];
    f32 playerLocalX;
    f32 playerLocalY;
    f32 playerLocalZ;

    placement = (const Dll1D6PlacementView*)obj->anim.placementData;
    state = obj->extra;

    if ((state->flags & DLL1D6_STATE_FLAG_DOWN_PHASE) != 0) {
        if ((state->flags & DLL1D6_STATE_FLAG_BOB_ACTIVE) == 0) {
            state->flags |= DLL1D6_STATE_FLAG_BOB_ACTIVE;
            state->bobPhase = randomGetRange(20, 40);
            state->bobRate = randomGetRange(6, 10) / 20.0f;
        }
        state->downTimer -= framesThisStep;
        state->dizzyTimer = state->dizzyTimer - framesThisStep;
        if (state->dizzyTimer <= 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_en_trpopn_c_9f);
        }
        if (state->downTimer <= 0) {
            model = dll1d6_getActiveModel(obj);
            ObjModel_SetBlendChannelTargets(model, 0, -1, 0, 0.1f, 16);
            state->upTimer = placement->upTimer;
            if (state->upTimer < 15) {
                state->upTimer = 15;
            }
            state->flags &= ~DLL1D6_STATE_FLAG_DOWN_PHASE;
            Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_1f6);
        }
    } else {
        ObjModelBlendChannel* blendChannel;

        model = dll1d6_getActiveModel(obj);
        blendChannel = model->blendChannels;
        if (blendChannel != NULL && (state->flags & DLL1D6_STATE_FLAG_BOB_ACTIVE) != 0) {
            if (blendChannel->weight >= 1.0f) {
                state->flags &= ~DLL1D6_STATE_FLAG_BOB_ACTIVE;
            }
        }
        state->upTimer -= framesThisStep;
        if (state->upTimer <= 0) {
            ObjModel_SetBlendChannelTargets(model, 0, -1, 0, -0.1f, 16);
            state->downTimer = placement->downTimer;
            if (state->downTimer < 15) {
                state->downTimer = 15;
            }
            state->flags |= DLL1D6_STATE_FLAG_DOWN_PHASE;
            Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_1f7);
            state->dizzyTimer = 20;
        }
    }
    texture = objFindTexture(obj, 0, 0);
    {
        s16 negatedOffsetT = -texture->offsetT;
        int nextOffsetT = negatedOffsetT + 256;

        if ((s16)nextOffsetT > 2048) {
            nextOffsetT = nextOffsetT - 2048;
        }
        texture->offsetT = -nextOffsetT;
    }
    texture = objFindTexture(obj, 1, 0);
    {
        s16 negatedOffsetT = -texture->offsetT;
        int nextOffsetT = negatedOffsetT + 160;

        if ((s16)nextOffsetT > 2048) {
            nextOffsetT = nextOffsetT - 2048;
        }
        texture->offsetT = -nextOffsetT;
    }
    player = Obj_GetPlayerObject();
    transformStorage[0] = -obj->anim.localPosX;
    transformStorage[1] = -obj->anim.localPosY;
    transformStorage[2] = -obj->anim.localPosZ;
    inverseRotation[0] = -obj->anim.rotX;
    inverseRotation[1] = 0;
    inverseRotation[2] = 0;
    mtxRotateByVec3s(&transformStorage[3], inverseRotation);
    Matrix_TransformPoint(&transformStorage[3], player->anim.localPosX, player->anim.localPosY, player->anim.localPosZ,
                          &playerLocalX, &playerLocalY, &playerLocalZ);
    if ((state->flags & DLL1D6_STATE_FLAG_HIT_ENABLED) != 0) {
        playerLocalY = obj->anim.localPosY - player->anim.localPosY;
        if (playerLocalY < 0.0f) {
            playerLocalY = -playerLocalY;
        }
        if (playerLocalY < 50.0f) {
            playerLocalZ = playerLocalZ * playerLocalZ;
            if (playerLocalZ <= state->hitRangeSqA) {
                int* modelRow;
                f32 hitLimit;

                model = dll1d6_getActiveModel(obj);
                {
                    char* modelRowStorage = (char*)model + 4;

                    modelRow = *(int**)(modelRowStorage + ((model->bufferFlags >> 1) & 1) * 4);
                }
                hitLimit = obj->anim.rootMotionScale * (f32)(int)*(s16*)((char*)modelRow + state->hitRow * 16);
                if (playerLocalX <= hitLimit) {
                    ObjHits_RecordObjectHit(player, obj, 11, 4, 0);
                }
            }
        }
    }
    if ((state->flags & DLL1D6_STATE_FLAG_BOB_ACTIVE) != 0) {
        state->bobPhase = state->bobRate * timeDelta + state->bobPhase;
        if (state->bobPhase > 40.0f) {
            state->bobRate = -(f32)randomGetRange(6, 10) / 20.0f;
            state->bobPhase = 40.0f;
        } else if (state->bobPhase < 20.0f) {
            state->bobRate = randomGetRange(6, 10) / 20.0f;
            state->bobPhase = 20.0f;
        }
    }
    if (mainGetBit(DLL1D6_HIT_ENABLE_GAMEBIT) != 0) {
        state->flags |= DLL1D6_STATE_FLAG_HIT_ENABLED;
    } else {
        state->flags &= ~DLL1D6_STATE_FLAG_HIT_ENABLED;
    }
}

void dll_1D6_init(GameObject* obj, const Dll1D6PlacementView* placement) {
    Dll1D6State* state;
    ObjModel* model;
    int i;

    obj->anim.rotX = (s16)(placement->rotationXByte << 8);
    state = obj->extra;
    model = dll1d6_getActiveModel(obj);
    ObjModel_SetBlendChannelTargets(model, 0, -1, 0, 0.0f, 0);
    ObjModel_SetBlendChannelWeight(model, 0, 1.0f);
    state->upTimer = placement->upTimer;
    if (state->upTimer < 15) {
        state->upTimer = 15;
    }
    state->downTimer = placement->downTimer;
    if (state->downTimer < 15) {
        state->downTimer = 15;
    }
    {
        f32 k = 0.0f;

        state->hitRangeSqA = k * obj->anim.rootMotionScale;
        state->hitRangeSqA = state->hitRangeSqA * state->hitRangeSqA;
        state->hitRangeSqB = k * obj->anim.rootMotionScale;
        state->hitRangeSqB = state->hitRangeSqB * state->hitRangeSqB;
    }
    state->flags = mainGetBit(DLL1D6_HIT_ENABLE_GAMEBIT) ? DLL1D6_STATE_FLAG_HIT_ENABLED : 0;
    for (i = 0; i < DLL1D6_ACTION_SLOT_COUNT; i++) {
        if (gDll1D6SlotInUse[i] == 0) {
            gDll1D6SlotInUse[i] = 1;
            state->actionSlot = i;
            i = DLL1D6_ACTION_SLOT_COUNT;
        }
    }
    state->actionDataA = mmAlloc(DLL1D6_ACTION_DATA_SIZE, 18, 0);
    getTabEntry(state->actionDataA, MLDF_FILEID_LACTIONS_BIN,
                gDll1D6SlotTabIndex[state->actionSlot] * DLL1D6_ACTION_DATA_SIZE, DLL1D6_ACTION_DATA_SIZE);
    state->actionDataB = mmAlloc(DLL1D6_ACTION_DATA_SIZE, 18, 0);
    getTabEntry(state->actionDataB, MLDF_FILEID_LACTIONS_BIN,
                (gDll1D6SlotTabIndex[state->actionSlot] + 1) * DLL1D6_ACTION_DATA_SIZE, DLL1D6_ACTION_DATA_SIZE);
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void dll_1D6_release(void) {
}

void dll_1D6_initialise(void) {
}

ObjectDescriptor gDll1D6ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_1D6_initialise,
    (ObjectDescriptorCallback)dll_1D6_release,
    0,
    (ObjectDescriptorCallback)dll_1D6_init,
    (ObjectDescriptorCallback)dll_1D6_update,
    (ObjectDescriptorCallback)dll_1D6_hitDetect,
    (ObjectDescriptorCallback)dll_1D6_render,
    (ObjectDescriptorCallback)dll_1D6_free,
    (ObjectDescriptorCallback)dll_1D6_getObjectTypeId,
    dll_1D6_getExtraSize,
};
