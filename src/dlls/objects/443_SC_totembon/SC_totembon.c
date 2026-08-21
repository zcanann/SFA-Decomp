/*
 * SC_totembon (DLL 0x1BB) coordinates the LightFoot Village totem-bond
 * sequence and its ring of LightFoot objects.
 */

#include "dlls/objects/443_SC_totembon.h"

#include "dlls/objects/437.h"
#include "dlls/objects/440_SC_totempol.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0044_cameramodeviewfinder.h"
#include "main/dll/player_api.h"
#include "main/dll/tricky_api.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/obj_list.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "main/screen_transition.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

/*
 * Cross-object setup overlay for the slot 437 LightFoot objects allocated by
 * this unit. The 0x38-byte allocation is explicit at the construction site.
 */
typedef struct ScTotemBondLightfootSetup {
    ObjPlacement base;
    s16 unknown18;
    s16 completionGameBit;
    s16 eventGameBit;
    u8 unknown1E[0x2A - 0x1E];
    s8 rotationByte;
    u8 unknown2B[0x30 - 0x2B];
    s16 activeGameBit;
    u8 unknown32;
    u8 unknown33[0x38 - 0x33];
} ScTotemBondLightfootSetup;

STATIC_ASSERT(offsetof(ScTotemBondLightfootSetup, base) == 0x00);
STATIC_ASSERT(offsetof(ScTotemBondLightfootSetup, unknown18) == 0x18);
STATIC_ASSERT(offsetof(ScTotemBondLightfootSetup, completionGameBit) == 0x1A);
STATIC_ASSERT(offsetof(ScTotemBondLightfootSetup, eventGameBit) == 0x1C);
STATIC_ASSERT(offsetof(ScTotemBondLightfootSetup, unknown1E) == 0x1E);
STATIC_ASSERT(offsetof(ScTotemBondLightfootSetup, rotationByte) == 0x2A);
STATIC_ASSERT(offsetof(ScTotemBondLightfootSetup, unknown2B) == 0x2B);
STATIC_ASSERT(offsetof(ScTotemBondLightfootSetup, activeGameBit) == 0x30);
STATIC_ASSERT(offsetof(ScTotemBondLightfootSetup, unknown32) == 0x32);
STATIC_ASSERT(offsetof(ScTotemBondLightfootSetup, unknown33) == 0x33);
STATIC_ASSERT(sizeof(ScTotemBondLightfootSetup) == 0x38);

#define SC_TOTEM_BOND_CAMERA_MODE_DEFAULT    0x42

#define SC_TOTEM_BOND_MAP_SWAPCIRCLE 0xE

#define SC_TOTEM_BOND_RING_ANGLE_STEP         0x2000
#define SC_TOTEM_BOND_EVENT_START_ORBS        0x01
#define SC_TOTEM_BOND_EVENT_ORBS_ACTIVE       0x02
#define SC_TOTEM_BOND_EVENT_SET_MAP_MODE      0x10
#define SC_TOTEM_BOND_GAMEBIT_COMPLETE        0x2BC
#define SC_TOTEM_BOND_SCREEN_TRANSITION       0x1E
#define SC_TOTEM_BOND_SCREEN_TRANSITION_STATE 1
#define SC_TOTEM_BOND_LIGHTFOOT_ALPHA         0x1E

#define SC_TOTEM_BOND_COMPLETION_DELAY 35.0f
#define SC_TOTEM_BOND_CAMERA_DISTANCE  72.0f
#define SC_TOTEM_BOND_ROTATION_SPEED   512.0f

const f32 gScTotemBondInitialRadius[1] = {-130.0f};
const f32 gScTotemBondThirty[1] = {30.0f};

static inline void sc_totembond_beginOrbGame(GameObject* obj, ScTotemBondState* state) {
    state->active = 1;
    obj->anim.rotX = 0x3FFF;
    state->ringIndex = (s16)(u16)((s32)obj->anim.rotX / SC_TOTEM_BOND_RING_ANGLE_STEP);
    ObjHits_DisableObject(obj);
    sc_totembond_spawnGameBitOrbs(obj, state, gScTotemBondInitialRadius[0]);
    mainSetBits(gTotemBondRingGameBits[state->ringIndex], 1);
    obj->anim.alpha = 0;
    state->eventFlags &= ~SC_TOTEM_BOND_EVENT_START_ORBS;
    state->eventFlags |= SC_TOTEM_BOND_EVENT_ORBS_ACTIVE;
    (*gGameUIInterface)->setCMenuShouldClose(1);
    setHudForceShowMask(1);
    (*gScreenTransitionInterface)->step(SC_TOTEM_BOND_SCREEN_TRANSITION, SC_TOTEM_BOND_SCREEN_TRANSITION_STATE);
    state->spawnTimer = gScTotemBondThirty[0];
    Music_Trigger(MUSICTRIG_WLC_Puzzle_f0, 1);
}

void sc_totembond_spawnGameBitOrbs(GameObject* obj, ScTotemBondState* state, f32 radius) {
    s32 angleOffset;
    ScTotemBondLightfootSetup* setup;
    const u8* definition;
    s8 i;
    s8 orbIndex;
    u8 canSetupObject;

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject > 0) {
        i = 0;
        orbIndex = 1;
        angleOffset = 0;
        while (i < SC_TOTEM_BOND_GAMEBIT_COUNT) {
            definition = (const u8*)obj->anim.placementData;
            setup = (ScTotemBondLightfootSetup*)Obj_AllocObjectSetup(sizeof(ScTotemBondLightfootSetup),
                                                                     DLL1B5_SEQUENCE_ID_SC_LIGHTFOOT);
            setup->base.posX = radius * mathSinf((3.1415927f * (f32)(s32)(obj->anim.rotX + angleOffset)) / 32768.0f) +
                               obj->anim.localPosX;
            setup->base.posY = obj->anim.localPosY;
            setup->base.posZ = radius * mathCosf((3.1415927f * (f32)(s32)(obj->anim.rotX + angleOffset)) / 32768.0f) +
                               obj->anim.localPosZ;
            setup->base.color[0] = definition[0x04];
            setup->base.color[1] = (definition[0x05] & ~1) | 4;
            setup->base.color[2] = definition[0x06];
            setup->base.color[3] = SC_TOTEM_BOND_LIGHTFOOT_ALPHA;
            setup->unknown18 = -1;
            setup->completionGameBit = DLL1B5_COMPLETION_GAMEBIT_SC_TOTEM_BOND;
            setup->eventGameBit = gTotemBondOrbGameBits[orbIndex];
            setup->activeGameBit = gTotemBondRingGameBits[orbIndex];
            setup->rotationByte = (s8)(((obj->anim.rotX + 0x8000) + angleOffset) >> 8);
            setup->unknown32 = 1;
            objSetupObject(&setup->base, 5, -1, -1, 0);
            orbIndex++;
            if (orbIndex > 7) {
                orbIndex = 0;
            }
            angleOffset += SC_TOTEM_BOND_RING_ANGLE_STEP;
            i++;
        }
    }
}

u32 sc_totembond_SeqFn(GameObject* obj, u32 unused, ObjSeqState* animUpdate) {
    ScTotemBondState* state;
    int countForEvent2;
    int startForEvent2;
    int countForEvent3;
    int startForEvent3;
    GameObject** objects;
    int eventIndex;
    int eventId;

    (void)unused;

    state = obj->extra;
    animUpdate->movementState = 0;
    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        eventId = animUpdate->eventIds[eventIndex];
        switch (eventId) {
        case 1:
            state->eventFlags |= SC_TOTEM_BOND_EVENT_START_ORBS;
            (*gObjectTriggerInterface)->setCamVars(CAMERA_MODE_VIEWFINDER_RESOURCE_ID, 1, 0, 0);
            break;
        case 2:
            objects = ObjList_GetObjects(&startForEvent2, &countForEvent2);
            for (; startForEvent2 < countForEvent2; startForEvent2++) {
                if (objects[startForEvent2] != obj &&
                    objects[startForEvent2]->anim.romDefNo == SC_TOTEM_POLE_SEQUENCE_ID) {
                    (*(ScTotemPoleInterfaceVTable**)objects[startForEvent2]->anim.dll)
                        ->handleEvent(objects[startForEvent2], 2);
                    break;
                }
            }
            state->eventFlags |= SC_TOTEM_BOND_EVENT_SET_MAP_MODE;
            break;
        case 3:
            objects = ObjList_GetObjects(&startForEvent3, &countForEvent3);
            for (; startForEvent3 < countForEvent3; startForEvent3++) {
                if (objects[startForEvent3] != obj &&
                    objects[startForEvent3]->anim.romDefNo == SC_TOTEM_POLE_SEQUENCE_ID) {
                    (*(ScTotemPoleInterfaceVTable**)objects[startForEvent3]->anim.dll)
                        ->handleEvent(objects[startForEvent3], 1);
                    break;
                }
            }
            break;
        }
    }
    return 0;
}

int sc_totembond_getExtraSize(void) {
    return sizeof(ScTotemBondState);
}

int sc_totembond_getObjectTypeId(void) {
    return 0;
}

void sc_totembond_free(GameObject* obj) {
    (void)obj;

    Music_Trigger(MUSICTRIG_WLC_Puzzle_f0, 0);
    fearTestMeterSetFadeIn(0);
}

void sc_totembond_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 visibleValue = visible;

    if (visibleValue != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void sc_totembond_hitDetect(void) {
}

static inline void sc_totembond_finishOrbGame(GameObject* obj, ScTotemBondState* state) {
    GameObject* player;

    state->completionTimer = 0.0f;
    player = Obj_GetPlayerObject();
    (*gMapEventInterface)->clearRestartPoint();
    (*gCameraInterface)->setMode(SC_TOTEM_BOND_CAMERA_MODE_DEFAULT, 0, 3, 0, NULL, 0, 0);
    obj->anim.alpha = 0xFF;
    playerTeleport(player, NULL, NULL, 0);
    ObjHits_EnableObject(obj);
    setHudForceShowMask(0);
    mainSetBits(SC_TOTEM_BOND_GAMEBIT_COMPLETE, 1);
    state->eventFlags = 0;
    Music_Trigger(MUSICTRIG_WLC_Puzzle_f0, 0);
}

static inline u8 sc_totembond_gatherAvailableOrbs(u8* availableOrbs, u8 availableCount, u8 orbIndex) {
    for (; orbIndex < SC_TOTEM_BOND_GAMEBIT_COUNT; orbIndex++) {
        if (mainGetBit(gTotemBondOrbGameBits[orbIndex]) == 0) {
            availableOrbs[availableCount++] = orbIndex;
        }
    }
    return availableCount;
}

void sc_totembond_update(GameObject* obj) {
    ScTotemBondState* state;
    GameObject* player;
    u8 availableOrbs[SC_TOTEM_BOND_GAMEBIT_COUNT];
    u8 availableCount;
    u8 nextRing;
    u8 allOrbsCollected;
    f32 zero;

    zero = 0.0f;
    state = obj->extra;
    player = Obj_GetPlayerObject();
    if ((state->eventFlags & SC_TOTEM_BOND_EVENT_START_ORBS) != 0) {
        sc_totembond_beginOrbGame(obj, state);
    }

    if ((state->eventFlags & SC_TOTEM_BOND_EVENT_ORBS_ACTIVE) != 0) {
        if (state->spawnTimer != zero) {
            state->spawnTimer -= timeDelta;
            if (state->spawnTimer < zero) {
                state->spawnTimer = zero;
            }
        } else if (state->completionTimer != zero) {
            state->completionTimer -= timeDelta;
            if (state->completionTimer <= zero) {
                sc_totembond_finishOrbGame(obj, state);
                return;
            }
        } else {
            if (mainGetBit(DLL1B5_COMPLETION_GAMEBIT_SC_TOTEM_BOND) != 0) {
                mainSetBits(DLL1B5_COMPLETION_GAMEBIT_SC_TOTEM_BOND, 0);
                availableCount = sc_totembond_gatherAvailableOrbs(availableOrbs, 0, 0);
                if (availableCount == 0) {
                    allOrbsCollected = 1;
                } else {
                    nextRing = availableOrbs[randomGetRange(0, availableCount - 1)];
                    if (state->ringIndex == nextRing) {
                        mainSetBits(gTotemBondRingGameBits[state->ringIndex], 1);
                    }
                    if (state->ringIndex != nextRing) {
                        state->ringIndex = nextRing;
                        Sfx_PlayFromObject(obj, SFXTRIG_mv_cagerat01);
                    }
                    allOrbsCollected = 0;
                }
                if (allOrbsCollected) {
                    state->completionTimer = SC_TOTEM_BOND_COMPLETION_DELAY;
                    fearTestMeterSetFadeIn(0);
                    (*gScreenTransitionInterface)
                        ->start(SC_TOTEM_BOND_SCREEN_TRANSITION, SC_TOTEM_BOND_SCREEN_TRANSITION_STATE);
                }
            }
            if ((int)((u32)(u16)obj->anim.rotX >> 13) != state->ringIndex) {
                obj->anim.rotX = (s16) - ((SC_TOTEM_BOND_ROTATION_SPEED * timeDelta) - (f32)(s32)obj->anim.rotX);
                if ((int)((u32)(u16)obj->anim.rotX >> 13) == state->ringIndex) {
                    mainSetBits(gTotemBondRingGameBits[state->ringIndex], 1);
                }
            }
        }

        playerTeleport(player, &obj->anim.localPos, &obj->anim.rotation, 0);
        state->cameraX = obj->anim.localPosX;
        state->cameraY = gScTotemBondThirty[0] + obj->anim.localPosY;
        state->cameraZ = obj->anim.localPosZ;
        state->cameraYaw = (s16)(0x8000 - obj->anim.rotX);
        state->cameraPitch = obj->anim.rotY;
        state->cameraRoll = obj->anim.rotZ;
        state->cameraDistance = SC_TOTEM_BOND_CAMERA_DISTANCE;
        (*gCameraInterface)->releaseAction(state, 0x18);
    }

    if ((state->eventFlags & SC_TOTEM_BOND_EVENT_SET_MAP_MODE) != 0) {
        (*gMapEventInterface)->setMapAct(SC_TOTEM_BOND_MAP_SWAPCIRCLE, 6);
        state->eventFlags &= ~SC_TOTEM_BOND_EVENT_SET_MAP_MODE;
    }
}

void sc_totembond_init(GameObject* obj, const ScTotemBondPlacement* placement) {
    ScTotemBondState* state;
    u32 flags;
    s16 hi = (s16)(u16)((s32)obj->anim.rotX / SC_TOTEM_BOND_RING_ANGLE_STEP);

    (void)placement;

    state = obj->extra;
    state->ringIndex = hi;
    obj->animEventCallback = sc_totembond_SeqFn;
    flags = obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    obj->objectFlags = flags;
}

void sc_totembond_release(void) {
}

void sc_totembond_initialise(void) {
}

int sc_totembond_insertOrderedGameBit(u16* gameBitIds, u16 newValue) {
    u16 values[4];
    u8 i, j;
    s32 changed = 0;

    for (i = 0; i < 3; i++) {
        u16 value = mainGetBit(gameBitIds[i]);
        values[i] = value;
    }
    values[3] = newValue;
    for (j = 0; j < 3; j++) {
        for (i = 0; i < 3; i++) {
            if (values[i + 1] != 0) {
                if ((values[i + 1] < values[i]) || (values[i] == 0)) {
                    u16 tmp = values[i];
                    values[i] = values[i + 1];
                    values[i + 1] = tmp;
                    changed = 1;
                }
            }
        }
    }
    for (i = 0; i < 3; i++) {
        mainSetBits(gameBitIds[i], values[i]);
    }
    return changed;
}

u16 gTotemBondRingGameBits[SC_TOTEM_BOND_GAMEBIT_COUNT] = {
    0x064D, 0x064E, 0x064F, 0x0650, 0x0A4C, 0x0A4D, 0x0A4E, 0x0A4F,
};

u16 gTotemBondOrbGameBits[SC_TOTEM_BOND_GAMEBIT_COUNT] = {
    0x0768, 0x0769, 0x076A, 0x076B, 0x0A50, 0x0A51, 0x0A52, 0x0A53,
};

ObjectDescriptor gSC_totembondObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)sc_totembond_initialise,
    (ObjectDescriptorCallback)sc_totembond_release,
    0,
    (ObjectDescriptorCallback)sc_totembond_init,
    (ObjectDescriptorCallback)sc_totembond_update,
    (ObjectDescriptorCallback)sc_totembond_hitDetect,
    (ObjectDescriptorCallback)sc_totembond_render,
    (ObjectDescriptorCallback)sc_totembond_free,
    (ObjectDescriptorCallback)sc_totembond_getObjectTypeId,
    sc_totembond_getExtraSize,
};
