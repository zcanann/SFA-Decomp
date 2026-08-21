/*
 * Ocean Force Point Temple level controller (DLL 0x229; "DFP_LevelControl").
 * The DFP prefix is inherited from Dinosaur Planet's Desert Force Point Temple.
 * Drives the electric-floor puzzle state: a zap-effect countdown timer, RNG
 * seeding of the safe-floor-tile table when its map-act initialization flag is
 * raised, plus gamebit-driven progression, object-group loading, and music.
 */
#include "main/audio/music_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/dfp_types.h"
#include "main/dll/player_api.h"
#include "main/lightmap_api.h"
#include "main/map_load.h"
#include "main/obj_message.h"
#include "main/objtype.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "dlls/objects/430_SH_LevelCon.h"
#include "main/mapEventTypes.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/DF/dll_0229_dfplevelcontrol.h"

s16 gDFPLevelControlMapAct1Timer = 0x82;
u8 gDFPLevelControlInitialiseAct1 = 1;
u8 gDFPLevelControlInitialiseAct2 = 1;
s16 gDFPLevelControlSafeFloorTiles[10] = {1, 2, 3, 0, 0, 0, 0, 0, 0, 0};

#define DFP_LEVEL_CONTROL_OBJECT_TYPE     0x9
#define DFP_LEVEL_CONTROL_MSG_ZAP_PLAYER  0x60005
/* repels the player away from this object and applies status damage (arg = status type) */
#define DFPLEVELCONTROL_MSG_PLAYER_HIT 0x60005
#define DFPLEVELCONTROL_OBJGROUP       0x9

#define DFP_LEVEL_CONTROL_SFX_TRIGGER_D5D 0xd5d
#define DFP_LEVEL_CONTROL_SFX_TRIGGER_D59 0xd59
#define DFP_LEVEL_CONTROL_SFX_TRIGGER_D5A 0xd5a

void DFP_LevelControl_updateAct2(GameObject* obj) {
    s16 i;
    DfpLevelControlState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();

    if (gDFPLevelControlInitialiseAct2 != 0) {
        mainSetBits(GAMEBIT_STAFF_ABILITY_FIRE_BLASTER, 1);
        mainSetBits(GAMEBIT_ITEM_DeletedSpell1D7, 1);

        for (i = 0; i < 9; i++) {
            gDFPLevelControlSafeFloorTiles[i] = randomGetRange(1, 4);
        }

        mainSetBits(GAMEBIT_OFP_PuzzlePadShowSolution, 0);
        state->zappedTimer = 0;
        gDFPLevelControlInitialiseAct2 = 0;
    }

    if (mainGetBit(0x5e3) == 0 && mainGetBit(0x5e0) != 0 && mainGetBit(0x5e1) != 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_wp_espk2_c);
        mainSetBits(0x5e3, 1);
    }

    if (mainGetBit(0x792) == 0 && mainGetBit(0xb8c) != 0 && mainGetBit(0xb8c) != 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_wp_espk2_c);
        mainSetBits(0x792, 1);
    }

    if (mainGetBit(GAMEBIT_OFP_ElectricFloorPuzzleAct2Complete) == 0) {
        if (mainGetBit(GAMEBIT_OFP_PuzzlePadPressed) != 0 && state->previousPuzzlePadState == 0) {
            Sfx_PlayFromObject(0, SFXTRIG_dn_boar1_c_1c4);
            for (i = 0; i < 9; i++) {
                gDFPLevelControlSafeFloorTiles[i] = randomGetRange(1, 4);
            }
            mainSetBits(GAMEBIT_OFP_PuzzlePadShowSolution, 1);
            state->previousPuzzlePadState = 1;
        } else {
            if (mainGetBit(GAMEBIT_OFP_PuzzlePadPressed) == 0 && state->previousPuzzlePadState == 1) {
                state->previousPuzzlePadState = 0;
                mainSetBits(GAMEBIT_OFP_PuzzlePadShowSolution, 0);
            }
        }

        if (mainGetBit(GAMEBIT_OFP_ZappedByFloorTiles) != 0) {
            state->zappedTimer = 300;
            ObjMsg_SendToObject(player, DFP_LEVEL_CONTROL_MSG_ZAP_PLAYER, obj, 0);
        }
    }

    if (mainGetBit(GAMEBIT_OFP_LoadBlockSlidePuzzle2) != 0) {
        if ((*gMapEventInterface)->getObjGroupStatus(obj->anim.mapEventSlot, 6) == 0) {
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, 6, 1);
        }
    }
}

void DFP_LevelControl_updateAct1(GameObject* obj) {
    s16 i;
    DfpLevelControlState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();

    if (gDFPLevelControlInitialiseAct1 != 0) {
        gDFPLevelControlSafeFloorTiles[6] = 0;
        gDFPLevelControlSafeFloorTiles[7] = 0;
        gDFPLevelControlSafeFloorTiles[8] = 0;
        for (i = 0; i < 6; i++) {
            gDFPLevelControlSafeFloorTiles[i] = randomGetRange(1, 4);
        }
        mainSetBits(GAMEBIT_OFP_PuzzlePadShowSolution, 0);
        state->zappedTimer = 0;
        gDFPLevelControlInitialiseAct1 = 0;
    }

    if (mainGetBit(0x5e3) == 0) {
        if (mainGetBit(0x5e0) != 0 && mainGetBit(0x5e1) != 0) {
            mainSetBits(0x5e3, 1);
        }
    }

    if (mainGetBit(GAMEBIT_OFP_ElectricFloorPuzzleAct1Complete) == 0) {
        if (mainGetBit(GAMEBIT_OFP_PuzzlePadPressed) != 0 && state->previousPuzzlePadState == 0) {
            Sfx_PlayFromObject(0, SFXTRIG_statue_wave);
            for (i = 0; i < 6; i++) {
                gDFPLevelControlSafeFloorTiles[i] = randomGetRange(1, 4);
            }
            mainSetBits(GAMEBIT_OFP_PuzzlePadShowSolution, 1);
            state->previousPuzzlePadState = 1;
        } else if (mainGetBit(GAMEBIT_OFP_PuzzlePadPressed) == 0 && state->previousPuzzlePadState == 1) {
            state->previousPuzzlePadState = 0;
            mainSetBits(GAMEBIT_OFP_PuzzlePadShowSolution, 0);
        }

        if (mainGetBit(GAMEBIT_OFP_ZappedByFloorTiles) != 0) {
            state->zappedTimer = 300;
            ObjMsg_SendToObject(player, DFP_LEVEL_CONTROL_MSG_ZAP_PLAYER, obj, 1);
        }
    }
}

int DFP_LevelControl_animCallback(GameObject* obj) {
    DfpLevelControlState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();
    s16 timer = state->zappedTimer;

    if (timer > 0) {
        state->zappedTimer -= (s16)timeDelta;
        playerSetPendingBoneEffect(player, 0x51e);
    }

    return 0;
}

void DFP_LevelControl_copySafeFloorTiles(GameObject* unused, u8* out) {
    int i;
    for (i = 0; (s16)i < 9; i += 3) {
        out[(s16)i] = gDFPLevelControlSafeFloorTiles[i];
        out[(s16)(i + 1)] = gDFPLevelControlSafeFloorTiles[i + 1];
        out[(s16)(i + 2)] = gDFPLevelControlSafeFloorTiles[i + 2];
    }
}

int DFP_LevelControl_getExtraSize(void) {
    return sizeof(DfpLevelControlState);
}
int DFP_LevelControl_getObjectTypeId(void) {
    return 0x0;
}

void DFP_LevelControl_free(GameObject* obj) {
    objFreeObjectType(obj, DFP_LEVEL_CONTROL_OBJECT_TYPE);
}

void DFP_LevelControl_render(void) {
}

void DFP_LevelControl_hitDetect(void) {
}

void DFP_LevelControl_update(GameObject* obj) {
    DfpLevelControlState* state = obj->extra;
    GameObject* player;
    u8 sfxTriggerD5d;
    u8 sfxTriggerD59;
    u8 sfxTriggerD5a;
    int mode;

    player = Obj_GetPlayerObject();
    sfxTriggerD5d = mainGetBit(DFP_LEVEL_CONTROL_SFX_TRIGGER_D5D);
    sfxTriggerD59 = mainGetBit(DFP_LEVEL_CONTROL_SFX_TRIGGER_D59);
    sfxTriggerD5a = mainGetBit(DFP_LEVEL_CONTROL_SFX_TRIGGER_D5A);

    if ((sfxTriggerD5d != 0 && state->previousSfxState.triggerD5d == 0) ||
        (sfxTriggerD59 != 0 && state->previousSfxState.triggerD59 == 0) ||
        (sfxTriggerD5a != 0 && state->previousSfxState.triggerD5a == 0)) {
        Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
    }

    state->previousSfxState.triggerD5d = sfxTriggerD5d;
    state->previousSfxState.triggerD59 = sfxTriggerD59;
    state->previousSfxState.triggerD5a = sfxTriggerD5a;

    if (mainGetBit(0x5e8) == 0 && mainGetBit(0x5ee) != 0 && mainGetBit(0x5ef) != 0) {
        mainSetBits(0x5e8, 1);
    }
    coordsToMapCell(player->anim.localPosX, player->anim.localPosZ);

    mode = (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
    switch (mode) {
    case 1:
        if (gDFPLevelControlMapAct1Timer != 0) {
            gDFPLevelControlMapAct1Timer -= (s16)timeDelta;
            if (gDFPLevelControlMapAct1Timer <= 0) {
                gDFPLevelControlMapAct1Timer = 0;
            }
        }

        DFP_LevelControl_updateAct1(obj);
        break;
    case 2:
        DFP_LevelControl_updateAct2(obj);
        break;
    case 3:
        break;
    }

    GameBitLatch_Update((GameBitLatchState*)&state->musicLatchMask, 2, -1, -1, GAMEBIT_OFP_MusicLatch,
                        MUSICTRIG_mmpassalien);
    GameBitLatch_UpdateInverted((GameBitLatchState*)&state->musicLatchMask, 4, -1, -1, GAMEBIT_OFP_MusicLatch,
                                MUSICTRIG_blizzard);
    GameBitLatch_UpdateInverted((GameBitLatchState*)&state->musicLatchMask, 1, -1, -1, GAMEBIT_OFP_MusicLatch,
                                MUSICTRIG_trex_hit);
    mainSetBits(GAMEBIT_VFP_MusicLatch, 0);
}

void DFP_LevelControl_init(GameObject* obj, DfpLevelControlPlacement* placement) {
    int mode;
    DfpLevelControlState* state = obj->extra;
    objAddObjectType(obj, DFP_LEVEL_CONTROL_OBJECT_TYPE);

    state->previousSfxState.triggerD5d = mainGetBit(DFP_LEVEL_CONTROL_SFX_TRIGGER_D5D);
    state->previousSfxState.triggerD59 = mainGetBit(DFP_LEVEL_CONTROL_SFX_TRIGGER_D59);
    state->previousSfxState.triggerD5a = mainGetBit(DFP_LEVEL_CONTROL_SFX_TRIGGER_D5A);

    obj->animEventCallback = DFP_LevelControl_animCallback;
    state->mode = 1;

    mode = placement->mode;
    if (mode != 0 && mode <= 2) {
        state->mode = mode;
    }

    (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
    unlockLevel(0, 0, 1);
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;

    if (obj->anim.mapEventSlot == 0x15) {
        mainSetBits(GAMEBIT_OFP_MusicLatch, 0);
    }

    if (mainGetBit(GAMEBIT_OFP_MusicLatch) != 0) {
        Music_Trigger(MUSICTRIG_blizzard, 0);
        Music_Trigger(MUSICTRIG_trex_hit, 0);
    }
}

void DFP_LevelControl_release(void) {
}

void DFP_LevelControl_initialise(void) {
    gDFPLevelControlSafeFloorTiles[0] = 1;
    gDFPLevelControlSafeFloorTiles[1] = 2;
    gDFPLevelControlSafeFloorTiles[2] = 3;
    gDFPLevelControlSafeFloorTiles[3] = 0;
    gDFPLevelControlSafeFloorTiles[4] = 0;
    gDFPLevelControlSafeFloorTiles[5] = 0;
    gDFPLevelControlSafeFloorTiles[6] = 0;
    gDFPLevelControlSafeFloorTiles[7] = 0;
    gDFPLevelControlSafeFloorTiles[8] = 0;
}

ObjectDescriptor11ExtraSize gDFP_LevelControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
    (ObjectDescriptorCallback)DFP_LevelControl_initialise,
    (ObjectDescriptorCallback)DFP_LevelControl_release,
    0,
    (ObjectDescriptorCallback)DFP_LevelControl_init,
    (ObjectDescriptorCallback)DFP_LevelControl_update,
    (ObjectDescriptorCallback)DFP_LevelControl_hitDetect,
    (ObjectDescriptorCallback)DFP_LevelControl_render,
    (ObjectDescriptorCallback)DFP_LevelControl_free,
    (ObjectDescriptorCallback)DFP_LevelControl_getObjectTypeId,
    DFP_LevelControl_getExtraSize,
    (ObjectDescriptorCallback)DFP_LevelControl_copySafeFloorTiles,
};
