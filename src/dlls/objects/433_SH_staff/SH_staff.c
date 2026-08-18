/*
 * shstaff (DLL 0x1B1) - the Krazoa Staff pickup object and its ring of
 * sh_staffhaze flames (the shimmering blue "haze" spawned as child objects,
 * model 0x659 -> SH_StaffHaze_update; live-verified in ThornTail Hollow by
 * hiding a slot child and watching the flame vanish).
 *
 * sh_staff_render positions the staff (carried, attached to the player's
 * hand matrix in the carry phases) and animates up to ten staff-haze child
 * flames spread along the staff's two path points; before pickup a single
 * flame climbs the staff from base to tip on a loop (hazeClimbT) as an
 * attract effect. sh_staff_sequenceCallback spawns the flames on demand and
 * consumes the carry/HUD animation events; sh_staff_update runs the pickup
 * proximity/map-load state machine (phase 0 idle -> 1 armed -> 2 pickup ->
 * 3/4/5 carry -> 6 done). sh_staff_deactivate hides the staff, releases the
 * flames, and ends the player's carry.
 */
#include "dlls/objects/433_SH_staff.h"
#include "dolphin/mtx.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/player_objects.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/obj_path.h"
#include "main/objhits.h"
#include "main/object_render.h"
#include "main/objprint_render_api.h"
#include "main/obj_trigger.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/player_staff_api.h"
#include "main/dll/tricky_api.h"
#include "main/map_load.h"

/* ShStaffState.phase pickup / carry state machine (see file header) */
#define SHSTAFF_PHASE_IDLE           0     /* wait for the staff object / acquired game bit */
#define SHSTAFF_PHASE_ARMED          1     /* proximity map load; wait for the pickup trigger */
#define SHSTAFF_PHASE_PICKUP         2     /* acquired; fade in and unload the pickup map */
#define SHSTAFF_PHASE_CARRY_ATTACH   3     /* build the carry matrix from the world transform */
#define SHSTAFF_PHASE_CARRY_LOCAL    4     /* build the carry matrix from the hand's local matrix */
#define SHSTAFF_PHASE_CARRY_RENDER   5     /* settled carry: render attached to the hand */
#define SHSTAFF_PHASE_DONE           6     /* deactivated */
#define SHSTAFF_CHILD_OBJ_HAZE_FLAME 0x659 /* staff-haze child flame (SH_StaffHaze_update), spawned by the callback */
#define SHSTAFF_TARGET_OBJGROUP      0xf   /* player-target group; the nearest object gets the pickup sequence */

#define SHSTAFF_HAZE_FLAG_SPAWN_EVEN    0x01
#define SHSTAFF_HAZE_FLAG_EVEN_COMPLETE 0x02
#define SHSTAFF_HAZE_FLAG_SPAWN_ODD     0x04
#define SHSTAFF_HAZE_FLAG_ODD_COMPLETE  0x08
#define SHSTAFF_HAZE_FLAG_FADE_OUT      0x10
#define SHSTAFF_HAZE_FLAG_CONVERGE      0x20

#define SHSTAFF_EVENT_ATTACH_WORLD       2
#define SHSTAFF_EVENT_SHOW_HELP_TEXT     3
#define SHSTAFF_EVENT_HIDE_HELP_TEXT     4
#define SHSTAFF_EVENT_DEACTIVATE         5
#define SHSTAFF_EVENT_ATTACH_LOCAL       6
#define SHSTAFF_EVENT_SHOW_STAFF_HUD     7
#define SHSTAFF_EVENT_SPAWN_EVEN_HAZE    8
#define SHSTAFF_EVENT_SPAWN_ODD_HAZE     9
#define SHSTAFF_EVENT_FADE_HAZE_OUT      0xA
#define SHSTAFF_EVENT_CONVERGE_HAZE      0xB
#define SHSTAFF_EVENT_FINISH_HAZE_EFFECT 0xC

#define SHSTAFF_HAZE_SETUP_SIZE       0x20
#define SHSTAFF_PICKUP_MAP_ID         8
#define SHSTAFF_PICKUP_MAP_CELL       0x13
#define SHSTAFF_PICKUP_MAP_LOAD_FLAGS 0x20000000

ObjectDescriptor gSH_staffObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    0,
    (ObjectDescriptorCallback)sh_staff_update,
    0,
    (ObjectDescriptorCallback)sh_staff_render,
    (ObjectDescriptorCallback)sh_staff_free,
    0,
    sh_staff_getExtraSize,
};

int sh_staff_getExtraSize(void) {
    return sizeof(ShStaffState);
}

void sh_staff_free(GameObject* obj, int freeArg) {
    ShStaffState* state = obj->extra;
    GameObject* child;
    int i;

    if (freeArg != 0) {
        return;
    }

    i = 0;
    for (; i < SHSTAFF_HAZE_CHILD_COUNT; i++) {
        child = (GameObject*)state->hazeChildren[i];
        if (child != NULL) {
            child->anim.flags = (s16)(child->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
    }
}

#define SHSTAFF_FADE_OUT_TIMER_INIT 1500.0f
#define SHSTAFF_FIZZ_SFX_TIMER_INIT 0.9f
#define SHSTAFF_MAP_LOAD_DIST_SQ    250000.0f
#define SHSTAFF_MAP_UNLOAD_DIST_SQ  490000.0f


void sh_staff_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    ShStaffState* state;
    int player;
    int i;
    int j;
    GameObject* hazeChild;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 foldScale;
    f32 scatterScale;
    f32 t;
    f32 scale;
    f32 bx;
    f32 cur2;
    f32 mtxB[12];
    f32 mtxA[12];
    f32 z0;
    f32 y0;
    f32 x0;
    f32 z1;
    f32 y1;
    f32 x1;

    state = obj->extra;
    player = (int)Obj_GetPlayerObject();
    if (visible != 0) {
        if (state->phase == SHSTAFF_PHASE_CARRY_ATTACH) {
            Obj_BuildWorldTransformMatrix(obj, mtxB, 0);
            PSMTXInverse((MtxPtr)ObjPath_GetPointModelMtx((GameObject*)player, 0), (MtxPtr)mtxA);
            PSMTXConcat((MtxPtr)mtxA, (MtxPtr)mtxB, (MtxPtr)state->carryMatrix);
            state->phase = SHSTAFF_PHASE_CARRY_RENDER;
        }
        if (state->phase == SHSTAFF_PHASE_CARRY_LOCAL) {
            ObjPath_GetPointLocalMtx((GameObject*)player, 0, state->carryMatrix);
            state->phase = SHSTAFF_PHASE_CARRY_RENDER;
        }
        if (state->phase == SHSTAFF_PHASE_CARRY_RENDER) {
            PSMTXConcat((MtxPtr)ObjPath_GetPointModelMtx((GameObject*)player, 0), (MtxPtr)state->carryMatrix, (MtxPtr)mtxB);
            objSetCurrentMatrix((MtxPtr)mtxB);
            objRenderModel(obj);
        } else {
            objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        }
        ObjPath_GetPointWorldPosition(obj, 0, &x0, &y0, &z0, 0);
        ObjPath_GetPointWorldPosition(obj, 1, &x1, &y1, &z1, 0);
        dx = x1 - x0;
        dy = y1 - y0;
        dz = z1 - z0;
        if (((state->hazeFlags & SHSTAFF_HAZE_FLAG_SPAWN_EVEN) != 0) &&
            ((state->hazeFlags & SHSTAFF_HAZE_FLAG_EVEN_COMPLETE) == 0)) {
            for (i = 2; i < SHSTAFF_HAZE_CHILD_COUNT; i += 2) {
                if ((u32)state->hazeChildren[i] == 0) {
                    state->hazeSpawnPending[i] = 1;
                    break;
                }
            }
            if (i >= SHSTAFF_HAZE_CHILD_COUNT) {
                state->hazeFlags |= SHSTAFF_HAZE_FLAG_EVEN_COMPLETE;
            }
        }
        if (((state->hazeFlags & SHSTAFF_HAZE_FLAG_SPAWN_ODD) != 0) &&
            ((state->hazeFlags & SHSTAFF_HAZE_FLAG_ODD_COMPLETE) == 0)) {
            for (i = 1; i < SHSTAFF_HAZE_CHILD_COUNT; i += 2) {
                if ((u32)state->hazeChildren[i] == 0) {
                    state->hazeSpawnPending[i] = 1;
                    break;
                }
            }
            if (i >= SHSTAFF_HAZE_CHILD_COUNT) {
                state->hazeFlags |= SHSTAFF_HAZE_FLAG_ODD_COMPLETE;
            }
        }
        if (state->hazeFlags != 0) {
            if ((state->hazeFlags & SHSTAFF_HAZE_FLAG_CONVERGE) != 0) {
                i = 5;
                for (; i < 5; i++) {
                    if ((u32)state->hazeChildren[i] != 0) {
                        ((GameObject*)state->hazeChildren[i])->anim.flags |= OBJANIM_FLAG_HIDDEN;
                        state->hazeChildren[i] = 0;
                    }
                }
                if ((state->hazeFlags & SHSTAFF_HAZE_FLAG_FADE_OUT) != 0) {
                    state->hazeFadeTimer = state->hazeFadeTimer - timeDelta;
                    if (state->hazeFadeTimer <= 0.0f) {
                        foldScale = 0.01f;
                    } else {
                        state->hazeFadeTimer = state->hazeFadeTimer - timeDelta;
                        foldScale = (1.0f / 3000.0f) * state->hazeFadeTimer;
                    }
                } else {
                    state->hazeFadeTimer = state->hazeFadeTimer + timeDelta;
                    if (state->hazeFadeTimer >= 60.0f) {
                        state->hazeFadeTimer = 60.0f;
                    }
                    foldScale = (1.0f / 120.0f) * state->hazeFadeTimer;
                }
                j = 0;
                for (; j < 5; j++) {
                    if (((u32)state->hazeChildren[j] != 0) && ((u32)state->hazeChildren[4] != 0)) {
                        t = 0.2f + j / 5.0f;
                        bx = ((GameObject*)state->hazeChildren[4])->anim.localPosX;
                        ((GameObject*)state->hazeChildren[j])->anim.localPosX = t * (x0 - bx) + bx;
                        ((GameObject*)state->hazeChildren[j])->anim.localPosY =
                            t * (y0 - ((GameObject*)state->hazeChildren[4])->anim.localPosY) +
                            ((GameObject*)state->hazeChildren[4])->anim.localPosY;
                        ((GameObject*)state->hazeChildren[j])->anim.localPosZ =
                            t * (z0 - ((GameObject*)state->hazeChildren[4])->anim.localPosZ) +
                            ((GameObject*)state->hazeChildren[4])->anim.localPosZ;
                        ((GameObject*)state->hazeChildren[j])->anim.rootMotionScale = foldScale;
                    }
                }
                j = 9;
                for (; j > 4; j--) {
                    if (((u32)state->hazeChildren[j] != 0) && ((u32)state->hazeChildren[5] != 0)) {
                        t = 0.2f + (f32)(9 - j) / 5.0f;
                        bx = ((GameObject*)state->hazeChildren[5])->anim.localPosX;
                        ((GameObject*)state->hazeChildren[j])->anim.localPosX = t * (x1 - bx) + bx;
                        ((GameObject*)state->hazeChildren[j])->anim.localPosY =
                            t * (y1 - ((GameObject*)state->hazeChildren[5])->anim.localPosY) +
                            ((GameObject*)state->hazeChildren[5])->anim.localPosY;
                        ((GameObject*)state->hazeChildren[j])->anim.localPosZ =
                            t * (z1 - ((GameObject*)state->hazeChildren[5])->anim.localPosZ) +
                            ((GameObject*)state->hazeChildren[5])->anim.localPosZ;
                        ((GameObject*)state->hazeChildren[j])->anim.rootMotionScale = foldScale;
                    }
                }
            } else {
                scatterScale = 0.01f;
                if ((state->hazeFlags & SHSTAFF_HAZE_FLAG_FADE_OUT) != 0) {
                    state->hazeFadeTimer = state->hazeFadeTimer - timeDelta;
                    if (state->hazeFadeTimer <= 0.0f) {
                        state->hazeFlags &= ~SHSTAFF_HAZE_FLAG_FADE_OUT;
                    } else {
                        scatterScale = (1.0f / 120.0f) * state->hazeFadeTimer;
                    }
                }
                for (j = 0; j < SHSTAFF_HAZE_CHILD_COUNT; j++) {
                    if ((u32)state->hazeChildren[j] != 0) {
                        t = (1.0f / 9.0f) * j;
                        t = t + (f32)randomGetRange(-0x32, 0x32) / 1000.0f;
                        ((GameObject*)state->hazeChildren[j])->anim.localPosX = dx * t + x0;
                        ((GameObject*)state->hazeChildren[j])->anim.localPosY = dy * t + y0;
                        ((GameObject*)state->hazeChildren[j])->anim.localPosZ = dz * t + z0;
                        ((GameObject*)state->hazeChildren[j])->anim.rootMotionScale = scatterScale;
                    }
                }
            }
        } else {
            scale = 0.5f;
            cur2 = state->hazeFadeTimer;
            bx = 0.0f;
            if (cur2 != bx) {
                state->hazeFadeTimer = cur2 - timeDelta;
                if (state->hazeFadeTimer <= bx) {
                    hazeChild = (GameObject*)state->hazeChildren[0];
                    if ((u32)hazeChild != 0) {
                        hazeChild->anim.flags |= OBJANIM_FLAG_HIDDEN;
                        state->hazeChildren[0] = 0;
                        state->hazeFadeTimer = bx;
                    }
                } else {
                    scale = (1.0f / 120.0f) * state->hazeFadeTimer;
                }
            }
            if ((u32)state->hazeChildren[0] != 0) {
                ((GameObject*)state->hazeChildren[0])->anim.localPosX = dx * state->hazeClimbT + x0;
                ((GameObject*)state->hazeChildren[0])->anim.localPosY = dy * state->hazeClimbT + y0;
                ((GameObject*)state->hazeChildren[0])->anim.localPosZ = dz * state->hazeClimbT + z0;
                ((GameObject*)state->hazeChildren[0])->anim.rootMotionScale = scale;
            }
        }
    }
}

int sh_staff_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    ShStaffState* state = obj->extra;
    int i;

    for (i = 0; i < SHSTAFF_HAZE_CHILD_COUNT; i++) {
        if (state->hazeSpawnPending[i] != 0) {
            int loadResult;
            if (Obj_IsLoadingLocked() == 0) {
                loadResult = 0;
            } else {
                ObjPlacement* newSetup = Obj_AllocObjectSetup(SHSTAFF_HAZE_SETUP_SIZE, SHSTAFF_CHILD_OBJ_HAZE_FLAME);
                newSetup->color[0] = 2;
                newSetup->color[3] = 0xff;
                loadResult = (int)loadObjectAtObject(obj, newSetup);
            }
            state->hazeChildren[i] = loadResult;
            state->hazeSpawnPending[i] = 0;
        }
    }

    for (i = 0; i < animUpdate->eventCount; i++) {
        u8 eventId = animUpdate->eventIds[i];
        switch (eventId) {
        case SHSTAFF_EVENT_ATTACH_WORLD:
            state->phase = SHSTAFF_PHASE_CARRY_ATTACH;
            break;
        case SHSTAFF_EVENT_SHOW_HELP_TEXT:
            state->helpTextVisible = 1;
            break;
        case SHSTAFF_EVENT_HIDE_HELP_TEXT:
            state->helpTextVisible = 0;
            break;
        case SHSTAFF_EVENT_DEACTIVATE:
            sh_staff_deactivate(obj, state, 1);
            break;
        case SHSTAFF_EVENT_ATTACH_LOCAL:
            state->phase = SHSTAFF_PHASE_CARRY_LOCAL;
            break;
        case SHSTAFF_EVENT_SHOW_STAFF_HUD:
            setHudForceShowMask(1);
            break;
        case SHSTAFF_EVENT_SPAWN_EVEN_HAZE:
            state->hazeFlags |= SHSTAFF_HAZE_FLAG_SPAWN_EVEN;
            break;
        case SHSTAFF_EVENT_SPAWN_ODD_HAZE:
            state->hazeFlags |= SHSTAFF_HAZE_FLAG_SPAWN_ODD;
            break;
        case SHSTAFF_EVENT_FADE_HAZE_OUT:
            state->hazeFlags |= SHSTAFF_HAZE_FLAG_FADE_OUT;
            state->hazeFadeTimer = 60.0f;
            break;
        case SHSTAFF_EVENT_CONVERGE_HAZE:
            state->hazeFlags |= SHSTAFF_HAZE_FLAG_CONVERGE;
            state->hazeFadeTimer = 0.0f;
            break;
        case SHSTAFF_EVENT_FINISH_HAZE_EFFECT:
            state->hazeFlags |= SHSTAFF_HAZE_FLAG_FADE_OUT;
            state->hazeFlags |= SHSTAFF_HAZE_FLAG_EVEN_COMPLETE | SHSTAFF_HAZE_FLAG_ODD_COMPLETE;
            state->hazeFadeTimer = SHSTAFF_FADE_OUT_TIMER_INIT;
            break;
        case 0:
        case 1:
            break;
        }
    }

    if (state->helpTextVisible != 0) {
        ((void (*)(s16, int, int))((int*)*gGameUIInterface)[0x34 / 4])(obj->anim.modelInstance->helpTextIds[1], 0xa0,
                                                                       0x8c);
    }
    state->hazeClimbT += 0.01f * timeDelta;
    if (state->hazeClimbT > 1.0f) {
        state->hazeClimbT = 0.0f;
    }
    return 0;
}

void sh_staff_deactivate(GameObject* obj, ShStaffState* state, int clearChildren) {
    int player;
    GameObject* child;
    int i;

    player = (int)Obj_GetPlayerObject();
    ObjHits_DisableObject(obj);
    obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
    obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;

    if (clearChildren != 0) {
        staffToggle((GameObject*)player, 1);
        playerPutAwayStaff((GameObject*)player, 1);
        for (i = 0; i < SHSTAFF_HAZE_CHILD_COUNT; i++) {
            child = (GameObject*)state->hazeChildren[i];
            if (child != NULL) {
                child->anim.flags = (s16)(child->anim.flags | OBJANIM_FLAG_HIDDEN);
                state->hazeChildren[i] = 0;
            }
        }
    }

    state->phase = SHSTAFF_PHASE_DONE;
}

void sh_staff_update(GameObject* obj) {
    ShStaffState* state = obj->extra;
    ShStaffPlacement* placement = (ShStaffPlacement*)obj->anim.placementData;
    GameObject* player = Obj_GetPlayerObject();
    f32 distanceSq = getXZDistanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX);
    u8 currentPhase = state->phase;

    if (currentPhase == SHSTAFF_PHASE_IDLE) {
        if (player != NULL && Player_GetStaffObject(player) != NULL) {
            if (mainGetBit(GAMEBIT_STAFF_ACQUIRED) != 0) {
                sh_staff_deactivate(obj, obj->extra, 0);
            } else {
                int loadResult;
                staffToggle(player, 0);
                ObjAnim_SetMoveProgress((ObjAnimComponent*)obj, 1.0f);
                obj->anim.rotY = (s16)(placement->rotYByte << 8);
                obj->anim.rotZ = (s16)(placement->rotZByte << 8);
                obj->animEventCallback = sh_staff_sequenceCallback;
                state->phase = SHSTAFF_PHASE_ARMED;
                if (Obj_IsLoadingLocked() == 0) {
                    loadResult = 0;
                } else {
                    ObjPlacement* newSetup =
                        Obj_AllocObjectSetup(SHSTAFF_HAZE_SETUP_SIZE, SHSTAFF_CHILD_OBJ_HAZE_FLAME);
                    newSetup->color[0] = 2;
                    newSetup->color[3] = 0xff;
                    loadResult = (int)loadObjectAtObject(obj, newSetup);
                }
                state->hazeChildren[0] = loadResult;
                state->fizzSfxTimer = SHSTAFF_FIZZ_SFX_TIMER_INIT;
            }
        }
    } else if (currentPhase == SHSTAFF_PHASE_ARMED) {
        if (ObjTrigger_IsSet(obj) != 0) {
            GameObject* target = objGetNearestTypeTo(SHSTAFF_TARGET_OBJGROUP, obj, 0);
            (*gObjectTriggerInterface)->runSequence(0, (void*)target, -1);
            state->phase = SHSTAFF_PHASE_PICKUP;
            state->hazeFadeTimer = 60.0f;
            mainSetBits(GAMEBIT_STAFF_ACQUIRED, 1);
        } else if (distanceSq > SHSTAFF_MAP_UNLOAD_DIST_SQ) {
            if (state->pickupMapLoaded != 0) {
                state->pickupMapLoaded = 0;
                mapUnload(SHSTAFF_PICKUP_MAP_CELL, SHSTAFF_PICKUP_MAP_LOAD_FLAGS);
            }
        } else if (distanceSq < SHSTAFF_MAP_LOAD_DIST_SQ) {
            if (state->pickupMapLoaded == 0) {
                state->pickupMapLoaded = 1;
                loadMapAndParent(SHSTAFF_PICKUP_MAP_ID);
            }
        }
    } else if (state->pickupMapLoaded != 0) {
        state->pickupMapLoaded = 0;
        mapUnload(SHSTAFF_PICKUP_MAP_CELL, SHSTAFF_PICKUP_MAP_LOAD_FLAGS);
        mainSetBits(GAMEBIT_STAFF_PICKUP_MAP_UNLOADED, 1);
    }
    setHudForceShowMask(0);
    state->hazeClimbT = 0.01f * timeDelta + state->hazeClimbT;
    if (state->hazeClimbT > 1.0f) {
        state->hazeClimbT = 0.0f;
    }
    state->fizzSfxTimer = 0.01f * timeDelta + state->fizzSfxTimer;
    if (state->fizzSfxTimer > 1.0f) {
        state->fizzSfxTimer = 0.0f;
        if (state->phase == SHSTAFF_PHASE_ARMED) {
            Sfx_PlayFromObject(obj, SFXTRIG_pk_staff_fizz);
        }
    }
}
