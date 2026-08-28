#include "dlls/object_descriptor.h"
#include "sys/objects.h"
#include "main/dll/player_objects.h"
#include "main/pad.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/track_dolphin_api.h"
#include "dolphin/pad.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/player_api.h"
#include "main/dll/savegame_object_api.h"
#include "main/obj_message.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "main/dll/dll_002F_carryable.h"

#define CARRYABLE_MSG_PLAYER_GRAB 0x100008

#define CARRYABLE_OBJGROUP 0x10

void Carryable_putDownAndSavePos(GameObject* obj) {
    CarryableState* state = obj->extra;
    state->carryState = CARRY_STATE_RESTING;
    state->isHeld = 0;
    if ((state->flags & CARRYABLE_FLAG_SUPPRESS_POS_SAVE) == 0) {
        obj->anim.localPosY += 10.0f;
        saveGame_saveObjectPos(obj);
        obj->anim.localPosY -= 10.0f;
    }
}

void Carryable_stopCarrying(GameObject* obj, CarryableState* state) {
    GameObject* player = Obj_GetPlayerObject();
    GameObject* held;
    state->carryState = CARRY_STATE_RESTING;
    Player_GetHeldObject(player, &held);
    if (held == obj) {
        playerSetHeldObject(player, NULL);
    }
}

void Carryable_setSuppressPositionSave(CarryableState* state, u8 enable) {
    if (enable != 0) {
        state->flags |= CARRYABLE_FLAG_SUPPRESS_POS_SAVE;
    } else {
        state->flags &= ~CARRYABLE_FLAG_SUPPRESS_POS_SAVE;
    }
}

s32 Carryable_getDropDisabled(CarryableState* state) {
    return (state->flags & CARRYABLE_FLAG_DROP_DISABLED) != 0;
}

void Carryable_setDropDisabled(CarryableState* state, u8 enable) {
    if (enable != 0) {
        state->flags |= CARRYABLE_FLAG_DROP_DISABLED;
    } else {
        state->flags &= ~CARRYABLE_FLAG_DROP_DISABLED;
    }
}

void Carryable_setGravityEnabled(CarryableState* state, u8 clear) {
    if (clear != 0) {
        state->flags &= ~CARRYABLE_FLAG_GRAVITY_DISABLED;
    } else {
        state->flags |= CARRYABLE_FLAG_GRAVITY_DISABLED;
    }
}

u8 Carryable_getSurfaceType(CarryableState* state) {
    return state->surfaceType;
}

s32 Carryable_wasJustGrabbed(CarryableState* state) {
    return state->flags & CARRYABLE_FLAG_JUST_GRABBED;
}

s32 Carryable_getCarryState(CarryableState* state) {
    return state->carryState;
}

void Carryable_free(GameObject* obj) {
    objFreeObjectType(obj, CARRYABLE_OBJGROUP);
}

int Carryable_updateRenderState(GameObject* obj, int flag) {
    ObjDef* p50 = (ObjDef*)((int*)obj->anim.modelInstance);
    if (p50->shadowType == OBJ_SHADOW_TYPE_MODEL_GEOMETRIC) {
        if (obj->seqIndex == -1) {
            obj->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        } else {
            obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if (obj->userData2 != 0) {
        if (flag != -1) {
            return 0;
        }
    } else {
        if (flag == 0) {
            return 0;
        }
    }
    return 1;
}

int Carryable_updateHeld(GameObject* obj, CarryableState* state) {
    TrackGroundHit** list;
    GameObject* player;
    CarryableState* held;
    held = obj->extra;
    held->surfaceType = 0;
    held->flags &= ~CARRYABLE_FLAG_JUST_GRABBED;
    player = Obj_GetPlayerObject();
    if (held->carryState == CARRY_STATE_RESTING) {
        struct {
            u8 a, b, c, d, e;
        }* t;
        int newCarryState = 0;
        t = (void*)obj->anim.hitVolumeBounds;
        if ((t[obj->hitVolumeIndex].e & 0xf) == 6 && (buttonGetDisabled(0) & PAD_BUTTON_A) == 0 &&
            (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0 && obj->userData2 == 0) {
            held->unk00 = 0;
            buttonDisable(0, PAD_BUTTON_A);
            newCarryState = 1;
        }
        held->carryState = newCarryState;
        if (held->carryState != CARRY_STATE_RESTING) {
            held->flags |= CARRYABLE_FLAG_JUST_GRABBED;
            held->isHeld = 1;
        }
        if (obj->userData2 == 0) {
            GameObject* hit;
            int cnt, i, j;
            ObjHits_SyncObjectPositionIfDirty(obj);
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            if ((held->flags & CARRYABLE_FLAG_GRAVITY_DISABLED) == 0) {
                obj->anim.velocityY = -(0.1f * timeDelta - obj->anim.velocityY);
                obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
            }
            cnt = trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &list, 0, 1);
            hit = 0;
            i = 0;
            for (j = cnt; j > 0; j--) {
                if ((s8)list[i]->surfaceType != 0xe) {
                    if (obj->anim.localPosY < list[i]->height && obj->anim.localPosY > list[i]->height - 40.0f) {
                        hit = list[i]->object;
                        obj->anim.localPosY = list[i]->height;
                        obj->anim.velocityY = 0.0f;
                        break;
                    }
                }
                i++;
            }
            i = 0;
            for (; cnt > 0; cnt--) {
                f32 d = obj->anim.localPosY - list[i]->height;
                if (d < 0.0f) {
                    d = -d;
                }
                if (d < 5.0f) {
                    s8 t2 = *(s8*)&list[i]->surfaceType;
                    if (t2 > held->surfaceType) {
                        *(s8*)&held->surfaceType = t2;
                    }
                }
                i++;
            }
            if (hit != 0) {
                ObjHitboxTransformState* owner = hit->anim.hitboxTransformState;
                u8 slot = owner->contactObjectCount++;
                owner->contactObjects[(s8)slot] = obj;
            }
        }
    } else {
        ObjHits_MarkObjectPositionDirty(&obj->anim);
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if ((getButtonsJustPressed(0) & PAD_BUTTON_A) != 0) {
            if ((held->flags & CARRYABLE_FLAG_DROP_DISABLED) != 0 || isTrickyNear(player) == 0) {
                Sfx_PlayFromObject(0, SFXTRIG_id_10a);
            } else {
                buttonDisable(0, PAD_BUTTON_A);
                held->isHeld = 0;
            }
        }
        if (obj->userData2 == 1) {
            held->carryState = CARRY_STATE_PUTDOWN;
        }
        if (held->carryState == CARRY_STATE_PUTDOWN && obj->userData2 == 0) {
            CarryableState* h2 = obj->extra;
            h2->carryState = CARRY_STATE_RESTING;
            h2->isHeld = 0;
            if ((h2->flags & CARRYABLE_FLAG_SUPPRESS_POS_SAVE) == 0) {
                obj->anim.localPosY += 10.0f;
                saveGame_saveObjectPos(obj);
                obj->anim.localPosY -= 10.0f;
            }
        }
        if (*(s8*)&held->isHeld != 0) {
            ObjMsg_SendToObject(player, CARRYABLE_MSG_PLAYER_GRAB, obj, (held->unk02 << 16) | (u16)held->unk00);
        }
    }
    return held->carryState;
}

void Carryable_init(GameObject* obj, CarryableState* state, int arg2) {
    objAddObjectType(obj, CARRYABLE_OBJGROUP);
    state->unk02 = 0;
    state->carryState = CARRY_STATE_RESTING;
    state->unk04 = 0;
    state->isHeld = 0;
    (obj)->userData2 = 0;
}

void Carryable_release(void) {
}

void Carryable_initialise(void) {
}
typedef struct CarryableDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback init;
    ObjectDescriptorCallback updateHeld;
    ObjectDescriptorCallback updateRenderState;
    ObjectDescriptorCallback free;
    ObjectDescriptorCallback getCarryState;
    ObjectDescriptorCallback wasJustGrabbed;
    ObjectDescriptorCallback getSurfaceType;
    ObjectDescriptorCallback setGravityEnabled;
    ObjectDescriptorCallback setDropDisabled;
    ObjectDescriptorCallback getDropDisabled;
    ObjectDescriptorCallback setSuppressPositionSave;
    ObjectDescriptorCallback stopCarrying;
    ObjectDescriptorCallback slot0F;
} CarryableDllInterface;

CarryableDllInterface Carryable_funcs = {
    0,
    0,
    0,
    0x000E0000,
    (ObjectDescriptorCallback)Carryable_initialise,
    (ObjectDescriptorCallback)Carryable_release,
    0,
    (ObjectDescriptorCallback)Carryable_init,
    (ObjectDescriptorCallback)Carryable_updateHeld,
    (ObjectDescriptorCallback)Carryable_updateRenderState,
    (ObjectDescriptorCallback)Carryable_free,
    (ObjectDescriptorCallback)Carryable_getCarryState,
    (ObjectDescriptorCallback)Carryable_wasJustGrabbed,
    (ObjectDescriptorCallback)Carryable_getSurfaceType,
    (ObjectDescriptorCallback)Carryable_setGravityEnabled,
    (ObjectDescriptorCallback)Carryable_setDropDisabled,
    (ObjectDescriptorCallback)Carryable_getDropDisabled,
    (ObjectDescriptorCallback)Carryable_setSuppressPositionSave,
    (ObjectDescriptorCallback)Carryable_stopCarrying,
    0,
};
