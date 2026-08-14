/*
 * Placement-driven sound emitter supporting game-bit triggers, persistent
 * loops, random delays, point/object playback, and ROM-curve positioning.
 */
#include "dlls/objects/307_sfxPlayer.h"

#include "main/camera_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/frame_timing.h"
#include "sys/objects.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/gamebits_api.h"
#include "main/objseq_api.h"
#include "main/vecmath.h"

#define SFXPLAYER_GAME_BIT_NONE -1

#define SFXPLAYER_ROM_CURVE_SEARCH_MODE 7
#define SFXPLAYER_SECONDS_TO_FRAMES     60.0f

int SfxPlayer_getExtraSize(void) {
    return sizeof(SfxPlayerState);
}

void SfxPlayer_free(GameObject* obj) {
    SfxPlayerPlacement* placement = (SfxPlayerPlacement*)obj->anim.placementData;
    SfxPlayerState* state = obj->extra;
    u8 flags = state->flags;

    if ((flags & SFXPLAYER_STATE_FLAG_ACTIVE) == 0) {
        return;
    }
    state->flags = (u8)(flags & ~SFXPLAYER_STATE_FLAG_ACTIVE);
    if (placement->mode == SFXPLAYER_MODE_LOOPED) {
        u16 primarySfxId = placement->primarySfxId;
        if (primarySfxId != 0) {
            Sfx_RemoveLoopedObjectSound(obj, primarySfxId);
        }
        {
            u16 secondarySfxId = placement->secondarySfxId;
            if (secondarySfxId != 0) {
                Sfx_RemoveLoopedObjectSound(obj, secondarySfxId);
            }
        }
    } else {
        u16 primarySfxId = placement->primarySfxId;
        if (primarySfxId != 0) {
            Sfx_StopFromObject(obj, primarySfxId);
        }
        {
            u16 secondarySfxId = placement->secondarySfxId;
            if (secondarySfxId != 0) {
                Sfx_StopFromObject(obj, secondarySfxId);
            }
        }
    }
}

static inline void SfxPlayer_startSound(GameObject* obj, SfxPlayerPlacement* placement, SfxPlayerState* state,
                                        u16 soundId) {
    GameObject* soundObj;

    if (soundId != 0) {
        soundObj = obj;
        state->flags = state->flags | SFXPLAYER_STATE_FLAG_ACTIVE;
        if ((placement->flags & SFXPLAYER_FLAG_AT_OBJECT) == 0) {
            soundObj = NULL;
        }
        if (soundObj == NULL || (placement->flags & SFXPLAYER_FLAG_FORCE_POINT) != 0) {
            if (placement->mode == SFXPLAYER_MODE_LOOPED) {
                Sfx_AddLoopedObjectSound(soundObj, soundId);
            } else {
                Sfx_PlayFromObject(soundObj, soundId);
            }
        } else {
            Sfx_PlayAtPositionFromObject(soundObj, soundObj->anim.localPosX, soundObj->anim.localPosY,
                                         soundObj->anim.localPosZ, soundId);
        }
    }
}

#define SFXPLAYER_STOP_SOUND_PAIR()                                                                                    \
    do {                                                                                                               \
        if (placement->mode == SFXPLAYER_MODE_LOOPED) {                                                                \
            soundId = placement->primarySfxId;                                                                         \
            if (soundId != 0) {                                                                                        \
                Sfx_RemoveLoopedObjectSound(obj, soundId);                                                        \
            }                                                                                                          \
            soundId = placement->secondarySfxId;                                                                       \
            if (soundId != 0) {                                                                                        \
                Sfx_RemoveLoopedObjectSound(obj, soundId);                                                        \
            }                                                                                                          \
        } else {                                                                                                       \
            soundId = placement->primarySfxId;                                                                         \
            if (soundId != 0) {                                                                                        \
                Sfx_StopFromObject(obj, soundId);                                                                 \
            }                                                                                                          \
            soundId = placement->secondarySfxId;                                                                       \
            if (soundId != 0) {                                                                                        \
                Sfx_StopFromObject(obj, soundId);                                                                 \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

void SfxPlayer_update(GameObject* obj) {
    SfxPlayerState* state;
    SfxPlayerPlacement* placement;
    GameObject* focusObj;
    u16 soundId;
    int bitState;

    state = obj->extra;
    placement = (SfxPlayerPlacement*)obj->anim.placementData;
    if ((placement->flags & SFXPLAYER_FLAG_ROM_CURVE) != 0) {
        if (getCurSeqNo() != 0) {
            focusObj = (*gCameraInterface)->getCamera();
            (*gRomCurveInterface)
                ->findPosition(SFXPLAYER_ROM_CURVE_SEARCH_MODE, placement->romCurveChannel, focusObj->anim.worldPosX,
                               focusObj->anim.worldPosY, focusObj->anim.worldPosZ, &obj->anim.localPosX,
                               &obj->anim.localPosY, &obj->anim.localPosZ);
        } else {
            focusObj = Obj_GetPlayerObject();
            (*gRomCurveInterface)
                ->findPosition(SFXPLAYER_ROM_CURVE_SEARCH_MODE, placement->romCurveChannel, focusObj->anim.worldPosX,
                               focusObj->anim.worldPosY, focusObj->anim.worldPosZ, &obj->anim.localPosX,
                               &obj->anim.localPosY, &obj->anim.localPosZ);
        }
    }

    if (placement->gameBit > 0) {
        bitState = mainGetBit(placement->gameBit);
    }

    switch (placement->mode) {
    case SFXPLAYER_MODE_GAME_BIT:
        if (placement->gameBit > 0) {
            if (state->gameBitState != 0) {
                if (bitState == 0) {
                    state->gameBitState = 0;
                    if ((placement->flags & SFXPLAYER_FLAG_TRIGGER_ON_CLEAR) != 0) {
                        SfxPlayer_startSound(obj, placement, state, placement->primarySfxId);
                        SfxPlayer_startSound(obj, placement, state, placement->secondarySfxId);
                    }
                }
            } else if (bitState != 0) {
                state->gameBitState = 1;
                if ((placement->flags & SFXPLAYER_FLAG_TRIGGER_ON_SET) != 0) {
                    SfxPlayer_startSound(obj, placement, state, placement->primarySfxId);
                    SfxPlayer_startSound(obj, placement, state, placement->secondarySfxId);
                }
            }
        }
        break;
    case SFXPLAYER_MODE_LOOPED:
        if ((placement->gameBit == SFXPLAYER_GAME_BIT_NONE) ||
            (((placement->flags & SFXPLAYER_FLAG_TRIGGER_ON_SET) != 0) && (bitState != 0)) ||
            (((placement->flags & SFXPLAYER_FLAG_TRIGGER_ON_CLEAR) != 0) && (bitState == 0))) {
            if ((state->flags & SFXPLAYER_STATE_FLAG_ACTIVE) == 0) {
                SfxPlayer_startSound(obj, placement, state, placement->primarySfxId);
                SfxPlayer_startSound(obj, placement, state, placement->secondarySfxId);
            }
        } else if ((state->flags & SFXPLAYER_STATE_FLAG_ACTIVE) != 0) {
            state->flags = state->flags & ~SFXPLAYER_STATE_FLAG_ACTIVE;
            SFXPLAYER_STOP_SOUND_PAIR();
        }
        break;
    case SFXPLAYER_MODE_RANDOM_DELAY:
        if ((placement->gameBit == SFXPLAYER_GAME_BIT_NONE) ||
            (((placement->flags & SFXPLAYER_FLAG_TRIGGER_ON_SET) != 0) && (bitState != 0)) ||
            (((placement->flags & SFXPLAYER_FLAG_TRIGGER_ON_CLEAR) != 0) && (bitState == 0))) {
            state->delayTimer -= timeDelta;
            if (state->delayTimer <= 0.0f) {
                state->delayTimer = (f32)(s32)randomGetRange(placement->randomDelayMin, placement->randomDelayMax) *
                                    SFXPLAYER_SECONDS_TO_FRAMES;
                SfxPlayer_startSound(obj, placement, state, placement->primarySfxId);
                SfxPlayer_startSound(obj, placement, state, placement->secondarySfxId);
            }
        } else if ((state->flags & SFXPLAYER_STATE_FLAG_ACTIVE) != 0) {
            state->flags = state->flags & ~SFXPLAYER_STATE_FLAG_ACTIVE;
            SFXPLAYER_STOP_SOUND_PAIR();
        }
        break;
    }
}

void SfxPlayer_init(GameObject* obj, SfxPlayerPlacement* placement) {
    SfxPlayerState* state = obj->extra;
    int mode;

    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED | OBJECT_OBJFLAG_HIDDEN);
    mode = placement->mode;
    switch (mode) {
    case SFXPLAYER_MODE_GAME_BIT: {
        s16 bit = placement->gameBit;
        if (bit > 0) {
            state->gameBitState = mainGetBit(bit);
        }
        break;
    }
    case SFXPLAYER_MODE_LOOPED:
        break;
    case SFXPLAYER_MODE_RANDOM_DELAY: {
        int delay = randomGetRange(placement->randomDelayMin, placement->randomDelayMax);
        f32 delayF = delay;
        delayF = SFXPLAYER_SECONDS_TO_FRAMES * delayF;
        state->delayTimer = delayF;
        break;
    }
    }
}

ObjectDescriptor gSfxPlayerObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)SfxPlayer_init,
    (ObjectDescriptorCallback)SfxPlayer_update,
    0,
    0,
    (ObjectDescriptorCallback)SfxPlayer_free,
    0,
    SfxPlayer_getExtraSize,
};
