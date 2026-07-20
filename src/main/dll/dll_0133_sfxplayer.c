/*
 * sfxplayer (DLL 0x133) - a placement-driven ambient/triggered SFX emitter.
 *
 * Each instance reads its behaviour from placement bytes: data->mode selects
 * the mode (SFXPLAYER_MODE_GAMEBIT / _LOOPED / _RANDOM_DELAY), data->flags
 * holds the trigger/positioning flag bits, data[0x18] a gate game bit, the
 * sfx-id pair at data[0x1a]/data[0x22], and the random-delay range at
 * data->randomDelayMin/data->randomDelayMax.
 *
 * Per frame sfxplayerObj_update optionally feeds a rom-curve channel (flag
 * 0x8) tracking either the active camera or the player object, evaluates the
 * gate bit, and starts/stops the sfx pair via the Sfx_* API. Positioning is
 * chosen by flags 0x10 (at object position) and 0x1 (force point form).
 * sfxplayerObj_free tears down any still-active looped sounds.
 *
 * This TU owns these symbols and the SFXPLAYER_* constants.
 */
#include "main/dll/dll_0133_sfxplayer.h"
#include "main/objseq_api.h"
#include "main/camera_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "main/frame_timing.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_stop_object_api.h"

int sfxplayerObj_getExtraSize(void)
{
    return sizeof(SfxplayerObjState);
}

void sfxplayerObj_free(GameObject* obj)
{
    SfxplayerPlacement* data = (SfxplayerPlacement*)obj->anim.placementData;
    SfxplayerObjState* state = obj->extra;
    u8 flag = state->flags;
    if ((flag & SFXPLAYER_RUNTIME_ACTIVE_FLAG) == 0)
        return;
    state->flags = (u8)(flag & ~SFXPLAYER_RUNTIME_ACTIVE_FLAG);
    if (data->mode == SFXPLAYER_MODE_LOOPED)
    {
        u16 sfx1 = data->primarySfxId;
        if (sfx1 != 0)
            Sfx_RemoveLoopedObjectSound((u32)obj, sfx1);
        {
            u16 sfx2 = data->secondarySfxId;
            if (sfx2 != 0)
                Sfx_RemoveLoopedObjectSound((u32)obj, sfx2);
        }
    }
    else
    {
        u16 sfx1 = data->primarySfxId;
        if (sfx1 != 0)
            Sfx_StopFromObject((u32)obj, sfx1);
        {
            u16 sfx2 = data->secondarySfxId;
            if (sfx2 != 0)
                Sfx_StopFromObject((u32)obj, sfx2);
        }
    }
}

static inline void sfxplayerStartSound(GameObject* obj, SfxplayerPlacement* data, SfxplayerObjState* state,
                                       u16 soundId)
{
    GameObject* soundObj;
    if (soundId != 0)
    {
        soundObj = obj;
        state->flags = state->flags | SFXPLAYER_RUNTIME_ACTIVE_FLAG;
        if ((data->flags & SFXPLAYER_FLAG_AT_OBJECT) == 0)
        {
            soundObj = NULL;
        }
        if (soundObj == NULL || (data->flags & SFXPLAYER_FLAG_FORCE_POINT) != 0)
        {
            if (data->mode == SFXPLAYER_MODE_LOOPED)
            {
                Sfx_AddLoopedObjectSound((u32)soundObj, soundId);
            }
            else
            {
                Sfx_PlayFromObject((u32)soundObj, soundId);
            }
        }
        else
        {
            Sfx_PlayAtPositionFromObject((int)soundObj, soundObj->anim.localPosX, soundObj->anim.localPosY,
                                         soundObj->anim.localPosZ, soundId);
        }
    }
}

#define SFXPLAYER_STOP_PAIR()                                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        if (data->mode == SFXPLAYER_MODE_LOOPED)                                                                       \
        {                                                                                                              \
            soundId = data->primarySfxId;                                                                    \
            if (soundId != 0)                                                                                          \
            {                                                                                                          \
                Sfx_RemoveLoopedObjectSound((u32)obj, soundId);                                                       \
            }                                                                                                          \
            soundId = data->secondarySfxId;                                                                  \
            if (soundId != 0)                                                                                          \
            {                                                                                                          \
                Sfx_RemoveLoopedObjectSound((u32)obj, soundId);                                                       \
            }                                                                                                          \
        }                                                                                                              \
        else                                                                                                           \
        {                                                                                                              \
            soundId = data->primarySfxId;                                                                    \
            if (soundId != 0)                                                                                          \
            {                                                                                                          \
                Sfx_StopFromObject((u32)obj, soundId);                                                                \
            }                                                                                                          \
            soundId = data->secondarySfxId;                                                                  \
            if (soundId != 0)                                                                                          \
            {                                                                                                          \
                Sfx_StopFromObject((u32)obj, soundId);                                                                \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

void sfxplayerObj_update(GameObject* obj)
{
    SfxplayerObjState* state;
    SfxplayerPlacement* data;
    GameObject* focusObj;
    u16 soundId;
    int bitState;

    state = obj->extra;
    data = (SfxplayerPlacement*)obj->anim.placementData;
    if ((data->flags & SFXPLAYER_FLAG_ROM_CURVE) != 0)
    {
        if (getCurSeqNo() != 0)
        {
            focusObj = (*gCameraInterface)->getCamera();
            (*gRomCurveInterface)->findPosition(
                7, data->romCurveChannel, focusObj->anim.worldPosX, focusObj->anim.worldPosY,
                focusObj->anim.worldPosZ, &obj->anim.localPosX, &obj->anim.localPosY, &obj->anim.localPosZ);
        }
        else
        {
            focusObj = Obj_GetPlayerObject();
            (*gRomCurveInterface)->findPosition(
                7, data->romCurveChannel, focusObj->anim.worldPosX, focusObj->anim.worldPosY,
                focusObj->anim.worldPosZ, &obj->anim.localPosX, &obj->anim.localPosY, &obj->anim.localPosZ);
        }
    }

    if (data->gameBit > 0)
    {
        bitState = mainGetBit(data->gameBit);
    }

    switch (data->mode)
    {
    case SFXPLAYER_MODE_GAMEBIT:
        if (data->gameBit > 0)
        {
            if (state->gameBitState != 0)
            {
                if (bitState == 0)
                {
                    state->gameBitState = 0;
                    if ((data->flags & SFXPLAYER_FLAG_TRIGGER_ON_CLEAR) != 0)
                    {
                        sfxplayerStartSound(obj, data, state, data->primarySfxId);
                        sfxplayerStartSound(obj, data, state, data->secondarySfxId);
                    }
                }
            }
            else if (bitState != 0)
            {
                state->gameBitState = 1;
                if ((data->flags & SFXPLAYER_FLAG_TRIGGER_ON_SET) != 0)
                {
                    sfxplayerStartSound(obj, data, state, data->primarySfxId);
                    sfxplayerStartSound(obj, data, state, data->secondarySfxId);
                }
            }
        }
        break;
    case SFXPLAYER_MODE_LOOPED:
        if ((data->gameBit == -1) || (((data->flags & SFXPLAYER_FLAG_TRIGGER_ON_SET) != 0) && (bitState != 0)) ||
            (((data->flags & SFXPLAYER_FLAG_TRIGGER_ON_CLEAR) != 0) && (bitState == 0)))
        {
            if ((state->flags & SFXPLAYER_RUNTIME_ACTIVE_FLAG) == 0)
            {
                sfxplayerStartSound(obj, data, state, data->primarySfxId);
                sfxplayerStartSound(obj, data, state, data->secondarySfxId);
            }
        }
        else if ((state->flags & SFXPLAYER_RUNTIME_ACTIVE_FLAG) != 0)
        {
            state->flags = state->flags & ~SFXPLAYER_RUNTIME_ACTIVE_FLAG;
            SFXPLAYER_STOP_PAIR();
        }
        break;
    case SFXPLAYER_MODE_RANDOM_DELAY:
        if ((data->gameBit == -1) || (((data->flags & SFXPLAYER_FLAG_TRIGGER_ON_SET) != 0) && (bitState != 0)) ||
            (((data->flags & SFXPLAYER_FLAG_TRIGGER_ON_CLEAR) != 0) && (bitState == 0)))
        {
            state->delayTimer -= timeDelta;
            if (state->delayTimer <= 0.0f)
            {
                state->delayTimer =
                    (f32)(s32)randomGetRange(data->randomDelayMin, data->randomDelayMax) * 60.0f;
                sfxplayerStartSound(obj, data, state, data->primarySfxId);
                sfxplayerStartSound(obj, data, state, data->secondarySfxId);
            }
        }
        else if ((state->flags & SFXPLAYER_RUNTIME_ACTIVE_FLAG) != 0)
        {
            state->flags = state->flags & ~SFXPLAYER_RUNTIME_ACTIVE_FLAG;
            SFXPLAYER_STOP_PAIR();
        }
        break;
    }
}

void sfxplayerObj_init(GameObject* obj, SfxplayerPlacement* data)
{
    SfxplayerObjState* state = obj->extra;
    int mode;
    obj->objectFlags = (u16)(obj->objectFlags | SFXPLAYER_OBJECT_FLAGS);
    mode = data->mode;
    switch (mode)
    {
    case SFXPLAYER_MODE_GAMEBIT:
    {
        s16 bit = data->gameBit;
        if (bit > 0)
        {
            state->gameBitState = mainGetBit(bit);
        }
        break;
    }
    case SFXPLAYER_MODE_LOOPED:
        break;
    case SFXPLAYER_MODE_RANDOM_DELAY:
    {
        int delay = randomGetRange(data->randomDelayMin, data->randomDelayMax);
        f32 delayF = delay;
        delayF = 60.0f * delayF;
        state->delayTimer = delayF;
        break;
    }
    }
}
