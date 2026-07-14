/*
 * sfxplayer (DLL 0x133) - a placement-driven ambient/triggered SFX emitter.
 *
 * Each instance reads its behaviour from placement bytes: data->mode selects
 * the mode (SFXPLAYER_MODE_GAMEBIT / _LOOPED / _RANDOM_DELAY), data->flags
 * holds the trigger/positioning flag bits, data[0x18] a gate game bit, the
 * sfx-id pair at data[0x1a]/data[0x22], and the random-delay range at
 * data->randDelayMin/data->randDelayMax.
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
#include "main/audio/sfx_play_pointer_u16_legacy_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_stop_object_api.h"

/*
 * Per-instance runtime state stored in GameObject::extra
 * (sfxplayerObj_getExtraSize returns sizeof == 0x8).
 *
 * Offset 0 overlays the GAMEBIT-mode latched bit value and the
 * RANDOM_DELAY-mode countdown timer; offset 4 holds the runtime flags
 * (SFXPLAYER_RUNTIME_ACTIVE_FLAG marks the sfx pair as currently playing).
 */
typedef struct SfxplayerObjState
{
    union
    {
        int gameBitState;
        f32 delayTimer;
    };
    u8 flags;
    u8 pad5[3];
} SfxplayerObjState;

STATIC_ASSERT(sizeof(SfxplayerObjState) == 0x8);
STATIC_ASSERT(offsetof(SfxplayerObjState, flags) == 0x4);

/*
 * Per-instance placement record (ObjAnimComponent.placementData view).
 * Everything through 0x18 is the shared ObjPlacement head; the fields from
 * 0x18 on are private to this object type.
 */
typedef struct SfxplayerPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 gameBit;        /* 0x18: gate game bit (mainGetBit) */
    u16 sfx1;           /* 0x1a: primary sfx id */
    u8 flags;           /* 0x1c: SFXPLAYER_FLAG_* bits */
    u8 mode;            /* 0x1d: SFXPLAYER_MODE_* selector */
    u8 randDelayMin;    /* 0x1e: RANDOM_DELAY range low */
    u8 randDelayMax;    /* 0x1f: RANDOM_DELAY range high */
    s8 romCurveChannel; /* 0x20: rom-curve channel index */
    u8 pad21[1];        /* 0x21 */
    u16 sfx2;           /* 0x22: secondary sfx id */
} SfxplayerPlacement;

/*
 * Placement flag bits in data->flags (documented in the file header). These
 * are private to this object type's placement record, so they live here.
 */
#define SFXPLAYER_FLAG_FORCE_POINT      0x1  /* force point (positional) sound form */
#define SFXPLAYER_FLAG_TRIGGER_ON_SET   0x2  /* play the pair when the gate bit goes on */
#define SFXPLAYER_FLAG_TRIGGER_ON_CLEAR 0x4  /* play the pair when the gate bit goes off */
#define SFXPLAYER_FLAG_ROM_CURVE        0x8  /* feed a rom-curve channel each frame */
#define SFXPLAYER_FLAG_AT_OBJECT        0x10 /* play at the object's position */

extern f32 lbl_803E40B8;
extern f32 lbl_803E40BC;
int sfxplayerObj_getExtraSize(void)
{
    return 0x8;
}

void sfxplayerObj_free(u8* obj)
{
    SfxplayerPlacement* data = *(SfxplayerPlacement**)&((GameObject*)obj)->anim.placementData;
    SfxplayerObjState* state = ((GameObject*)obj)->extra;
    u8 flag = state->flags;
    if ((flag & SFXPLAYER_RUNTIME_ACTIVE_FLAG) == 0)
        return;
    state->flags = (u8)(flag & ~SFXPLAYER_RUNTIME_ACTIVE_FLAG);
    if (data->mode == SFXPLAYER_MODE_LOOPED)
    {
        u16 sfx1 = data->sfx1;
        if (sfx1 != 0)
            Sfx_RemoveLoopedObjectSoundPtrU16Legacy(obj, sfx1);
        {
            u16 sfx2 = data->sfx2;
            if (sfx2 != 0)
                Sfx_RemoveLoopedObjectSoundPtrU16Legacy(obj, sfx2);
        }
    }
    else
    {
        u16 sfx1 = data->sfx1;
        if (sfx1 != 0)
            Sfx_StopFromObjectPtrU16Legacy(obj, sfx1);
        {
            u16 sfx2 = data->sfx2;
            if (sfx2 != 0)
                Sfx_StopFromObjectPtrU16Legacy(obj, sfx2);
        }
    }
}

static inline void sfxplayerStartSound(u8* obj, SfxplayerPlacement* data, SfxplayerObjState* state, u16 soundId)
{
    u8* soundObj;
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
                Sfx_AddLoopedObjectSoundPtrU16Legacy(soundObj, soundId);
            }
            else
            {
                Sfx_PlayFromObject(soundObj, soundId);
            }
        }
        else
        {
            Sfx_PlayAtPositionFromObjectPtrCanonicalLegacy(
                ((GameObject*)soundObj)->anim.localPosX, ((GameObject*)soundObj)->anim.localPosY,
                ((GameObject*)soundObj)->anim.localPosZ, soundObj, soundId);
        }
    }
}

#define SFXPLAYER_START_SOUND(sfxExpr) sfxplayerStartSound(obj, data, state, (sfxExpr))

#define SFXPLAYER_STOP_PAIR()                                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        if (data->mode == SFXPLAYER_MODE_LOOPED)                                                                       \
        {                                                                                                              \
            soundId = data->sfx1;                                                                            \
            if (soundId != 0)                                                                                          \
            {                                                                                                          \
                Sfx_RemoveLoopedObjectSoundPtrU16Legacy(obj, soundId);                                                 \
            }                                                                                                          \
            soundId = data->sfx2;                                                                            \
            if (soundId != 0)                                                                                          \
            {                                                                                                          \
                Sfx_RemoveLoopedObjectSoundPtrU16Legacy(obj, soundId);                                                 \
            }                                                                                                          \
        }                                                                                                              \
        else                                                                                                           \
        {                                                                                                              \
            soundId = data->sfx1;                                                                            \
            if (soundId != 0)                                                                                          \
            {                                                                                                          \
                Sfx_StopFromObjectPtrU16Legacy(obj, soundId);                                                          \
            }                                                                                                          \
            soundId = data->sfx2;                                                                            \
            if (soundId != 0)                                                                                          \
            {                                                                                                          \
                Sfx_StopFromObjectPtrU16Legacy(obj, soundId);                                                          \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

void sfxplayerObj_update(u8* obj)
{
    SfxplayerObjState* state;
    SfxplayerPlacement* data;
    GameObject* focusObj;
    u16 soundId;
    int bitState;

    state = ((GameObject*)obj)->extra;
    data = *(SfxplayerPlacement**)&((GameObject*)obj)->anim.placementData;
    if ((data->flags & SFXPLAYER_FLAG_ROM_CURVE) != 0)
    {
        if (getCurSeqNoInt() != 0)
        {
            focusObj = (*gCameraInterface)->getCamera();
            ((void (*)(int, int, f32, f32, f32, u8*, u8*, u8*))(*gRomCurveInterface)->slot20)(
                7, data->romCurveChannel, ((GameObject*)focusObj)->anim.worldPosX,
                ((GameObject*)focusObj)->anim.worldPosY, ((GameObject*)focusObj)->anim.worldPosZ, obj + 0x0c,
                obj + 0x10, obj + 0x14);
        }
        else
        {
            focusObj = Obj_GetPlayerObject();
            ((void (*)(int, int, f32, f32, f32, u8*, u8*, u8*))(*gRomCurveInterface)->slot20)(
                7, data->romCurveChannel, ((GameObject*)focusObj)->anim.worldPosX,
                ((GameObject*)focusObj)->anim.worldPosY, ((GameObject*)focusObj)->anim.worldPosZ, obj + 0x0c,
                obj + 0x10, obj + 0x14);
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
                        SFXPLAYER_START_SOUND(data->sfx1);
                        SFXPLAYER_START_SOUND(data->sfx2);
                    }
                }
            }
            else if (bitState != 0)
            {
                state->gameBitState = 1;
                if ((data->flags & SFXPLAYER_FLAG_TRIGGER_ON_SET) != 0)
                {
                    SFXPLAYER_START_SOUND(data->sfx1);
                    SFXPLAYER_START_SOUND(data->sfx2);
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
                SFXPLAYER_START_SOUND(data->sfx1);
                SFXPLAYER_START_SOUND(data->sfx2);
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
            if (state->delayTimer <= lbl_803E40B8)
            {
                state->delayTimer = (f32)(s32)randomGetRange(data->randDelayMin, data->randDelayMax) * lbl_803E40BC;
                SFXPLAYER_START_SOUND(data->sfx1);
                SFXPLAYER_START_SOUND(data->sfx2);
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

void sfxplayerObj_init(u8* obj, u8* dataBytes)
{
    SfxplayerPlacement* data = (SfxplayerPlacement*)dataBytes;
    SfxplayerObjState* state = ((GameObject*)obj)->extra;
    int mode;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | SFXPLAYER_OBJECT_FLAGS);
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
        int delay = randomGetRange(data->randDelayMin, data->randDelayMax);
        f32 delayF = delay;
        delayF = lbl_803E40BC * delayF;
        state->delayTimer = delayF;
        break;
    }
    }
}
