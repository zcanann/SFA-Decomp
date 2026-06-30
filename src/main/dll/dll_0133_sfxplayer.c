/*
 * sfxplayer (DLL 0x133) - a placement-driven ambient/triggered SFX emitter.
 *
 * Each instance reads its behaviour from placement bytes: data[0x1d] selects
 * the mode (SFXPLAYER_MODE_GAMEBIT / _LOOPED / _RANDOM_DELAY), data[0x1c]
 * holds the trigger/positioning flag bits, data[0x18] a gate game bit, the
 * sfx-id pair at data[0x1a]/data[0x22], and the random-delay range at
 * data[0x1e]/data[0x1f].
 *
 * Per frame sfxplayerObj_update optionally feeds a rom-curve channel (flag
 * 0x8) tracking either the active camera or the player object, evaluates the
 * gate bit, and starts/stops the sfx pair via the Sfx_* API. Positioning is
 * chosen by flags 0x10 (at object position) and 0x1 (force point form).
 * sfxplayerObj_free tears down any still-active looped sounds.
 *
 * Home TU of these symbols and the SFXPLAYER_* constants is MMP_moonrock.
 */
#include "main/dll/MMP/MMP_moonrock.h"
#include "main/camera_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"


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
    union {
        int gameBitState;
        f32 delayTimer;
    };
    u8 flags;
    u8 pad5[3];
} SfxplayerObjState;

STATIC_ASSERT(sizeof(SfxplayerObjState) == 0x8);
STATIC_ASSERT(offsetof(SfxplayerObjState, flags) == 0x4);

extern int getCurSeqNo(void);
extern void Sfx_RemoveLoopedObjectSound(u8* obj, u16 sfx);
extern void Sfx_StopFromObject(u8* obj, u16 sfx);
extern void Sfx_AddLoopedObjectSound(u8* obj, u16 sfx);
extern void Sfx_PlayFromObject(u8* obj, u16 sfx);
extern void Sfx_PlayAtPositionFromObject(f32 x, f32 y, f32 z, u8* obj, u16 sfx);
extern f32 lbl_803E40B8;
extern f32 lbl_803E40BC;

void sfxplayerObj_init(u8* obj, u8* data)
{
    SfxplayerObjState* sub = ((GameObject*)obj)->extra;
    int type;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | SFXPLAYER_OBJECT_FLAGS);
    type = data[0x1d];
    switch (type)
    {
    case SFXPLAYER_MODE_GAMEBIT:
        {
            s16 bit = *(s16*)(data + 0x18);
            if (bit > 0)
            {
                sub->gameBitState = GameBit_Get(bit);
            }
            break;
        }
    case SFXPLAYER_MODE_LOOPED:
        break;
    case SFXPLAYER_MODE_RANDOM_DELAY:
        {
            int v = randomGetRange(data[0x1e], data[0x1f]);
            f32 fv = v;
            fv = lbl_803E40BC * fv;
            sub->delayTimer = fv;
            break;
        }
    }
}

void sfxplayerObj_free(u8* obj)
{
    u8* data = *(u8**)&((GameObject*)obj)->anim.placementData;
    SfxplayerObjState* sub = ((GameObject*)obj)->extra;
    u8 flag = sub->flags;
    if ((flag & SFXPLAYER_RUNTIME_ACTIVE_FLAG) == 0) return;
    sub->flags = (u8)(flag & ~SFXPLAYER_RUNTIME_ACTIVE_FLAG);
    if (data[0x1d] == SFXPLAYER_MODE_LOOPED)
    {
        u16 sfx1 = *(u16*)(data + 0x1a);
        if (sfx1 != 0) Sfx_RemoveLoopedObjectSound(obj, sfx1);
        {
            u16 sfx2 = *(u16*)(data + 0x22);
            if (sfx2 != 0) Sfx_RemoveLoopedObjectSound(obj, sfx2);
        }
    }
    else
    {
        u16 sfx1 = *(u16*)(data + 0x1a);
        if (sfx1 != 0) Sfx_StopFromObject(obj, sfx1);
        {
            u16 sfx2 = *(u16*)(data + 0x22);
            if (sfx2 != 0) Sfx_StopFromObject(obj, sfx2);
        }
    }
}

static inline void sfxplayerStartSound(u8* obj, u8* data, SfxplayerObjState* state, u16 soundId)
{
    u8* soundObj;
    if (soundId != 0) {
        soundObj = obj;
        state->flags = state->flags | SFXPLAYER_RUNTIME_ACTIVE_FLAG;
        if ((data[0x1c] & 0x10) == 0) {
            soundObj = NULL;
        }
        if (soundObj == NULL || (data[0x1c] & 1) != 0) {
            if (data[0x1d] == SFXPLAYER_MODE_LOOPED) {
                Sfx_AddLoopedObjectSound(soundObj, soundId);
            } else {
                Sfx_PlayFromObject(soundObj, soundId);
            }
        } else {
            Sfx_PlayAtPositionFromObject(((GameObject*)soundObj)->anim.localPosX,
                                         ((GameObject*)soundObj)->anim.localPosY,
                                         ((GameObject*)soundObj)->anim.localPosZ, soundObj, soundId);
        }
    }
}

#define SFXPLAYER_START_SOUND(sfxExpr) sfxplayerStartSound(obj, data, state, (sfxExpr))

#define SFXPLAYER_STOP_PAIR() \
    do { \
        if (data[0x1d] == SFXPLAYER_MODE_LOOPED) { \
            soundId = *(u16 *)(data + 0x1a); \
            if (soundId != 0) { \
                Sfx_RemoveLoopedObjectSound(obj, soundId); \
            } \
            soundId = *(u16 *)(data + 0x22); \
            if (soundId != 0) { \
                Sfx_RemoveLoopedObjectSound(obj, soundId); \
            } \
        } \
        else { \
            soundId = *(u16 *)(data + 0x1a); \
            if (soundId != 0) { \
                Sfx_StopFromObject(obj, soundId); \
            } \
            soundId = *(u16 *)(data + 0x22); \
            if (soundId != 0) { \
                Sfx_StopFromObject(obj, soundId); \
            } \
        } \
    } while (0)

void sfxplayerObj_update(u8* obj)
{
    SfxplayerObjState* state;
    u8* data;
    u8* focusObj;
    u16 soundId;
    int bitState;

    state = ((GameObject*)obj)->extra;
    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    if ((data[0x1c] & 8) != 0)
    {
        if (getCurSeqNo() != 0)
        {
            focusObj = (*gCameraInterface)->getCamera();
            ((void (*)(int, int, f32, f32, f32, u8*, u8*, u8*))(*gRomCurveInterface)->slot20)(
                7, *(s8*)(data + 0x20),
                ((GameObject*)focusObj)->anim.worldPosX, ((GameObject*)focusObj)->anim.worldPosY, ((GameObject*)focusObj)->anim.worldPosZ,
                obj + 0x0c, obj + 0x10, obj + 0x14);
        }
        else
        {
            focusObj = Obj_GetPlayerObject();
            ((void (*)(int, int, f32, f32, f32, u8*, u8*, u8*))(*gRomCurveInterface)->slot20)(
                7, *(s8*)(data + 0x20),
                ((GameObject*)focusObj)->anim.worldPosX, ((GameObject*)focusObj)->anim.worldPosY, ((GameObject*)focusObj)->anim.worldPosZ,
                obj + 0x0c, obj + 0x10, obj + 0x14);
        }
    }

    if (*(s16*)(data + 0x18) > 0)
    {
        bitState = GameBit_Get(*(s16*)(data + 0x18));
    }

    switch (data[0x1d])
    {
    case SFXPLAYER_MODE_GAMEBIT:
        if (*(s16*)(data + 0x18) > 0)
        {
            if (state->gameBitState != 0)
            {
                if (bitState == 0)
                {
                    state->gameBitState = 0;
                    if ((data[0x1c] & 4) != 0)
                    {
                        SFXPLAYER_START_SOUND(*(u16 *)(data + 0x1a));
                        SFXPLAYER_START_SOUND(*(u16 *)(data + 0x22));
                    }
                }
            }
            else if (bitState != 0)
            {
                state->gameBitState = 1;
                if ((data[0x1c] & 2) != 0)
                {
                    SFXPLAYER_START_SOUND(*(u16 *)(data + 0x1a));
                    SFXPLAYER_START_SOUND(*(u16 *)(data + 0x22));
                }
            }
        }
        break;
    case SFXPLAYER_MODE_LOOPED:
        if ((*(s16*)(data + 0x18) == -1) ||
            (((data[0x1c] & 2) != 0) && (bitState != 0)) ||
            (((data[0x1c] & 4) != 0) && (bitState == 0)))
        {
            if ((state->flags & SFXPLAYER_RUNTIME_ACTIVE_FLAG) == 0)
            {
                SFXPLAYER_START_SOUND(*(u16 *)(data + 0x1a));
                SFXPLAYER_START_SOUND(*(u16 *)(data + 0x22));
            }
        }
        else if ((state->flags & SFXPLAYER_RUNTIME_ACTIVE_FLAG) != 0)
        {
            state->flags = state->flags & ~SFXPLAYER_RUNTIME_ACTIVE_FLAG;
            SFXPLAYER_STOP_PAIR();
        }
        break;
    case SFXPLAYER_MODE_RANDOM_DELAY:
        if ((*(s16*)(data + 0x18) == -1) ||
            (((data[0x1c] & 2) != 0) && (bitState != 0)) ||
            (((data[0x1c] & 4) != 0) && (bitState == 0)))
        {
            state->delayTimer -= timeDelta;
            if (state->delayTimer <= lbl_803E40B8)
            {
                state->delayTimer = (f32)(s32)
                randomGetRange(data[0x1e], data[0x1f]) * lbl_803E40BC;
                SFXPLAYER_START_SOUND(*(u16 *)(data + 0x1a));
                SFXPLAYER_START_SOUND(*(u16 *)(data + 0x22));
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

int sfxplayerObj_getExtraSize(void) { return 0x8; }
