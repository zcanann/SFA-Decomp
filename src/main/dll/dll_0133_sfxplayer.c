#include "main/dll/MMP/MMP_asteroid.h"

extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);

extern f32 timeDelta;

#include "main/dll/MMP/MMP_moonrock.h"
#include "main/camera_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"

typedef struct SfxplayerObjPlacement
{
    u8 pad0[0x14 - 0x0];
    u32 unk14;
    u32 unk18;
    u8 pad1C[0x22 - 0x1C];
    u16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} SfxplayerObjPlacement;

extern f32 lbl_803E40B8;

extern u8* Obj_GetPlayerObject(void);
extern int getCurSeqNo(void);

/* lightning_render: deref obj->_b8->_0 (effect handle); if non-null call
 * lightningRender(handle). */

/* WaterFallSpray_init: stash 3 signed-byte<<8 fields at obj+0..+4, clear
 * obj+0xf4, install WaterFallSpray_SeqFn as the think routine at obj+0xbc, then
 * pick one of two SFX-id pairs based on the range of obj->_4c->_14. */

/* sfxplayerObj_init: prime obj->_b0 with SFXPLAYER_OBJECT_FLAGS, then dispatch
 * on (s8)data->_1d: gamebit mode stores GameBit_Get(data->_18) at sub[0] if the
 * event id is positive; random-delay mode computes randomGetRange(data->_1e, data->_1f)
 * scaled by lbl_803E40BC as f32; cases 1 and >=3 are no-ops. */
extern f32 lbl_803E40BC;

extern void Sfx_RemoveLoopedObjectSound(u8* obj, u16 sfx);
extern void Sfx_StopFromObject(u8* obj, u16 sfx);
extern void Sfx_AddLoopedObjectSound(u8* obj, u16 sfx);
extern void Sfx_PlayFromObject(u8* obj, u16 sfx);
extern void Sfx_PlayAtPositionFromObject(f32 x, f32 y, f32 z, u8* obj, u16 sfx);

void sfxplayerObj_init(u8* obj, u8* data)
{
    u8* sub = ((GameObject*)obj)->extra;
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
                *(int*)sub = GameBit_Get(bit);
            }
            break;
        }
    case SFXPLAYER_MODE_LOOPED:
        break;
    case SFXPLAYER_MODE_RANDOM_DELAY:
        {
            int v = randomGetRange(data[0x1e], data[0x1f]);
            f32 fv = (f32)v;
            fv = lbl_803E40BC * fv;
            *(f32*)sub = fv;
            break;
        }
    }
}

/* sfxplayerObj_free: bit-0 of obj->_b8->_4 gates teardown. When set, clear
 * it and stop two sfx loops (data->_1a and data->_22). Mode depends on
 * data->_1d: 1 → Sfx_RemoveLoopedObjectSound, else Sfx_StopFromObject. */

void sfxplayerObj_free(u8* obj)
{
    u8* data = *(u8**)&((GameObject*)obj)->anim.placementData;
    u8* sub = ((GameObject*)obj)->extra;
    u8 flag = sub[4];
    if ((flag & SFXPLAYER_RUNTIME_ACTIVE_FLAG) == 0) return;
    sub[4] = (u8)(flag & ~SFXPLAYER_RUNTIME_ACTIVE_FLAG);
    if (data[0x1d] == SFXPLAYER_MODE_LOOPED)
    {
        u16 sfx1 = *(u16*)(data + 0x1a);
        if (sfx1 != 0) Sfx_RemoveLoopedObjectSound(obj, sfx1);
        {
            u16 sfx2 = ((SfxplayerObjPlacement*)data)->unk22;
            if (sfx2 != 0) Sfx_RemoveLoopedObjectSound(obj, sfx2);
        }
    }
    else
    {
        u16 sfx1 = *(u16*)(data + 0x1a);
        if (sfx1 != 0) Sfx_StopFromObject(obj, sfx1);
        {
            u16 sfx2 = ((SfxplayerObjPlacement*)data)->unk22;
            if (sfx2 != 0) Sfx_StopFromObject(obj, sfx2);
        }
    }
}

#define SFXPLAYER_START_SOUND(sfxExpr) \
    do { \
        soundId = (sfxExpr); \
        if (soundId != 0) { \
            soundObj = obj; \
            state[4] = state[4] | SFXPLAYER_RUNTIME_ACTIVE_FLAG; \
            if ((data[0x1c] & 0x10) == 0) { \
                soundObj = NULL; \
            } \
            if (soundObj == NULL || (data[0x1c] & 1) != 0) { \
                if (data[0x1d] == SFXPLAYER_MODE_LOOPED) { \
                    Sfx_AddLoopedObjectSound(soundObj, soundId); \
                } \
                else { \
                    Sfx_PlayFromObject(soundObj, soundId); \
                } \
            } \
            else { \
                Sfx_PlayAtPositionFromObject(*(f32 *)(soundObj + 0x0c), \
                                             *(f32 *)(soundObj + 0x10), \
                                             *(f32 *)(soundObj + 0x14), soundObj, soundId); \
            } \
        } \
    } while (0)

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
    u8* state;
    u8* data;
    u8* focusObj;
    u8* soundObj;
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
                *(f32*)(focusObj + 0x18), *(f32*)(focusObj + 0x1c), *(f32*)(focusObj + 0x20),
                obj + 0x0c, obj + 0x10, obj + 0x14);
        }
        else
        {
            focusObj = Obj_GetPlayerObject();
            ((void (*)(int, int, f32, f32, f32, u8*, u8*, u8*))(*gRomCurveInterface)->slot20)(
                7, *(s8*)(data + 0x20),
                *(f32*)(focusObj + 0x18), *(f32*)(focusObj + 0x1c), *(f32*)(focusObj + 0x20),
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
            if (*(int*)state != 0)
            {
                if (bitState == 0)
                {
                    *(u32*)state = 0;
                    if ((data[0x1c] & 4) != 0)
                    {
                        SFXPLAYER_START_SOUND(*(u16 *)(data + 0x1a));
                        SFXPLAYER_START_SOUND(((SfxplayerObjPlacement *)data)->unk22);
                    }
                }
            }
            else if (bitState != 0)
            {
                *(u32*)state = 1;
                if ((data[0x1c] & 2) != 0)
                {
                    SFXPLAYER_START_SOUND(*(u16 *)(data + 0x1a));
                    SFXPLAYER_START_SOUND(((SfxplayerObjPlacement *)data)->unk22);
                }
            }
        }
        break;
    case SFXPLAYER_MODE_LOOPED:
        if ((*(s16*)(data + 0x18) == -1) ||
            (((data[0x1c] & 2) != 0) && (bitState != 0)) ||
            (((data[0x1c] & 4) != 0) && (bitState == 0)))
        {
            if ((state[4] & SFXPLAYER_RUNTIME_ACTIVE_FLAG) == 0)
            {
                SFXPLAYER_START_SOUND(*(u16 *)(data + 0x1a));
                SFXPLAYER_START_SOUND(((SfxplayerObjPlacement *)data)->unk22);
            }
        }
        else if ((state[4] & SFXPLAYER_RUNTIME_ACTIVE_FLAG) != 0)
        {
            state[4] = state[4] & ~SFXPLAYER_RUNTIME_ACTIVE_FLAG;
            SFXPLAYER_STOP_PAIR();
        }
        break;
    case 2:
        if ((*(s16*)(data + 0x18) == -1) ||
            (((data[0x1c] & 2) != 0) && (bitState != 0)) ||
            (((data[0x1c] & 4) != 0) && (bitState == 0)))
        {
            *(f32*)state -= timeDelta;
            if (*(f32*)state <= lbl_803E40B8)
            {
                *(f32*)state = (f32)(s32)
                randomGetRange(data[0x1e], data[0x1f]) * lbl_803E40BC;
                SFXPLAYER_START_SOUND(*(u16 *)(data + 0x1a));
                SFXPLAYER_START_SOUND(((SfxplayerObjPlacement *)data)->unk22);
            }
        }
        else if ((state[4] & SFXPLAYER_RUNTIME_ACTIVE_FLAG) != 0)
        {
            state[4] = state[4] & ~SFXPLAYER_RUNTIME_ACTIVE_FLAG;
            SFXPLAYER_STOP_PAIR();
        }
        break;
    }
}


int sfxplayerObj_getExtraSize(void) { return 0x8; }

