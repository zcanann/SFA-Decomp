/*
 * spdrape (DLL 0x288) - a hanging cloth drape / door curtain in the
 * SnowHorn shop area that swings aside as the player walks through it.
 *
 * Init builds a vertical plane through the drape (planeNormal / planeD,
 * derived from its facing angle and world position). The plane's signed
 * distance to the player picks which of two swing-direction move tables
 * (gSpDrapeSwingLeftMoveTable / gSpDrapeSwingRightMoveTable) to play, so the cloth always parts away
 * from the approaching player. The update() switch is the swing state
 * machine keyed on the active animation move; it rustles (sfx 0x13f),
 * swings (0x140) and flutters (0x141) and re-opens if the player lingers.
 */
#include "main/dll/DR/dll_0287_spscarab.h"
#include "main/audio/sfx_play_legacy_api.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/camera.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/SP/dll_0288_spdrape.h"

#define SPDRAPE_OBJFLAG_HIDDEN             0x4000
#define SPDRAPE_OBJFLAG_HITDETECT_DISABLED 0x2000

/* indices into a swing-direction move table (gSpDrapeSwingLeftMoveTable / gSpDrapeSwingRightMoveTable) */
enum
{
    SPDRAPE_MOVE_OPEN = 0,
    SPDRAPE_MOVE_HOLD = 1,
    SPDRAPE_MOVE_CLOSE = 2
};

extern f32 gSpDrapeSwingLeftMoveTable;  /* swing-left move-id table */
extern f32 gSpDrapeSwingRightMoveTable; /* swing-right move-id table */
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E5AA0 = 0.0f;
__declspec(section ".sdata2") f32 gSpDrapeNearRadiusSq = 4900.0f; /* squared player-proximity radius */
__declspec(section ".sdata2") f32 lbl_803E5AA8 = 0.0175f;
__declspec(section ".sdata2") f32 gSpDrapeLeaveRadius = 8100.0f; /* player-left radius (re-close) */
__declspec(section ".sdata2") f32 lbl_803E5AB0 = 0.0165f;
__declspec(section ".sdata2") f32 lbl_803E5AB4 = 0.0144f;
__declspec(section ".sdata2") f32 gSpDrapeReopenProgress = 0.6f;
__declspec(section ".sdata2") f32 lbl_803E5ABC = 0.0072f;
__declspec(section ".sdata2") f32 lbl_803E5AC0 = 10.0f;
__declspec(section ".sdata2") f32 lbl_803E5AC4 = 32767.0f;
__declspec(section ".sdata2") f32 gSpDrapePi = 3.1415927f;
__declspec(section ".sdata2") f32 lbl_803E5ACC = 32768.0f;
#pragma explicit_zero_data off

extern void Sfx_StopObjectChannel(u32 obj, u32 channel);

ObjectDescriptor gSPDrapeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)spdrape_initialise,
    (ObjectDescriptorCallback)spdrape_release,
    0,
    (ObjectDescriptorCallback)spdrape_init,
    (ObjectDescriptorCallback)spdrape_update,
    (ObjectDescriptorCallback)spdrape_hitDetect,
    (ObjectDescriptorCallback)spdrape_render,
    (ObjectDescriptorCallback)spdrape_free,
    (ObjectDescriptorCallback)spdrape_getObjectTypeId,
    spdrape_getExtraSize,
};

int spdrape_getExtraSize(void)
{
    return 0x18;
}

int spdrape_getObjectTypeId(void)
{
    return 0;
}

void spdrape_free(void)
{
}

void spdrape_render(void)
{
}

void spdrape_hitDetect(void)
{
}

void spdrape_update(GameObject* obj)
{
    f32* state;
    char* player;

    state = (obj)->extra;
    player = (char*)Obj_GetPlayerObject();
    switch ((obj)->anim.currentMove)
    {
    case 0: /* idle: rustle, and swing open when the player is near */
        if ((s16)(((SpdrapeState*)state)->sfxTimer -= framesThisStep) <= 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_propsp_6);
            ((SpdrapeState*)state)->sfxTimer = randomGetRange(0xb4, 0x12c);
        }
        if (getXZDistance(&(obj)->anim.worldPosX, (f32*)(player + 0x18)) < gSpDrapeNearRadiusSq)
        {
            if (player != 0)
            {
                if (state[3] + (state[1] * ((GameObject*)player)->anim.localPosX +
                                state[2] * ((GameObject*)player)->anim.localPosZ) <
                    lbl_803E5AA0)
                {
                    ((SpdrapeState*)state)->moveTable = (int)&gSpDrapeSwingLeftMoveTable;
                }
                else
                {
                    ((SpdrapeState*)state)->moveTable = (int)&gSpDrapeSwingRightMoveTable;
                }
            }
            ObjAnim_SetCurrentMove((int)obj, **(u8**)&((SpdrapeState*)state)->moveTable, lbl_803E5AA0, 0);
            *state = lbl_803E5AA8;
            Sfx_PlayFromObject((int)obj, SFXTRIG_cagesqk11);
            Camera_GetCurrentViewSlot();
        }
        break;
    case 1: /* opening: hold while near, close once the player leaves */
    case 4:
        if (((SpdrapeState*)state)->moveActive != 0)
        {
            if (getXZDistance(&(obj)->anim.worldPosX, (f32*)(player + 0x18)) > gSpDrapeLeaveRadius)
            {
                ObjAnim_SetCurrentMove((int)obj, (*(u8**)&((SpdrapeState*)state)->moveTable)[SPDRAPE_MOVE_CLOSE],
                                       lbl_803E5AA0, 0);
                Sfx_PlayFromObject((int)obj, SFXTRIG_cagesqk11);
                *state = lbl_803E5AB0;
            }
            else
            {
                ObjAnim_SetCurrentMove((int)obj, (*(u8**)&((SpdrapeState*)state)->moveTable)[SPDRAPE_MOVE_HOLD],
                                       lbl_803E5AA0, 0);
                *state = lbl_803E5AB4;
            }
        }
        break;
    case 2: /* held open: flutter, close when the player leaves */
    case 5:
        Sfx_PlayFromObject((int)obj, SFXTRIG_wickhit16);
        if (getXZDistance(&(obj)->anim.worldPosX, (f32*)(player + 0x18)) > gSpDrapeLeaveRadius)
        {
            ObjAnim_SetCurrentMove((int)obj, (*(u8**)&((SpdrapeState*)state)->moveTable)[SPDRAPE_MOVE_CLOSE],
                                   lbl_803E5AA0, 0);
            Sfx_StopObjectChannel((int)obj, 0x40);
            Sfx_PlayFromObject((int)obj, SFXTRIG_cagesqk11);
            *state = lbl_803E5AB0;
        }
        break;
    case 3: /* closing: re-open if the player returns, else settle to idle */
    case 6:
        if (((obj)->anim.currentMoveProgress > gSpDrapeReopenProgress) &&
            (getXZDistance(&(obj)->anim.worldPosX, (f32*)(player + 0x18)) < gSpDrapeNearRadiusSq))
        {
            if (player != 0)
            {
                if (state[3] + (state[1] * ((GameObject*)player)->anim.localPosX +
                                state[2] * ((GameObject*)player)->anim.localPosZ) <
                    lbl_803E5AA0)
                {
                    ((SpdrapeState*)state)->moveTable = (int)&gSpDrapeSwingLeftMoveTable;
                }
                else
                {
                    ((SpdrapeState*)state)->moveTable = (int)&gSpDrapeSwingRightMoveTable;
                }
            }
            ObjAnim_SetCurrentMove((int)obj, **(u8**)&((SpdrapeState*)state)->moveTable, lbl_803E5AA0, 0);
            Sfx_PlayFromObject((int)obj, SFXTRIG_cagesqk11);
            *state = lbl_803E5AA8;
        }
        else if (((SpdrapeState*)state)->moveActive != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E5AA0, 0);
            *state = lbl_803E5ABC;
            Camera_GetCurrentViewSlot();
        }
        break;
    }
    ((SpdrapeState*)state)->moveActive =
        ObjAnim_AdvanceCurrentMove((int)obj, *state, timeDelta, NULL);
}

void spdrape_init(int* obj, u8* def)
{

    f32* state;
    int* player;
    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags |= SPDRAPE_OBJFLAG_HITDETECT_DISABLED;
    ((GameObject*)obj)->objectFlags |= SPDRAPE_OBJFLAG_HIDDEN;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)((SpdrapeObjectDef*)def)->facingByte << 8);
    if (((SpdrapeObjectDef*)def)->motionScaleNum != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale =
            (f32)(s32)((SpdrapeObjectDef*)def)->motionScaleNum / lbl_803E5AC4 * lbl_803E5AC0;
    }
    state[0] = lbl_803E5ABC;
    state[1] = mathSinf(gSpDrapePi * (f32)(s32) * (s16*)obj / lbl_803E5ACC);
    state[2] = mathCosf(gSpDrapePi * (f32)(s32) * (s16*)obj / lbl_803E5ACC);
    state[3] = -(state[1] * ((GameObject*)obj)->anim.localPosX + state[2] * ((GameObject*)obj)->anim.localPosZ);
    ((SpdrapeState*)state)->sfxTimer = randomGetRange(0xb4, 0x12c);
    player = (int*)Obj_GetPlayerObject();
    if (player != NULL)
    {
        if (state[1] * ((GameObject*)player)->anim.localPosX + state[2] * ((GameObject*)player)->anim.localPosZ +
                state[3] <
            lbl_803E5AA0)
        {
            ((SpdrapeState*)state)->moveTable = (int)&gSpDrapeSwingLeftMoveTable;
        }
        else
        {
            ((SpdrapeState*)state)->moveTable = (int)&gSpDrapeSwingRightMoveTable;
        }
    }
}

void spdrape_release(void)
{
}

void spdrape_initialise(void)
{
}
