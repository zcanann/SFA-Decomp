/*
 * SPDrape (DLL 648) - a hanging cloth drape / door curtain in the
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
#include "sys/objects.h"
#include "main/camera.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/SP/dll_0288_spdrape.h"
#include "dlls/object_descriptor.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/vecmath.h"

u8 gSpDrapeSwingLeftMoveTable[4] = {1, 2, 3, 0};
u8 gSpDrapeSwingRightMoveTable[4] = {4, 5, 6, 0};

/* indices into a swing-direction move table (gSpDrapeSwingLeftMoveTable / gSpDrapeSwingRightMoveTable) */
enum
{
    SPDRAPE_MOVE_OPEN = 0,
    SPDRAPE_MOVE_HOLD = 1,
    SPDRAPE_MOVE_CLOSE = 2
};

#define SP_DRAPE_NEAR_RADIUS_SQ 4900.0f
#define SP_DRAPE_LEAVE_RADIUS 8100.0f
#define SP_DRAPE_REOPEN_PROGRESS 0.6f
#define SP_DRAPE_PI 3.1415927f
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
    return sizeof(SpdrapeState);
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

const f32 gSpDrapeZero[] = {0.0f};

void spdrape_update(GameObject* obj)
{
    SpdrapeState* state;
    GameObject* player;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    switch (obj->anim.currentMove)
    {
    case 0: /* idle: rustle, and swing open when the player is near */
        if ((s16)(state->sfxTimer -= framesThisStep) <= 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_propsp_6);
            state->sfxTimer = randomGetRange(0xb4, 0x12c);
        }
        if (getXZDistanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) < SP_DRAPE_NEAR_RADIUS_SQ)
        {
            if (player != 0)
            {
                if (state->planeD + (state->planeNormalX * player->anim.localPosX +
                                     state->planeNormalZ * player->anim.localPosZ) <
                    gSpDrapeZero[0])
                {
                    state->moveTable = (int)gSpDrapeSwingLeftMoveTable;
                }
                else
                {
                    state->moveTable = (int)gSpDrapeSwingRightMoveTable;
                }
            }
            ObjAnim_SetCurrentMove(obj, *(u8*)state->moveTable, gSpDrapeZero[0], 0);
            state->animSpeed = 0.0175f;
            Sfx_PlayFromObject(obj, SFXTRIG_cagesqk11);
            Camera_GetCurrent();
        }
        break;
    case 1: /* opening: hold while near, close once the player leaves */
    case 4:
        if (state->moveActive != 0)
        {
            if (getXZDistanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) > SP_DRAPE_LEAVE_RADIUS)
            {
                ObjAnim_SetCurrentMove(obj, ((u8*)state->moveTable)[SPDRAPE_MOVE_CLOSE],
                                       gSpDrapeZero[0], 0);
                Sfx_PlayFromObject(obj, SFXTRIG_cagesqk11);
                state->animSpeed = 0.0165f;
            }
            else
            {
                ObjAnim_SetCurrentMove(obj, ((u8*)state->moveTable)[SPDRAPE_MOVE_HOLD],
                                       gSpDrapeZero[0], 0);
                state->animSpeed = 0.0144f;
            }
        }
        break;
    case 2: /* held open: flutter, close when the player leaves */
    case 5:
        Sfx_PlayFromObject(obj, SFXTRIG_wickhit16);
        if (getXZDistanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) > SP_DRAPE_LEAVE_RADIUS)
        {
            ObjAnim_SetCurrentMove(obj, ((u8*)state->moveTable)[SPDRAPE_MOVE_CLOSE],
                                   gSpDrapeZero[0], 0);
            Sfx_StopObjectChannel(obj, 0x40);
            Sfx_PlayFromObject(obj, SFXTRIG_cagesqk11);
            state->animSpeed = 0.0165f;
        }
        break;
    case 3: /* closing: re-open if the player returns, else settle to idle */
    case 6:
        if ((obj->anim.currentMoveProgress > SP_DRAPE_REOPEN_PROGRESS) &&
            (getXZDistanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) < SP_DRAPE_NEAR_RADIUS_SQ))
        {
            if (player != 0)
            {
                if (state->planeD + (state->planeNormalX * player->anim.localPosX +
                                     state->planeNormalZ * player->anim.localPosZ) <
                    gSpDrapeZero[0])
                {
                    state->moveTable = (int)gSpDrapeSwingLeftMoveTable;
                }
                else
                {
                    state->moveTable = (int)gSpDrapeSwingRightMoveTable;
                }
            }
            ObjAnim_SetCurrentMove(obj, *(u8*)state->moveTable, gSpDrapeZero[0], 0);
            Sfx_PlayFromObject(obj, SFXTRIG_cagesqk11);
            state->animSpeed = 0.0175f;
        }
        else if (state->moveActive != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0, gSpDrapeZero[0], 0);
            state->animSpeed = 0.0072f;
            Camera_GetCurrent();
        }
        break;
    }
    state->moveActive =
        ObjAnim_AdvanceCurrentMove(obj, state->animSpeed, timeDelta, NULL);
}

void spdrape_init(GameObject* obj, SpdrapeObjectDef* def)
{

    SpdrapeState* state;
    GameObject* player;
    state = obj->extra;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
    obj->anim.rotX = (s16)((s32)def->facingByte << 8);
    if (def->motionScaleNum != 0)
    {
        obj->anim.rootMotionScale =
            (f32)(s32)def->motionScaleNum / 32767.0f * 10.0f;
    }
    state->animSpeed = 0.0072f;
    state->planeNormalX = mathSinf(SP_DRAPE_PI * (f32)(s32)obj->anim.rotX / 32768.0f);
    state->planeNormalZ = mathCosf(SP_DRAPE_PI * (f32)(s32)obj->anim.rotX / 32768.0f);
    state->planeD = -(state->planeNormalX * obj->anim.localPosX + state->planeNormalZ * obj->anim.localPosZ);
    state->sfxTimer = randomGetRange(0xb4, 0x12c);
    player = Obj_GetPlayerObject();
    if (player != NULL)
    {
        if (state->planeNormalX * player->anim.localPosX + state->planeNormalZ * player->anim.localPosZ +
                state->planeD <
            gSpDrapeZero[0])
        {
            state->moveTable = (int)gSpDrapeSwingLeftMoveTable;
        }
        else
        {
            state->moveTable = (int)gSpDrapeSwingRightMoveTable;
        }
    }
}

void spdrape_release(void)
{
}

void spdrape_initialise(void)
{
}
