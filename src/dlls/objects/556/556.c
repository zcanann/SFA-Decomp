/*
 * DLL slot 556 (0x22C): a placed object that rises from placement Y - 1228
 * to placement Y + 60, then alternates endpoints according to the player.
 * Each completed move pauses for 100 frames. Activation mode 1 bypasses
 * the initial gamebit gate, retaining the 230-unit proximity check.
 */
#include "dlls/objects/556.h"

#include "sys/objects.h"
#include "main/dll_000A_expgfx.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx_ids.h"
#include "main/frame_timing.h"
#include "main/vecmath_distance_api.h"
#include "main/object_render.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/render_lactions_api.h"

/* Dll22CState.mode rise/hold/fall cycle (see file-header comment). */
#define DLL22C_MODE_ARMED      0 /* wait for gameBit + player proximity, then rise -> HOLD_SETUP */
#define DLL22C_MODE_HOLD_SETUP 1 /* one-frame: arm the 100-frame pauseTimer -> HOLD */
#define DLL22C_MODE_HOLD       2 /* hold, then pick DESCEND or ASCEND by player Y */
#define DLL22C_MODE_DESCEND    3 /* fall to posY-1228.0f, then -> HOLD */
#define DLL22C_MODE_ASCEND     4 /* rise to posY+60.0f, then -> HOLD */


int dll_22C_SeqFn(void)
{
    return 0x0;
}
int dll_22C_getExtraSize_ret_16(void)
{
    return sizeof(Dll22CState);
}
int dll_22C_getObjectTypeId(void)
{
    return 0x0;
}

void dll_22C_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    getLActions((void*)obj, (void*)obj, 0, 0, 0, 0);
}

void dll_22C_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dll_22C_hitDetect_nop(void)
{
}

void dll_22C_update(GameObject* obj)
{
    GameObject* object = obj;
    ObjPlacement* placement = object->anim.placement;
    Dll22CState* state = object->extra;
    GameObject* player;
    int pauseTimer;
    f32 dist;
    f32 heightOffset;
    f32 posY;

    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    switch (state->mode)
    {
    case DLL22C_MODE_ARMED:
        if (mainGetBit(state->gameBit) != 0 && state->activationMode != 1 &&
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX) < 230.0f)
        {
            if (object->anim.localPosY < 60.0f + placement->posY)
            {
                if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_id_116);
                    state->sfxLatch = 1;
                }
                object->anim.localPosY += timeDelta;
                if (object->anim.localPosY >= 60.0f + placement->posY)
                {
                    object->anim.localPosY = 60.0f + placement->posY;
                    state->mode = DLL22C_MODE_HOLD_SETUP;
                    Sfx_StopObjectChannel(obj, 8);
                }
            }
        }
        else if (state->activationMode == 1)
        {
            if (Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX) < 230.0f)
            {
                posY = object->anim.localPosY;
                heightOffset = 60.0f;
                if (posY < heightOffset + placement->posY)
                {
                    object->anim.localPosY = posY + timeDelta;
                    if (object->anim.localPosY >= heightOffset + placement->posY)
                    {
                        object->anim.localPosY = heightOffset + placement->posY;
                        state->mode = DLL22C_MODE_HOLD_SETUP;
                    }
                }
            }
        }
        break;
    case DLL22C_MODE_HOLD_SETUP:
        state->mode = DLL22C_MODE_HOLD;
        state->pauseTimer = 0x64;
        break;
    case DLL22C_MODE_HOLD:
        pauseTimer = state->pauseTimer;
        if (pauseTimer != 0)
        {
            state->pauseTimer -= (s16)timeDelta;
            if (state->pauseTimer <= 0)
            {
                state->pauseTimer = 0;
            }
        }
        else
        {
            dist = Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
            if (dist < 50.0f)
            {
                if (object->anim.localPosY == 60.0f + placement->posY)
                {
                    state->mode = DLL22C_MODE_DESCEND;
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_liftloop);
                        state->sfxLatch = 1;
                    }
                }
                else if (object->anim.localPosY == placement->posY - 1228.0f)
                {
                    state->mode = DLL22C_MODE_ASCEND;
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_liftloop);
                        state->sfxLatch = 1;
                    }
                }
            }
            else
            {
                if (player->anim.localPosY < placement->posY)
                {
                    state->mode = DLL22C_MODE_DESCEND;
                    if (state->sfxLatch == 1)
                    {
                        state->sfxLatch = 0;
                    }
                }
                else if (player->anim.localPosY > placement->posY)
                {
                    state->mode = DLL22C_MODE_ASCEND;
                    if (state->sfxLatch == 1)
                    {
                        state->sfxLatch = 0;
                    }
                }
            }
        }
        break;
    case DLL22C_MODE_DESCEND:
        if (object->anim.localPosY > placement->posY - (heightOffset = 1228.0f))
        {
            object->anim.localPosY -= timeDelta;
            if (object->anim.localPosY <= placement->posY - heightOffset)
            {
                object->anim.localPosY = placement->posY - heightOffset;
                state->mode = DLL22C_MODE_HOLD;
                Sfx_StopObjectChannel(obj, 8);
                state->pauseTimer = 0x64;
            }
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
        }
        else
        {
            Sfx_StopObjectChannel(obj, 8);
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
            state->mode = DLL22C_MODE_HOLD;
            state->pauseTimer = 0x64;
        }
        break;
    case DLL22C_MODE_ASCEND:
        posY = object->anim.localPosY;
        heightOffset = 60.0f;
        if (posY < heightOffset + placement->posY)
        {
            object->anim.localPosY = posY + timeDelta;
            if (object->anim.localPosY >= heightOffset + placement->posY)
            {
                object->anim.localPosY = heightOffset + placement->posY;
                state->mode = DLL22C_MODE_HOLD;
                state->pauseTimer = 0x64;
                Sfx_StopObjectChannel(obj, 8);
            }
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
        }
        else
        {
            state->mode = DLL22C_MODE_HOLD;
            state->pauseTimer = 0x64;
            Sfx_StopObjectChannel(obj, 8);
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
        }
        break;
    }
}

void dll_22C_init(GameObject* obj, Dll22CPlacementPrefix* def)
{
    Dll22CState* state;
    Dll22CPlacementPrefix* placement = def;

    state = obj->extra;
    obj->animEventCallback = dll_22C_SeqFn;
    obj->anim.rotX = (s16)(placement->rotationHighByte << 8);
    state->mode = DLL22C_MODE_ARMED;
    state->gameBit = placement->gameBit;
    state->gameBit2 = placement->gameBit2;
    state->placementValue1A = placement->parameter1A;
    state->activationMode = placement->activationMode;
    obj->anim.localPosY -= 1228.0f;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void dll_22C_release_nop(void)
{
}

void dll_22C_initialise_nop(void)
{
}

ObjectDescriptor gDll22CObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_22C_initialise_nop,
    (ObjectDescriptorCallback)dll_22C_release_nop,
    0,
    (ObjectDescriptorCallback)dll_22C_init,
    (ObjectDescriptorCallback)dll_22C_update,
    (ObjectDescriptorCallback)dll_22C_hitDetect_nop,
    (ObjectDescriptorCallback)dll_22C_render,
    (ObjectDescriptorCallback)dll_22C_free,
    (ObjectDescriptorCallback)dll_22C_getObjectTypeId,
    dll_22C_getExtraSize_ret_16,
};
