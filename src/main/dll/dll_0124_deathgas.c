/* DLL 0x0124 - death-gas objects [8018BC48-8018BC50) */
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/gamebits.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "main/objhits.h"
#include "main/frame_timing.h"
#include "main/pi_dolphin_api.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/dll/dll_0124_deathgas.h"

#define DEATHGAS_AIRMETER_BGTEXTURE 0x603
#define DEATHGAS_NOFOG_OBJECT_ID 2103

int DeathGas_getExtraSize(void) { return sizeof(DeathGasState); }

void DeathGas_free(GameObject* obj)
{
    DeathGasState* state = obj->extra;
    if (state->fogOn)
    {
        if (!state->noFog)
        {
            disableHeavyFog();
        }
    }
    if (state->draining)
    {
        (*gGameUIInterface)->airMeterSetShutdown();
    }
}

void DeathGas_update(GameObject* obj)
{

    DeathGasSetup* setup = (DeathGasSetup*)obj->anim.placementData;
    DeathGasState* state = obj->extra;
    GameObject* player;
    u8 active;
    int bit;

    bit = setup->activeGameBit;
    if (bit == -1)
    {
        active = 1;
    }
    else
    {
        active = mainGetBit(bit);
    }

    if (active == 0)
    {
        if (state->fogOn)
        {
            if (!state->noFog)
            {
                disableHeavyFog();
            }
            state->fogOn = 0;
        }
        if (state->draining)
        {
            (*gGameUIInterface)->airMeterSetShutdown();
            state->draining = 0;
        }
        return;
    }

    if (!state->fogOn)
    {
        if (!state->noFog)
        {
            enableHeavyFog(35.0f + obj->anim.worldPosY,
                           obj->anim.worldPosY - 5.0f,
                           1000.0f, 0.1f, 0.0005f, 0);
        }
        state->fogOn = 1;
    }

    player = Obj_GetPlayerObject();
    if (!playerIsDisguised(player)
        && player->anim.worldPosY <= 30.0f + obj->anim.worldPosY
        && Vec_distance(&player->anim.worldPosX, &obj->anim.worldPosX) <=
               state->effectRadius)
    {
        if (!state->draining)
        {
            (*gGameUIInterface)->initAirMeter(6000, DEATHGAS_AIRMETER_BGTEXTURE);
            state->airRemaining = 6000.0f;
            state->draining = 1;
        }
        state->airRemaining -= (timeDelta * setup->drainRate) / 10.0f;
        if (state->airRemaining <= 0.0f)
        {
            f32 floor = 0.0f;
            state->airRemaining = 0.0f;
            state->damageTimer -= timeDelta;
            if (state->damageTimer < floor)
            {
                state->damageTimer += 120.0f;
                ObjHits_RecordObjectHit(player, obj, 0x16, 1, 0);
            }
        }
    }
    else if (state->draining)
    {
        state->airRemaining += (timeDelta * setup->fillRate) / 10.0f;
        if (state->airRemaining > 6000.0f)
        {
            (*gGameUIInterface)->airMeterShutdown();
            state->draining = 0;
        }
    }

    if (state->draining)
    {
        (*gGameUIInterface)->runAirMeter((int)state->airRemaining);
    }
}

void DeathGas_init(GameObject* obj)
{
    register DeathGasState* state = obj->extra;
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HIDDEN);
    state->effectRadius = 10000.0f;
    if (obj->anim.seqId != DEATHGAS_NOFOG_OBJECT_ID) return;
    state->noFog = 1;
    state->effectRadius = obj->anim.cullDistance2;
}

ObjectDescriptor gDeathGasObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)DeathGas_init,
    (ObjectDescriptorCallback)DeathGas_update,
    0,
    0,
    (ObjectDescriptorCallback)DeathGas_free,
    0,
    DeathGas_getExtraSize,
};
