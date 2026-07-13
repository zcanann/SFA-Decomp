/* DLL 0x0124 — death-gas objects [8018BC48-8018BC50) */
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/render.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "main/objhits.h"
#include "main/frame_timing.h"
#include "main/pi_dolphin_api.h"

#define DEATHGAS_OBJFLAG_HIDDEN 0x4000
#define DEATHGAS_AIRMETER_BGTEXTURE 0x603
extern int playerIsDisguised(void);
int DeathGas_getExtraSize(void) { return 0x10; }

typedef struct
{
    f32 timer; // 0x0
    f32 hitTimer; // 0x4
    f32 radius; // 0x8
    u8 fogOn : 1; // 0xc bit 7
    u8 draining : 1; // bit 6
    u8 noFog : 1; // bit 5
} DeathGasState;

typedef struct
{
    u8 pad[0x18];
    u8 drainRate; // 0x18
    u8 fillRate; // 0x19
    s16 activeBit; // 0x1a
} DeathGasSetup;

void DeathGas_free(int* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    u8 flags = state[12];
    if (((u32)flags >> 7) & 1u)
    {
        if (!(((u32)flags >> 5) & 1u))
        {
            disableHeavyFog();
        }
    }
    if (((u32)state[12] >> 6) & 1u)
    {
        (*gGameUIInterface)->airMeterSetShutdown();
    }
}

void DeathGas_update(int* obj)
{

    DeathGasSetup* setup = *(DeathGasSetup**)&((GameObject*)obj)->anim.placementData;
    DeathGasState* state = ((GameObject*)obj)->extra;
    GameObject* player;
    u8 active;
    int bit;

    bit = setup->activeBit;
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
            enableHeavyFog(35.0f + ((GameObject*)obj)->anim.worldPosY,
                           ((GameObject*)obj)->anim.worldPosY - 5.0f,
                           1000.0f, 0.1f, 0.0005f, 0);
        }
        state->fogOn = 1;
    }

    player = Obj_GetPlayerObject();
    if (!playerIsDisguised()
        && player->anim.worldPosY <= 30.0f + ((GameObject*)obj)->anim.worldPosY
        && Vec_distance(&player->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX) <=
               state->radius)
    {
        if (!state->draining)
        {
            (*gGameUIInterface)->initAirMeter(6000, DEATHGAS_AIRMETER_BGTEXTURE);
            state->timer = 6000.0f;
            state->draining = 1;
        }
        state->timer -= (timeDelta * setup->drainRate) / 10.0f;
        if (state->timer <= 0.0f)
        {
            f32 floor = 0.0f;
            state->timer = 0.0f;
            state->hitTimer -= timeDelta;
            if (state->hitTimer < floor)
            {
                state->hitTimer += 120.0f;
                ObjHits_RecordObjectHit((int)player, (int)obj, 0x16, 1, 0);
            }
        }
    }
    else if (state->draining)
    {
        state->timer += (timeDelta * setup->fillRate) / 10.0f;
        if (state->timer > 6000.0f)
        {
            (*gGameUIInterface)->airMeterShutdown();
            state->draining = 0;
        }
    }

    if (state->draining)
    {
        (*gGameUIInterface)->runAirMeter((int)state->timer);
    }
}

void DeathGas_init(int* obj)
{
    register DeathGasState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DEATHGAS_OBJFLAG_HIDDEN);
    state->radius = 10000.0f;
    if (((GameObject*)obj)->anim.seqId != 2103) return;
    state->noFog = 1;
    state->radius = *(f32*)((char*)obj + 64);
}
