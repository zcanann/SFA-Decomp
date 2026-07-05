/*
 * DragonRock Palace force-field object (DLL 0x231; "DFP_ForceAw"),
 * implemented on the shared TrickyCurve state machine and sfxplayer: a
 * curve-driven hazard/barrier with per-state update handlers.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/trickycurve_state.h"
#include "main/mapEvent.h"
#include "main/dll/sfxplayer.h"
#include "main/dll/infopoint.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"

#define DFPFORCEAW_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DFPFORCEAW_MSG_PLAYER_BURST 0x60004 /* knock the player back with a burst hit */

typedef struct TrickyCurveObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 rangeYRaw; /* 0x18 << 2 -> state.rangeY */
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    s16 rangeZ;         /* 0x1C -> state.rangeZ */
    s16 triggerGameBit; /* 0x1E -> state.triggerGameBit */
    s16 gateGameBit;    /* 0x20 -> state.gateGameBit */
    u8 pad22[0x28 - 0x22];
} TrickyCurveObjectDef;

extern int Obj_GetPlayerObject(void);
extern u32 ObjMsg_SendToObject();
extern f32 lbl_803E70E0;

typedef struct TrickyCurveBurstFxParams
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 pad;
    f32 scale;
    f32 xOffset;
    f32 yOffset;
    f32 zOffset;
} TrickyCurveBurstFxParams;

extern void fn_80206C18(int* obj);
extern void fn_80206968(int* obj);

void TrickyCurve_updateBurstTrigger(int obj)
{
    u8* state;
    int player;
    f32 dx;
    f32 dz;
    f32 dy;
    u8 insideCount;
    u8 xSide;
    u8 ySide;
    u8 zSide;
    TrickyCurveBurstFxParams fxParams;
    int burstParticles;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    insideCount = 0;
    xSide = 0;
    ySide = 0;
    zSide = 0;
    dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
    dy = ((GameObject*)player)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    dz = ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;

    if ((((TrickyCurveObjState*)state)->gateGameBit != -1) && (GameBit_Get(((TrickyCurveObjState*)state)->gateGameBit) != 0))
    {
        return;
    }

    if (GameBit_Get(((TrickyCurveObjState*)state)->triggerGameBit) != 0)
    {
        GameBit_Set(((TrickyCurveObjState*)state)->triggerGameBit, 0);
    }

    if (dx <= 0.0f)
    {
        if (dx > -(f32) * (s16*)state)
        {
            insideCount = 1;
            xSide = 1;
        }
    }
    if (dx > 0.0f)
    {
        if (dx < (f32) * (s16*)state)
        {
            insideCount++;
            xSide--;
        }
    }
    if (dz <= 0.0f)
    {
        if (dz > -(f32)((TrickyCurveObjState*)state)->rangeZ)
        {
            insideCount++;
            zSide = 1;
        }
    }
    if (dz > 0.0f)
    {
        if (dz < (f32)((TrickyCurveObjState*)state)->rangeZ)
        {
            insideCount++;
            zSide--;
        }
    }
    if (dy <= 0.0f)
    {
        if (dy > -(f32)((TrickyCurveObjState*)state)->rangeY)
        {
            insideCount++;
            ySide = 1;
        }
    }
    if (dy > 0.0f)
    {
        if (dy < (f32)((TrickyCurveObjState*)state)->rangeY)
        {
            insideCount++;
            ySide--;
        }
    }

    if (insideCount == 3)
    {
        fxParams.xOffset = dx;
        fxParams.yOffset = dy;
        fxParams.zOffset = dz;
        fxParams.scale = lbl_803E70E0;
        fxParams.rotZ = 0;
        fxParams.rotY = 0;
        fxParams.rotX = 0;
        if (xSide != state[0x10])
        {
            fxParams.rotX = 0x3fff;
        }

        if (GameBit_Get(0x1d9) != 0)
        {
            GameBit_Set(0x468, 1);
            ObjMsg_SendToObject(player, DFPFORCEAW_MSG_PLAYER_BURST, obj, 0);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x5ed, &fxParams, 2, -1, NULL);
            burstParticles = 9;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x5fd, &fxParams, 2, -1, NULL);
            }
            while (burstParticles-- != 0);
        }
        else
        {
            ObjMsg_SendToObject(player, DFPFORCEAW_MSG_PLAYER_BURST, obj, 1);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x5ed, &fxParams, 2, -1, NULL);
            burstParticles = 9;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x5fd, &fxParams, 2, -1, NULL);
            }
            while (burstParticles-- != 0);
        }
        GameBit_Set(((TrickyCurveObjState*)state)->triggerGameBit, 1);
        Sfx_PlayFromObject(obj, SFXfoot_water_walk_3);
    }

    state[0x10] = xSide;
    state[0x11] = ySide;
    state[0x12] = zSide;
}

#pragma scheduling off
#pragma peephole off
void TrickyCurve_render(void)
{
}

void TrickyCurve_hitDetect(void)
{
}

void TrickyCurve_release(void)
{
}

void TrickyCurve_initialise(void)
{
}


int TrickyCurve_getExtraSize(void) { return 0x14; }
int TrickyCurve_getObjectTypeId(void) { return 0x0; }

void TrickyCurve_update(int* obj)
{
    u8* inner = ((GameObject*)obj)->extra;
    u32 state = inner[0xe];
    if (state == 0)
    {
        TrickyCurve_updateBurstTrigger((int)obj);
    }
    else if (state == 1)
    {
        TrickyCurve_updateCooldownTrigger((int)obj);
    }
    else if (state == 2)
    {
        fn_80206C18(obj);
    }
    else if (state == 3)
    {
        fn_80206968(obj);
    }
}

void TrickyCurve_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void TrickyCurve_init(int* obj, u8* def)
{
    u8* state = ((GameObject*)obj)->extra;
    state[0xc] = def[0x19];
    ((TrickyCurveObjState*)state)->rangeY = (s16)((s32)((TrickyCurveObjectDef*)def)->rangeYRaw << 2);
    *(s16*)state = ((TrickyCurveObjectDef*)def)->unk1A;
    ((TrickyCurveObjState*)state)->rangeZ = ((TrickyCurveObjectDef*)def)->rangeZ;
    state[0xe] = def[0x19];
    state[0x10] = 0;
    state[0x11] = 0;
    state[0x12] = 0;
    ((TrickyCurveObjState*)state)->gateGameBit = ((TrickyCurveObjectDef*)def)->gateGameBit;
    ((TrickyCurveObjState*)state)->triggerGameBit = ((TrickyCurveObjectDef*)def)->triggerGameBit;
    ((TrickyCurveObjState*)state)->unk6 = 0;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DFPFORCEAW_OBJFLAG_HITDETECT_DISABLED);
}
