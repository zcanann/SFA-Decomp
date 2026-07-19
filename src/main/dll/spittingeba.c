/*
 * spitting Eba baddie behaviour (retail OBJECTS.bin name "SpittingEba",
 * dispatch defNo 0x457): switches move sets by sky time-of-day;
 * spittingEbaSpawnPollen spawns its "Pollen" projectile setup object
 * (Obj_AllocObjectSetup/Obj_SetupObject, type 0x47b) aimed at the tracked
 * target with randomised speed.
 */
#include "main/audio/sfx_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/game_object.h"
#include "main/track_bbox_api.h"
#include "main/object.h"
#include "main/obj_placement.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/sky_interface.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/objfsa.h"
#include "main/frame_timing.h"
#include "main/dll/player_api.h"
#include "main/dll/fireflyLantern.h"
#include "main/dll/duster.h"
#include "main/dll/dll_00D8_pinponspike_arc_api.h"

#define DUSTER_CHILD_OBJ_POLLEN_SPIT 0x47b

extern const f32 gDusterDayStartSeconds;
extern const f32 gDusterDayEndSeconds;
extern const f32 lbl_803E2A78;
extern const f32 lbl_803E2A7C;
extern const f32 lbl_803E2A80;
extern const f32 lbl_803E2A84;
extern const f32 lbl_803E2A88;
extern const f32 lbl_803E2A8C;
extern const f32 lbl_803E2A90;

void spittingEbaSpawnPollen(u32 obj, int state)
{
    u32 loadLocked;
    int ref;
    u16* setup;
    f32 spd;
    f32 t;
    f32 dx;
    f32 dz;
    f32 a[3];
    f32 b[3];
    float velXZ;
    float cosVal;
    float velY;
    float cosPitch;

    loadLocked = Obj_IsLoadingLocked();
    if ((loadLocked & 0xff) != 0)
    {
        a[0] = ((GameObject*)obj)->anim.localPosX;
        a[1] = 15.0f + ((GameObject*)obj)->anim.localPosY;
        a[2] = ((GameObject*)obj)->anim.localPosZ;
        ref = *(int*)&((BaddieState*)state)->trackedObj;
        b[0] = ((GameObject*)ref)->anim.localPosX;
        b[1] = 30.0f + ((GameObject*)ref)->anim.localPosY;
        b[2] = ((GameObject*)ref)->anim.localPosZ;
        spd = (3.25f) * ((0.02f) * (f32)(int)randomGetRange(-10, 10) + (1.0f));
        ref = fn_80169EF4(a, b, spd, 1, (0.045f));
        fn_80293018(ref, &cosVal, &velXZ);
        velXZ = velXZ * spd;
        cosVal = cosVal * spd;
        dx = b[0] - ((GameObject*)obj)->anim.localPosX;
        dz = b[2] - ((GameObject*)obj)->anim.localPosZ;
        if (0.0f != dz)
        {
            ref = getAngle(dx, dz);
            fn_80293018(ref, &cosPitch, &velY);
            t = velXZ;
            velY = velY * t;
            velXZ = t * cosPitch;
        }
        else
        {
            velY = 0.0f;
        }
        setup = (u16*)Obj_AllocObjectSetup(0x24, DUSTER_CHILD_OBJ_POLLEN_SPIT);
        ((ObjPlacement*)setup)->posX = a[0];
        ((ObjPlacement*)setup)->posY = a[1];
        ((ObjPlacement*)setup)->posZ = a[2];
        ((ObjPlacement*)setup)->color[0] = 1;
        ((ObjPlacement*)setup)->color[1] = 1;
        ((ObjPlacement*)setup)->color[2] = 0xff;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        ref = (int)Obj_SetupObject((ObjPlacement*)setup, 5, -1, -1, 0);
        if ((void*)ref != NULL)
        {
            ((GameObject*)ref)->anim.velocityX = velXZ;
            ((GameObject*)ref)->anim.velocityY = cosVal;
            ((GameObject*)ref)->anim.velocityZ = velY;
            *(u32*)&((GameObject*)ref)->ownerObj = obj;
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_mika_cackle);
        }
    }
    return;
}

void spittingEbaUpdateTimeOfDay(int obj, int state)
{
    u8 isDaytime;
    float timeInfo[4];

    (*gSkyInterface)->getTimeOfDay(timeInfo);
    if ((timeInfo[0] >= gDusterDayStartSeconds) && (timeInfo[0] <= gDusterDayEndSeconds))
    {
        isDaytime = 1;
    }
    else
    {
        isDaytime = 0;
    }
    if ((isDaytime != 0) && (((BaddieState*)state)->userData1 == 0))
    {
        ((BaddieState*)state)->userData1 = 1;
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
        Baddie_SetMove(obj, state, 1, lbl_803E2A78, 0, 0);
    }
    else if ((isDaytime == 0) && (((BaddieState*)state)->userData1 == 2))
    {
        ((BaddieState*)state)->userData1 = 1;
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
        Baddie_SetMove(obj, state, 3, lbl_803E2A78, 0, 0);
    }
    return;
}

void spittingEbaUpdateWhileFrozen(u32 obj, int state, u32 unused1, int eventKind, u32 unused2, int damage, void* wpad0, int wpad1)
{
    if (eventKind == 0x10)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
    }
    else if (eventKind == 0x11)
    {
        if ((((BaddieState*)state)->userData1 == 2) && (((GameObject*)obj)->anim.currentMove != 5))
        {
            Baddie_SetMove(obj, state, 5, lbl_803E2A7C, 0, 0);
        }
    }
    else if ((((GameObject*)obj)->anim.currentMove == 5) || (((GameObject*)obj)->anim.currentMove == 4))
    {
        if (damage > (int)(u32)((BaddieState*)state)->hitCounter)
        {
            ((BaddieState*)state)->hitCounter = 0;
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_strike);
            Sfx_PlayFromObject(obj, SFXTRIG_stftest);
        }
        else
        {
            ((BaddieState*)state)->hitCounter = ((BaddieState*)state)->hitCounter - damage;
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_call);
            Sfx_PlayFromObject(obj, SFXTRIG_stftest);
        }
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x10;
        Sfx_PlayFromObject(obj, SFXTRIG_mv_ladderslide16_250);
    }
    return;
}

void spittingEbaUpdateIdle(GameObject* obj, int state)
{
    ((DusterState*)state)->phaseTimer = 0.0f;
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        if (((BaddieState*)state)->userData1 == 1)
        {
            if ((obj)->anim.currentMove == 1)
            {
                ((BaddieState*)state)->userData1 = 2;
                *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 & ~0x10000LL;
            }
            else if ((obj)->anim.currentMove == 3)
            {
                ((BaddieState*)state)->userData1 = 0;
                *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
                Baddie_SetMove(obj, state, 0, (1.0f), 0, 0);
            }
        }
        else if ((((BaddieState*)state)->userData1 == 2) && ((obj)->anim.currentMove != 2))
        {
            Baddie_SetMove(obj, state, 2, (1.0f), 0, 0);
        }
    }
    spittingEbaUpdateTimeOfDay((int)obj, state);
    return;
}

void spittingEbaUpdateEngaged(u32 obj, int state)
{
    u8 timerExpired;

    timerExpired = 0;
    ((DusterState*)state)->phaseTimer = ((DusterState*)state)->phaseTimer - timeDelta;
    if (((DusterState*)state)->phaseTimer <= 0.0f)
    {
        timerExpired = 1;
        ((DusterState*)state)->phaseTimer = 0.0f;
    }
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        if (((GameObject*)obj)->anim.currentMove == 4)
        {
            spittingEbaSpawnPollen(obj, state);
            ((DusterState*)state)->phaseTimer = lbl_803E2A80;
            Baddie_SetMove(obj, state, 5, (1.0f), 0, 0);
        }
        else if ((((GameObject*)obj)->anim.currentMove == 5) && (timerExpired))
        {
            Baddie_SetMove(obj, state, 6, (1.0f), 0, 0);
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_death);
        }
        else if (((GameObject*)obj)->anim.currentMove == 6)
        {
            Baddie_SetMove(obj, state, 2, (1.0f), 0, 0);
            ((DusterState*)state)->phaseTimer = lbl_803E2A80;
        }
        else if ((((GameObject*)obj)->anim.currentMove == 2) && (timerExpired) &&
                 ((((BaddieState*)state)->controlFlags & 0x4000000) != 0))
        {
            Baddie_SetMove(obj, state, 4, (1.0f), 0, 0);
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_hit);
        }
    }
    spittingEbaUpdateTimeOfDay(obj, state);
    return;
}

void spittingEbaInit(u32 unused, int state)
{
    float fa;
    float fb;

    ((BaddieState*)state)->speedScale = lbl_803E2A84;
    *(u32*)&((BaddieState*)state)->unk2E4 = 1;
    ((BaddieState*)state)->unk308 = (0.02f);
    ((BaddieState*)state)->animDeltaScale = lbl_803E2A88;
    ((BaddieState*)state)->unk304 = lbl_803E2A8C;
    ((BaddieState*)state)->unk320 = 0;
    fb = lbl_803E2A90;
    *(float*)&((BaddieState*)state)->eventFlags = lbl_803E2A90;
    ((BaddieState*)state)->unk321 = 7;
    fa = (1.0f);
    ((BaddieState*)state)->unk318 = (1.0f);
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fb;
    ((BaddieState*)state)->userData1 = 0;
    ((DusterState*)state)->phaseTimer = 0.0f;
    ((BaddieState*)state)->pathStep = fa;
    return;
}
