/*
 * weevil - the weevil baddie's init, freeze-event and per-frame handlers
 * (retail OBJECTS.bin name "Weevil" for dispatch defNo 0x369):
 *   - weevil_updateWhileFrozen  freeze-event handler: gates the reaction
 *     flags on the current move and re-arms the recover timer.
 *   - weevil_updateIdle  per-frame update: walks the rom curve path, runs the
 *     approach/recover timers and plays the idle grunt sfx.
 *   - weevil_updateEngaged  move update: picks the active move from the tracked
 *     target and runs the approach/retreat timer.
 *   - weevil_init  one-shot move setup: seeds speed/path-step and the
 *     BaddieState scratch floats.
 * (callers: dll_00C9_enemy, dll_00C4_tricky.)
 */
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/weevil.h"
#include "main/dll/baddie_frozen.h"

#define FALL_LADDERS_HIT_VOLUME_SLOT 0x18

extern int lbl_803DBCC8[2];
extern f64 lbl_803E2938;
extern f32 lbl_803E2940;
extern f32 lbl_803E2944;
extern f32 lbl_803E2948;
extern f32 lbl_803E294C;
extern f32 lbl_803E2950;
extern f32 lbl_803E2954;
extern f32 lbl_803E2958;

/*
 * WeevilState - file-local overlay naming the per-family scratch that
 * baddie_state.h leaves raw for the weevil creatures: four f32 per-frame
 * countdown timers at 0x324/0x328/0x32C/0x330 (they overlap the s16
 * stateTimer/cameraYaw fields the whirlpool family names, so they cannot
 * live in BaddieState itself).
 */
typedef struct WeevilState
{
    u8 pad00[0x324];
    f32 approachTimer; /* 0x324 */
    f32 retreatTimer;  /* 0x328 */
    f32 recoverTimer;  /* 0x32C */
    f32 gruntTimer;    /* 0x330 */
} WeevilState;

STATIC_ASSERT(offsetof(WeevilState, approachTimer) == 0x324);
STATIC_ASSERT(offsetof(WeevilState, retreatTimer) == 0x328);
STATIC_ASSERT(offsetof(WeevilState, recoverTimer) == 0x32C);
STATIC_ASSERT(offsetof(WeevilState, gruntTimer) == 0x330);

void weevil_updateWhileFrozen(GameObject* obj, u8* state, int attacker, int msgFlag, int wpad0, int wpad1, Vec* wpad2,
                              int wpad3)
{
    u8 cond = 0;
    if ((obj)->anim.currentMove == 5 || (obj)->anim.currentMove == 4 ||
        ((obj)->anim.currentMove == 6 && (double)(obj)->anim.currentMoveProgress < lbl_803E2938))
    {
        if (msgFlag != 0xe)
        {
            cond = 1;
        }
    }

{
    u32 condV = cond;
    if (msgFlag == 0x10)
    {
        if (condV != 0)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
        }
    }
    else if (condV != 0)
    {
        if (((BaddieState*)state)->userData2 == 0)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x8;
            *(s16*)&((BaddieState*)state)->hitCounter = 0;
            Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_25f);
        }
    }
    else if (msgFlag == 0x11)
    {
        ((WeevilState*)state)->recoverTimer = lbl_803E2940;
        ((WeevilState*)state)->approachTimer = lbl_803E2944;
        fn_8014D08C(obj, (int)state, 4, lbl_803E2948, 0, 3);
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
        ((BaddieState*)state)->userData2 = 0x3c;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x10;
    }
}
}

void weevil_updateIdle(GameObject* obj, int state)
{
    RomCurveWalker* curve;
    u32 rnd;
    u8 ctr;

    curve = *(RomCurveWalker**)state;
    ((BaddieState*)state)->userData1 = 0;
    ((WeevilState*)state)->retreatTimer = lbl_803E294C;
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if (Curve_AdvanceAlongPath(&curve->curve, ((BaddieState*)state)->pathStep) != 0 ||
            curve->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(curve) != 0)
            {
                if ((*gRomCurveInterface)
                        ->initCurve(*(RomCurveWalker**)state, (void*)obj, lbl_803E2950, lbl_803DBCC8, -1) != 0)
                {
                    ((BaddieState*)state)->controlFlags =
                        ((BaddieState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }
        if (lbl_803E294C == ((WeevilState*)state)->recoverTimer)
        {
            if ((obj)->anim.currentMove == 0)
            {
                baddieTurnTowardPoint(obj, state, curve->posX, curve->posZ, 0x3c, 0);
            }
            if (((WeevilState*)state)->approachTimer > lbl_803E294C)
            {
                f32 zero = lbl_803E294C;
                ((WeevilState*)state)->approachTimer = ((WeevilState*)state)->approachTimer - timeDelta;
                if (((WeevilState*)state)->approachTimer <= zero)
                {
                    *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 & ~(u64)0x10000;
                    ((WeevilState*)state)->approachTimer = zero;
                }
            }
        }
    }
    if (((WeevilState*)state)->recoverTimer > lbl_803E294C)
    {
        f32 zero = lbl_803E294C;
        ((WeevilState*)state)->recoverTimer = ((WeevilState*)state)->recoverTimer - timeDelta;
        if (((WeevilState*)state)->recoverTimer <= zero)
        {
            fn_8014D08C(obj, state, 6, lbl_803E2948, 0, 3);
            ((WeevilState*)state)->recoverTimer = lbl_803E294C;
        }
        else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            fn_8014D08C(obj, state, 5, lbl_803E2954, 0, 3);
        }
    }
    else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        fn_8014D08C(obj, state, 0, lbl_803E2958, 0, 3);
    }
    (obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
    (obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
    ((WeevilState*)state)->gruntTimer = ((WeevilState*)state)->gruntTimer - timeDelta;
    if (((WeevilState*)state)->gruntTimer <= lbl_803E294C)
    {
        rnd = randomGetRange(0x3c, 0x78);
        ((WeevilState*)state)->gruntTimer = (f32)(s32)rnd;
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_25e);
    }
    ctr = ((BaddieState*)state)->userData2;
    if (ctr != 0)
    {
        ((BaddieState*)state)->userData2--;
    }
}


void weevil_updateEngaged(int obj, int state)
{
    u8 done;

    ((WeevilState*)state)->recoverTimer = lbl_803E294C;
    done = 0;
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, FALL_LADDERS_HIT_VOLUME_SLOT, 1, -1);
    if (*(void**)(state + 0x340) != 0)
    {
        done = 1;
        ((WeevilState*)state)->approachTimer = 360.0f;
        ((WeevilState*)state)->recoverTimer = lbl_803E294C;
        if (((GameObject*)obj)->anim.currentMove != 0)
        {
            fn_8014D08C((GameObject*)obj, state, 2, lbl_803E2958, 0, 3);
        }
    }
    if (((GameObject*)obj)->anim.currentMove != 3)
    {
        baddieTurnTowardPoint((GameObject*)obj, state, ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                    ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ, 0x3c, 0);
    }
    else
    {
        ((WeevilState*)state)->retreatTimer -= timeDelta;
        if (((WeevilState*)state)->retreatTimer <= lbl_803E294C)
        {
            done = 1;
            ((WeevilState*)state)->recoverTimer = lbl_803E2940;
            ((WeevilState*)state)->approachTimer = lbl_803E2944;
            fn_8014D08C((GameObject*)obj, state, 4, lbl_803E2948, 0, 3);
        }
    }
    if (done != 0)
    {
        *(u32*)&((BaddieState*)state)->unk2E4 |= (u64)0x10000;
    }
    else if (((BaddieState*)state)->userData1 == 0)
    {
        ((BaddieState*)state)->userData1 = 1;
        fn_8014D08C((GameObject*)obj, state, 1, 0.35f, 0, 3);
    }
    else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0 &&
             (fn_8014D08C((GameObject*)obj, state, 3, 0.375f, 0, 3),
              lbl_803E294C == ((WeevilState*)state)->retreatTimer))
    {
        ((WeevilState*)state)->retreatTimer = 50.0f;
        baddieTurnTowardPoint((GameObject*)obj, state, ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                    ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ, 1, 0);
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_25d);
    }
    ((GameObject*)obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
    ((GameObject*)obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
    if (((BaddieState*)state)->userData2 != 0)
    {
        ((BaddieState*)state)->userData2 -= 1;
    }
}

void weevil_init(int unused, u8* state)
{
    f32 fz;
    f32 fc;
    ((BaddieState*)state)->speedScale = 40.0f;
    ((BaddieState*)state)->unk2E4 = 173;
    ((BaddieState*)state)->unk308 = 0.02f;
    ((BaddieState*)state)->animDeltaScale = lbl_803E2954;
    ((BaddieState*)state)->unk304 = 0.97f;
    ((BaddieState*)state)->unk320 = 0;
    fz = 1.5f;
    *(f32*)&((BaddieState*)state)->eventFlags = fz;
    ((BaddieState*)state)->unk321 = 7;
    ((BaddieState*)state)->unk318 = 4.0f;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fz;
    fc = lbl_803E294C;
    ((WeevilState*)state)->approachTimer = fc;
    ((WeevilState*)state)->retreatTimer = fc;
    ((WeevilState*)state)->recoverTimer = fc;
    ((BaddieState*)state)->userData1 = 0;
    ((BaddieState*)state)->userData2 = 0;
    ((WeevilState*)state)->gruntTimer = 60.0f;
    ((BaddieState*)state)->pathStep = lbl_803E2958;
}
