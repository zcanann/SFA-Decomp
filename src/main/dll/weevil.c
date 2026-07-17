/*
 * weevil - the weevil baddie's freeze-event + per-frame handlers, plus the
 * curve-following move update/setup pair that the same object first defined
 * and the sibling baddie DLLs reuse:
 *   - weevil_updateWhileFrozen  freeze-event handler: gates the reaction
 *     flags on the current move and re-arms the recover timer.
 *   - fn_80153E0C  per-frame update: walks the rom curve path, runs the
 *     approach/recover timers and plays the idle grunt sfx.
 *   - fn_801540A0  move update: picks the active move from the tracked
 *     target and runs the approach/retreat timer.
 *   - fn_801542AC  one-shot move setup: seeds speed/path-step and the
 *     BaddieState scratch floats.
 * (callers: dll_00C9_enemy, dll_00C4_tricky, fireflylantern.)
 */
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"

#define FALL_LADDERS_HIT_VOLUME_SLOT 0x18

extern void fn_8014CF7C(int obj, int state, f32 x, f32 z, int a, int b);
extern int lbl_803DBCC8[2];
extern f64 lbl_803E2938;
extern f32 lbl_803E2940;
extern f32 lbl_803E2944;
extern f32 lbl_803E2948;
extern f32 lbl_803E294C;
extern f32 lbl_803E2950;
extern f32 lbl_803E2954;
extern f32 lbl_803E2958;

void weevil_updateWhileFrozen(GameObject* obj, int state, int attacker, int msgFlag)
{
    u8 cond = 0;
    int kind = (obj)->anim.currentMove;
    if (kind == 5)
    {
    }
    else if (kind == 4)
    {
    }
    else if (kind == 6)
    {
        if ((double)(obj)->anim.currentMoveProgress < lbl_803E2938)
        {
        }
        else
        {
            goto checkedKind;
        }
    }
    else
    {
        goto checkedKind;
    }

    if (msgFlag != 0xe)
    {
        cond = 1;
    }

checkedKind:
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
        if (((BaddieState*)state)->inWhirlpoolGroup == 0)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x8;
            *(s16*)&((BaddieState*)state)->hitCounter = 0;
            Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_25f);
        }
    }
    else if (msgFlag == 0x11)
    {
        *(f32*)(state + 0x32c) = lbl_803E2940;
        *(f32*)(state + 0x324) = lbl_803E2944;
        Baddie_SetMove(obj, state, 4, lbl_803E2948, 0, 3);
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
        ((BaddieState*)state)->inWhirlpoolGroup = 0x3c;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x10;
    }
}
}

void fn_80153E0C(GameObject* obj, int state)
{
    RomCurveWalker* curve;
    u32 rnd;
    u8 ctr;

    curve = *(RomCurveWalker**)state;
    ((BaddieState*)state)->seqEntryIndex = 0;
    *(f32*)(state + 0x328) = lbl_803E294C;
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if (Curve_AdvanceAlongPath(curve, ((BaddieState*)state)->pathStep) != 0 || curve->atSegmentEnd != 0)
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
        if (lbl_803E294C == *(f32*)(state + 0x32c))
        {
            if ((obj)->anim.currentMove == 0)
            {
                fn_8014CF7C((int)obj, state, curve->posX, curve->posZ, 0x3c, 0);
            }
            if (*(f32*)(state + 0x324) > lbl_803E294C)
            {
                f32 zero = lbl_803E294C;
                *(f32*)(state + 0x324) = *(f32*)(state + 0x324) - timeDelta;
                if (*(f32*)(state + 0x324) <= zero)
                {
                    *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 & ~(u64)0x10000;
                    *(f32*)(state + 0x324) = zero;
                }
            }
        }
    }
    if (*(f32*)(state + 0x32c) > lbl_803E294C)
    {
        f32 zero = lbl_803E294C;
        *(f32*)(state + 0x32c) = *(f32*)(state + 0x32c) - timeDelta;
        if (*(f32*)(state + 0x32c) <= zero)
        {
            Baddie_SetMove(obj, state, 6, lbl_803E2948, 0, 3);
            *(f32*)(state + 0x32c) = lbl_803E294C;
        }
        else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            Baddie_SetMove(obj, state, 5, lbl_803E2954, 0, 3);
        }
    }
    else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        Baddie_SetMove(obj, state, 0, lbl_803E2958, 0, 3);
    }
    (obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
    (obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
    *(f32*)(state + 0x330) = *(f32*)(state + 0x330) - timeDelta;
    if (*(f32*)(state + 0x330) <= lbl_803E294C)
    {
        rnd = randomGetRange(0x3c, 0x78);
        *(f32*)(state + 0x330) = (f32)(s32)rnd;
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_25e);
    }
    ctr = ((BaddieState*)state)->inWhirlpoolGroup;
    if (ctr != 0)
    {
        ((BaddieState*)state)->inWhirlpoolGroup--;
    }
}

__declspec(section ".sdata2") f32 lbl_803E2968 = 3.6e+02f;
__declspec(section ".sdata2") f32 lbl_803E296C = 0.35f;
__declspec(section ".sdata2") f32 lbl_803E2970 = 0.375f;
__declspec(section ".sdata2") f32 lbl_803E2974 = 5e+01f;
__declspec(section ".sdata2") f32 lbl_803E2978 = 4e+01f;
__declspec(section ".sdata2") f32 lbl_803E297C = 0.02f;
__declspec(section ".sdata2") f32 lbl_803E2980 = 0.97f;
__declspec(section ".sdata2") f32 lbl_803E2984 = 1.5f;
__declspec(section ".sdata2") f32 lbl_803E2988 = 4.0f;
__declspec(section ".sdata2") f32 lbl_803E298C = 6e+01f;

void fn_801540A0(int obj, int state)
{
    u8 done;

    *(f32*)(state + 0x32c) = lbl_803E294C;
    done = 0;
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, FALL_LADDERS_HIT_VOLUME_SLOT, 1, -1);
    if (*(void**)(state + 0x340) != 0)
    {
        done = 1;
        *(f32*)(state + 0x324) = lbl_803E2968;
        *(f32*)(state + 0x32c) = lbl_803E294C;
        if (((GameObject*)obj)->anim.currentMove != 0)
        {
            Baddie_SetMove(obj, state, 2, lbl_803E2958, 0, 3);
        }
    }
    if (((GameObject*)obj)->anim.currentMove != 3)
    {
        fn_8014CF7C(obj, state, ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                    ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ, 0x3c, 0);
    }
    else
    {
        *(f32*)(state + 0x328) -= timeDelta;
        if (*(f32*)(state + 0x328) <= lbl_803E294C)
        {
            done = 1;
            *(f32*)(state + 0x32c) = lbl_803E2940;
            *(f32*)(state + 0x324) = lbl_803E2944;
            Baddie_SetMove(obj, state, 4, lbl_803E2948, 0, 3);
        }
    }
    if (done != 0)
    {
        *(u32*)&((BaddieState*)state)->unk2E4 |= (u64)0x10000;
    }
    else if (((BaddieState*)state)->seqEntryIndex == 0)
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
        Baddie_SetMove(obj, state, 1, lbl_803E296C, 0, 3);
    }
    else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0 &&
             (Baddie_SetMove(obj, state, 3, lbl_803E2970, 0, 3), lbl_803E294C == *(f32*)(state + 0x328)))
    {
        *(f32*)(state + 0x328) = lbl_803E2974;
        fn_8014CF7C(obj, state, ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                    ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ, 1, 0);
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_25d);
    }
    ((GameObject*)obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
    ((GameObject*)obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
    if (((BaddieState*)state)->inWhirlpoolGroup != 0)
    {
        ((BaddieState*)state)->inWhirlpoolGroup -= 1;
    }
}

void fn_801542AC(int unused, u8* state)
{
    f32 fz;
    f32 fc;
    ((BaddieState*)state)->speedScale = lbl_803E2978;
    ((BaddieState*)state)->unk2E4 = 173;
    ((BaddieState*)state)->unk308 = lbl_803E297C;
    ((BaddieState*)state)->animDeltaScale = lbl_803E2954;
    ((BaddieState*)state)->unk304 = lbl_803E2980;
    ((BaddieState*)state)->unk320 = 0;
    fz = lbl_803E2984;
    *(f32*)&((BaddieState*)state)->eventFlags = fz;
    ((BaddieState*)state)->unk321 = 7;
    ((BaddieState*)state)->unk318 = lbl_803E2988;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fz;
    fc = lbl_803E294C;
    *(f32*)((char*)state + 804) = fc;
    *(f32*)((char*)state + 808) = fc;
    *(f32*)((char*)state + 812) = fc;
    ((BaddieState*)state)->seqEntryIndex = 0;
    ((BaddieState*)state)->inWhirlpoolGroup = 0;
    *(f32*)((char*)state + 816) = lbl_803E298C;
    ((BaddieState*)state)->pathStep = lbl_803E2958;
}
