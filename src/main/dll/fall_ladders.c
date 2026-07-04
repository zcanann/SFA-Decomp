/*
 * fall_ladders - shared baddie move/behaviour handlers (0x801540A0..0x80154870).
 *
 * These five functions are not an object descriptor of their own; they are
 * called by other baddie DLLs (dll_00C9_enemy, dll_00C4_tricky, fireflylantern)
 * as per-state update/setup callbacks for a curve-following water creature.
 *
 *   fn_801540A0  per-frame move update: picks the active move (Baddie_SetMove)
 *                from the tracked target, runs an approach/retreat timer, and
 *                plays a gasp sfx on the attack transition.
 *   fn_801542AC  one-shot move setup: seeds speed/path-step and the BaddieState
 *                scratch floats at 0x300..0x33c.
 *   fn_80154328  spawns a water ripple under the object and a splash sfx when
 *                it is moving fast enough; gated by a randomised cooldown.
 *   fn_801544E8  hit-reaction handler: sets reaction flags + door sfx above a
 *                progress threshold.
 *   fn_80154584  curve-path follow update: advances the RomCurveWalker, steers
 *                toward the next point, bobs rotY via a sine table, then calls
 *                fn_80154328.
 *
 * The state pointer is the surrounding BaddieState; most accesses are raw
 * offsets into its per-baddie scratch region (0x29c..0x340).
 */
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "main/gameplay_runtime.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern f32 sqrtf(f32 x);
extern f32 lbl_803E294C;
extern f32 lbl_803E2958;

extern void fn_8014CF7C(int obj, int p, f32 a, f32 b, int c, int d);
extern void fn_8014C678(int obj, int p, f32* vec, f32 a, f32 b, f32 c, int d);
extern void fn_8014CD1C(int obj, int p, int c, f32 a, f32 b, int d);
extern void fn_80154328(int obj, int p);
extern f64 lbl_803DBCD0;
extern f32 timeDelta;
extern f32 lbl_803E2940;
extern f32 lbl_803E2944;
extern f32 lbl_803E2948;
extern f32 lbl_803E2968;
extern f32 lbl_803E296C;
extern f32 lbl_803E2970;
extern f32 lbl_803E2974;
extern f32 lbl_803E2990;
extern f32 lbl_803E2994;
extern f32 lbl_803E2998;
extern f32 lbl_803E299C;
extern f32 lbl_803E29A0;
extern f32 lbl_803E29A4;
extern f32 lbl_803E29B0;
extern f32 lbl_803E29B4;
extern f32 lbl_803E29B8;
extern f32 lbl_803E29BC;
extern f32 lbl_803E29C0;
extern f32 lbl_803E29C4;
extern f64 lbl_803E29C8;
extern f32 lbl_803E29D0;
extern f32 lbl_803E29D4;
extern f32 lbl_803E2978;
extern f32 lbl_803E297C;
extern f32 lbl_803E2954;
extern f32 lbl_803E2980;
extern f32 lbl_803E2984;
extern f32 lbl_803E2988;
extern f32 lbl_803E298C;

#pragma scheduling off
#pragma peephole off
void fn_801540A0(int obj, int p)
{
    u8 done;

    *(f32*)(p + 0x32c) = lbl_803E294C;
    done = 0;
    ObjHits_SetHitVolumeSlot(obj, 0x18, 1, -1);
    if (*(void**)(p + 0x340) != 0)
    {
        done = 1;
        *(f32*)(p + 0x324) = lbl_803E2968;
        *(f32*)(p + 0x32c) = lbl_803E294C;
        if (((GameObject*)obj)->anim.currentMove != 0)
        {
            Baddie_SetMove(obj, p, 2, lbl_803E2958, 0, 3);
        }
    }
    if (((GameObject*)obj)->anim.currentMove != 3)
    {
        fn_8014CF7C(obj, p, ((GameObject*)((BaddieState*)p)->trackedObj)->anim.localPosX, ((GameObject*)((BaddieState*)p)->trackedObj)->anim.localPosZ, 0x3c, 0);
    }
    else
    {
        *(f32*)(p + 0x328) -= timeDelta;
        if (*(f32*)(p + 0x328) <= lbl_803E294C)
        {
            done = 1;
            *(f32*)(p + 0x32c) = lbl_803E2940;
            *(f32*)(p + 0x324) = lbl_803E2944;
            Baddie_SetMove(obj, p, 4, lbl_803E2948, 0, 3);
        }
    }
    if (done != 0)
    {
        *(u32*)&((BaddieState*)p)->unk2E4 |= (u64)0x10000;
    }
    else if (((BaddieState*)p)->seqEntryIndex == 0)
    {
        ((BaddieState*)p)->seqEntryIndex = 1;
        Baddie_SetMove(obj, p, 1, lbl_803E296C, 0, 3);
    }
    else if ((((BaddieState*)p)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0 &&
        (Baddie_SetMove(obj, p, 3, lbl_803E2970, 0, 3), lbl_803E294C == *(f32*)(p + 0x328)))
    {
        *(f32*)(p + 0x328) = lbl_803E2974;
        fn_8014CF7C(obj, p, ((GameObject*)((BaddieState*)p)->trackedObj)->anim.localPosX, ((GameObject*)((BaddieState*)p)->trackedObj)->anim.localPosZ, 1, 0);
        Sfx_PlayFromObject(obj, SFXfox_healthgasp2);
    }
    ((GameObject*)obj)->anim.rotY = ((BaddieState*)p)->spawnRotY;
    ((GameObject*)obj)->anim.rotZ = ((BaddieState*)p)->spawnRotZ;
    if (((BaddieState*)p)->inWhirlpoolGroup != 0)
    {
        ((BaddieState*)p)->inWhirlpoolGroup -= 1;
    }
}

void fn_80154584(int obj, int p)
{
    ObjHitsPriorityState* hitState;
    RomCurveWalker* curve;
    u8 rnd;
    f32 vec[3];

    curve = *(RomCurveWalker**)p;
    ((BaddieState*)p)->inWhirlpoolGroup = 0;
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    if ((((BaddieState*)p)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if ((Curve_AdvanceAlongPath(curve, ((BaddieState*)p)->pathStep) != 0 || curve->atSegmentEnd != 0) &&
            (*gRomCurveInterface)->goNextPoint((void*)curve) != 0 &&
            (*gRomCurveInterface)->initCurve(*(RomCurveWalker**)p, (void*)obj, lbl_803E29B0,
                                             (int*)&lbl_803DBCD0, -1) != 0)
        {
            ((BaddieState*)p)->controlFlags &= ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
        }
        vec[0] = curve->posX - ((GameObject*)obj)->anim.localPosX;
        vec[1] = lbl_803E2990;
        vec[2] = curve->posZ - ((GameObject*)obj)->anim.localPosZ;
        fn_8014C678(obj, p, vec, lbl_803E29A0, lbl_803E29B4, *(f32*)&lbl_803E29B4, 1);
        *(f32*)(p + 0x324) += timeDelta;
        if (*(f32*)(p + 0x324) > lbl_803E29B8)
        {
            *(u32*)&((BaddieState*)p)->unk2E4 &= ~(u64)0x10000;
            *(f32*)(p + 0x324) = lbl_803E2990;
        }
    }
    ((GameObject*)obj)->anim.rotY = -(lbl_803E29BC * fn_80293DA4(lbl_803E29C0 * (f32)(u32) * (u8*)(p + 0x33a)) - (
        f32)((GameObject*)obj)->anim.rotY);
    fn_8014CD1C(obj, p, 0xf, lbl_803E29C4, lbl_803E2994, 0);
    if ((((BaddieState*)p)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E29C8)
        {
            rnd = randomGetRange(0, 200);
        }
        else
        {
            rnd = randomGetRange(0, 0x3c);
        }
        if (rnd == 0)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E29C8)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_hit);
                ((BaddieState*)p)->unk308 = lbl_803E29D0;
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_kooshy_death);
                ((BaddieState*)p)->unk308 = lbl_803E29D4;
            }
        }
    }
    ((BaddieState*)p)->seqEntryIndex += 1;
    ((GameObject*)obj)->anim.rotY = lbl_803E29BC * fn_80293DA4(lbl_803E29C0 * (f32)(u32) * (u8*)(p + 0x33a)) + (
        f32)((GameObject*)obj)->anim.rotY;
    fn_80154328(obj, p);
}

void fn_80154328(int obj, int p)
{
    f32 mtx[17];
    struct
    {
        s16 in[6];
        f32 pos[3];
    } stk;
    f32 tx;
    f32 ox;
    f32 tz;

    *(f32*)(p + 0x330) -= timeDelta;
    if (*(f32*)(p + 0x330) <= lbl_803E2990)
    {
        *(f32*)(p + 0x330) = (f32)(s32)randomGetRange(30, 60);
        stk.pos[0] = ((GameObject*)obj)->anim.localPosX;
        stk.pos[1] = lbl_803E2990;
        stk.pos[2] = ((GameObject*)obj)->anim.localPosZ;
        stk.in[0] = ((GameObject*)obj)->anim.rotX;
        stk.in[1] = 0;
        stk.in[2] = 0;
        *(f32*)(stk.in + 4) = lbl_803E2994;
        setMatrixFromObjectPos(mtx, stk.in);
        tx = lbl_803E2998 + (f32)(s32)randomGetRange(-20, 20) / lbl_803E299C;
        tz = lbl_803E29A0 + (f32)(s32)randomGetRange(-20, 20) / lbl_803E299C;
        Matrix_TransformPoint(mtx, tx, lbl_803E2990, tz, &tx, &ox, &tz);
        ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
            tx, *(f32*)(p + 0x32c), tz, 0, lbl_803E2990, 3);
        if (sqrtf(
            ((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)->anim.velocityZ
            * ((GameObject*)obj)->anim.velocityZ) > lbl_803E29A4)
        {
            ((void (*)(u32, f32, f32, f32, u16))Sfx_PlayAtPositionFromObject)(
                obj, stk.pos[0], stk.pos[1], stk.pos[2], SFXstaff_proj_putaway);
        }
    }
}

#pragma optimization_level 1
#pragma peephole on
void fn_801544E8(int obj, u8* state, int unused, int cmd)
{
    int objCopy = obj;
    if (cmd == 17 || cmd == 16) return;
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E29A4)
    {
        *(int*)&((BaddieState*)state)->reactionFlags |= 8;
        Sfx_PlayFromObject(objCopy, SFXdoor_unlocked);
        Sfx_PlayFromObject(obj, SFXdoor_creak);
        *(s16*)&((BaddieState*)state)->hitCounter = 0;
        ((BaddieState*)state)->unk2E4 |= 32;
    }
    else
    {
        *(int*)&((BaddieState*)state)->reactionFlags |= 16;
    }
}
#pragma peephole reset
#pragma optimization_level reset

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
