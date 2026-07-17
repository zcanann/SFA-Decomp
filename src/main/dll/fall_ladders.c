/*
 * fall_ladders - shared baddie move/behaviour handlers (0x80154328..0x80154870).
 *
 * These three functions are not an object descriptor of their own; they are
 * called by other baddie DLLs (dll_00C9_enemy, dll_00C4_tricky) as per-state
 * update/setup callbacks for a curve-following water creature.
 *
 *   fn_80154328  spawns a water ripple under the object and a splash sfx when
 *                it is moving fast enough; gated by a randomised cooldown.
 *   Baddie_HandleHitReaction  hit-reaction handler: sets reaction flags + door sfx above a
 *                progress threshold.
 *   fn_80154584  curve-path follow update: advances the RomCurveWalker, steers
 *                toward the next point, bobs rotY via a sine table, then calls
 *                fn_80154328.
 *
 * The state pointer is the surrounding BaddieState; most accesses are raw
 * offsets into its per-baddie scratch region (0x29c..0x340).
 */
#include "main/dll/baddie_state.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/e_rem_pio2.h"
#include "main/dll/baddie_setmove.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/waterfx_interface.h"
#include "main/game_object.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"

int lbl_803DBCD0[2] = {2, 3};

#define FALL_LADDERS_HIT_VOLUME_SLOT 0x18

extern f32 lbl_803E294C;
extern f32 lbl_803E2958;
extern f32 lbl_803E2940;
extern f32 lbl_803E2944;
extern f32 lbl_803E2948;
extern f32 lbl_803E2968;
extern f32 lbl_803E296C;
extern f32 lbl_803E2970;
extern f32 lbl_803E2974;
extern f32 lbl_803E2978;
extern f32 lbl_803E297C;
extern f32 lbl_803E2954;
extern f32 lbl_803E2980;
extern f32 lbl_803E2984;
extern f32 lbl_803E2988;
extern f32 lbl_803E298C;

extern void fn_8014CF7C(int obj, int state, f32 a, f32 b, int c, int d);
extern void fn_8014C678(int obj, int state, f32* vec, f32 a, f32 b, f32 c, int d);
extern void fn_8014CD1C(int obj, int state, int c, f32 a, f32 b, int d);


#pragma dont_inline on
void fn_80154328(int obj, int state)
{
    f32 mtx[17];
    MatrixTransform stk;
    f32 tx;
    f32 ox;
    f32 tz;

    *(f32*)(state + 0x330) -= timeDelta;
    if (*(f32*)(state + 0x330) <= 0.0f)
    {
        *(f32*)(state + 0x330) = (f32)(s32)randomGetRange(30, 60);
        stk.x = ((GameObject*)obj)->anim.localPosX;
        stk.y = 0.0f;
        stk.z = ((GameObject*)obj)->anim.localPosZ;
        stk.rotX = ((GameObject*)obj)->anim.rotX;
        stk.rotY = 0;
        stk.rotZ = 0;
        stk.scale = 1.0f;
        setMatrixFromObjectPos(mtx, &stk);
        tx = 5.0f + (f32)(s32)randomGetRange(-20, 20) / 10.0f;
        tz = 2.0f + (f32)(s32)randomGetRange(-20, 20) / 10.0f;
        Matrix_TransformPoint(mtx, tx, 0.0f, tz, &tx, &ox, &tz);
        (*gWaterfxInterface)->spawnRipple(tx, *(f32*)(state + 0x32c), tz, 0, 0.0f, 3);
        if (sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                  ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ) > 0.5f)
        {
            ((void (*)(u32, f32, f32, f32, u16))Sfx_PlayAtPositionFromObject)(obj, stk.x, stk.y, stk.z,
                                                                              SFXstaff_proj_putaway);
        }
    }
}

#pragma dont_inline reset

#pragma optimization_level 1
#pragma peephole on
void Baddie_HandleHitReaction(GameObject* obj, u8* state, int unused, int cmd)
{
    int objCopy = (int)obj;
    if (cmd == 17 || cmd == 16)
        return;
    if ((obj)->anim.currentMoveProgress > 0.5f)
    {
        ((BaddieState*)state)->reactionFlags |= 8;
        Sfx_PlayFromObject(objCopy, SFXTRIG_en_rfall5_c);
        Sfx_PlayFromObject((int)obj, SFXTRIG_wp_iceywindlp16_233);
        ((BaddieState*)state)->hitCounter = 0;
        ((BaddieState*)state)->unk2E4 |= 32;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags |= 16;
    }
}
#pragma peephole reset
#pragma optimization_level reset

void fn_80154584(GameObject* obj, int state)
{
    ObjHitsPriorityState* hitState;
    RomCurveWalker* curve;
    u8 rnd;
    f32 vec[3];

    curve = *(RomCurveWalker**)state;
    ((BaddieState*)state)->inWhirlpoolGroup = 0;
    hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if ((Curve_AdvanceAlongPath(curve, ((BaddieState*)state)->pathStep) != 0 || curve->atSegmentEnd != 0) &&
            (*gRomCurveInterface)->goNextPoint((void*)curve) != 0 &&
            (*gRomCurveInterface)
                    ->initCurve(*(RomCurveWalker**)state, (void*)obj, 700.0f, lbl_803DBCD0, -1) != 0)
        {
            ((BaddieState*)state)->controlFlags &= ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
        }
        vec[0] = curve->posX - (obj)->anim.localPosX;
        vec[1] = 0.0f;
        vec[2] = curve->posZ - (obj)->anim.localPosZ;
        fn_8014C678((int)obj, state, vec, 2.0f, 0.1f, 0.1f, 1);
        *(f32*)(state + 0x324) += timeDelta;
        if (*(f32*)(state + 0x324) > 360.0f)
        {
            *(u32*)&((BaddieState*)state)->unk2E4 &= ~(u64)0x10000;
            *(f32*)(state + 0x324) = 0.0f;
        }
    }
    (obj)->anim.rotY =
        -(1024.0f * fn_80293DA4(0.19634955f * (f32)(u32) * (u8*)(state + 0x33a)) - (f32)(obj)->anim.rotY);
    fn_8014CD1C((int)obj, state, 0xf, 7.5f, 1.0f, 0);
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        if ((obj)->anim.currentMoveProgress < 0.5)
        {
            rnd = randomGetRange(0, 200);
        }
        else
        {
            rnd = randomGetRange(0, 0x3c);
        }
        if (rnd == 0)
        {
            if ((obj)->anim.currentMoveProgress > 0.5)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_kooshy_hit);
                ((BaddieState*)state)->unk308 = -0.02f;
            }
            else
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_kooshy_death);
                ((BaddieState*)state)->unk308 = 0.02f;
            }
        }
    }
    ((BaddieState*)state)->seqEntryIndex += 1;
    (obj)->anim.rotY =
        1024.0f * fn_80293DA4(0.19634955f * (f32)(u32) * (u8*)(state + 0x33a)) + (f32)(obj)->anim.rotY;
    fn_80154328((int)obj, state);
}
