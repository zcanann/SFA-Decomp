/*
 * magicplant - per-move behaviour handlers for the magic-plant enemy,
 * shared by the tricky (DLL 0x00C4) and enemy (DLL 0x00C9) object DLLs,
 * which dispatch to these by object seqId.
 *
 * Each fn_8015xxxx takes (GameObject* obj, BaddieState* state) and drives
 * one AI phase: per-move setup of speed/hitbox/path constants, curve-path
 * following via the RomCurve interface, a wind-up state machine that spits
 * projectiles toward the tracked object, line-of-sight gating through the
 * voxel maps, hit-reaction message handling, and particle-fx spawning.
 * BaddieState->controlFlags bit 0x2000 gates path advance; 0x40000000 the
 * attack window; userData2 holds per-instance counters/flags.
 */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/audio/sfx.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/obj_placement.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/voxmaps.h"

int lbl_803DBCB8[2] = {2, 3};
u8 gMagicPlantSeqEntryTable[8] = {1, 1, 3, 2, 0, 0, 0, 0};
int lbl_803DBCC8[2] = {2, 3};

#define MAGICPLANT_OBJFLAG_PARENT_SLACK 0x1000

/* DLL-id of the object spawned by fn_80153640 (generic spawn; no cache field /
   named spawn-fn / kind name -> suffixless per role-gate). */
#define MAGICPLANT_CHILD_OBJ 0x51b

/* The magic-plant's one particle-fx effect (spawned per hit-count in the
   attack handler). */
#define MAGICPLANT_PARTFX          0x802
#define MAGICPLANT_HIT_VOLUME_SLOT 0xe

void fn_8014D08C(GameObject* obj, int state, u8 moveId, f32 speed, int p5, int flags);
#define Baddie_SetMove(obj, state, moveId, speed, p5, flags)                                                           \
    fn_8014D08C((GameObject*)(obj), (int)(state), (moveId), (speed), (p5), (flags))

void vambat_updateWhileFrozen(int obj, int state, int unused, int msgFlag, int wpad0, int wpad1, void* wpad2, int wpad3)
{
    if (((BaddieState*)state)->userData2 != 0)
    {
        if (msgFlag == 16)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x28;
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_mika_wingflap);
            *(s16*)&((BaddieState*)state)->hitCounter = 0;
        }
    }
    else if (msgFlag != 17)
    {
        if (msgFlag == 16)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
        }
        else
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x8;
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_mika_wingflap);
            *(s16*)&((BaddieState*)state)->hitCounter = 0;
        }
    }
}

void fn_80153040(GameObject* obj, int state)
{
    ObjHitsPriorityState* hitState;
    RomCurveWalker* curve;
    f32 vec[3];

    curve = *(RomCurveWalker**)state;
    if ((obj)->anim.hitReactState != NULL)
    {
        hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
        hitState->suppressOutgoingHits = 0;
    }
    if (((BaddieState*)state)->userData2 != 0)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x80;
    }
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if (Curve_AdvanceAlongPath(curve, ((BaddieState*)state)->pathStep) != 0 || curve->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(curve) != 0)
            {
                if ((*gRomCurveInterface)
                        ->initCurve(*(RomCurveWalker**)state, (void*)obj, 7e+02f, lbl_803DBCB8, -1) != 0)
                {
                    ((BaddieState*)state)->controlFlags =
                        ((BaddieState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }

        fn_8014CF7C(obj, state, curve->posX, curve->posZ, 0xf, 0);

        vec[0] = curve->posX - (obj)->anim.localPosX;
        vec[1] = curve->posY - (obj)->anim.localPosY;
        vec[2] = curve->posZ - (obj)->anim.localPosZ;
        fn_8014C678(obj, (void*)state, vec, 1.5f, 0.75f, 0.15f, 1);

        *(f32*)(state + 0x324) = *(f32*)(state + 0x324) + timeDelta;
        if (*(f32*)(state + 0x324) > 3.6e+02f)
        {
            *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 & ~(u64)0x10000;
            *(f32*)(state + 0x324) = 0.0f;
        }
    }

    fn_8014CD1C(obj, (void*)state, 0xf, 1e+01f, 1.0f, 0);

    *(f32*)(state + 0x328) = *(f32*)(state + 0x328) - timeDelta;
    if (*(f32*)(state + 0x328) <= 0.0f)
    {
        *(f32*)(state + 0x328) = 6e+01f;
        Sfx_PlayFromObject((int)obj, SFXTRIG_mn_heart1_c);
    }
    *(f32*)(state + 0x32c) = 0.0f;
}

void fn_80153248(GameObject* obj, int state)
{
    RomCurveWalker* curve;
    f32 vec[3];
    f32 worldPos[3];
    int gridB[2];
    int gridA[2];
    u8 hitOut;
    int trackedObj;

    curve = *(RomCurveWalker**)state;
    if (((BaddieState*)state)->userData2 != 0)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x80;
    }
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_mika_bombwhistle);
    }
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if (Curve_AdvanceAlongPath(curve, 2.0f * ((BaddieState*)state)->pathStep) != 0 ||
            curve->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(curve) != 0)
            {
                if ((*gRomCurveInterface)
                        ->initCurve(*(RomCurveWalker**)state, (void*)obj, 7e+02f, lbl_803DBCB8, -1) != 0)
                {
                    ((BaddieState*)state)->controlFlags =
                        ((BaddieState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, MAGICPLANT_HIT_VOLUME_SLOT, 1, 0);
    trackedObj = *(int*)&((BaddieState*)state)->trackedObj;
    vec[0] = ((GameObject*)trackedObj)->anim.localPosX - (obj)->anim.localPosX;
    vec[1] = (25.0f + ((GameObject*)trackedObj)->anim.localPosY) - (obj)->anim.localPosY;
    vec[2] = ((GameObject*)trackedObj)->anim.localPosZ - (obj)->anim.localPosZ;
    PSVECMag(vec);
    *(f32*)(state + 0x32c) = *(f32*)(state + 0x32c) + timeDelta;
    if (*(u32*)(state + 0x340) != 0 || *(f32*)(state + 0x32c) > 3.6e+02f)
    {
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
        *(f32*)(state + 0x324) = 0.0f;
        *(f32*)(state + 0x32c) = 0.0f;
    }
    else
    {
        worldPos[0] = (obj)->anim.localPosX;
        worldPos[1] = (obj)->anim.localPosY;
        worldPos[2] = (obj)->anim.localPosZ;
        voxmaps_worldToIntGrid(worldPos, gridA);
        worldPos[0] = curve->posX;
        worldPos[1] = curve->posY;
        worldPos[2] = curve->posZ;
        voxmaps_worldToIntGrid(worldPos, gridB);
        /* BUG: precedence - `!` binds before `&`, so this is (controlFlags == 0) & 0x01000000,
         * which is always false; the line-of-sight abort below can never fire. The author
         * almost certainly meant !(controlFlags & 0x01000000). */
        if (!((BaddieState*)state)->controlFlags & 0x01000000)
        {
            if (voxmaps_traceIntGrid(gridB, gridA, NULL, &hitOut, 0) == 0)
            {
                *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
                *(f32*)(state + 0x324) = 0.0f;
                *(f32*)(state + 0x32c) = 0.0f;
            }
        }
    }
    fn_8014C678(obj, (void*)state, vec, 1.5f, 0.75f, 0.15f, 1);
    fn_8014CD1C(obj, (void*)state, 0xf, 1e+01f, 1.0f, 0);
}

void vambat_init(GameObject* obj, int state)
{
    f32 initSpeed;
    f32 zero;
    f32 pathStepInit;

    ((BaddieState*)state)->speedScale = 4e+01f;
    *(u32*)&((BaddieState*)state)->unk2E4 = 0x1009;
    ((BaddieState*)state)->unk308 = 0.02f;
    ((BaddieState*)state)->animDeltaScale = 0.1f;
    ((BaddieState*)state)->unk304 = 0.97f;
    ((BaddieState*)state)->unk320 = 0;
    initSpeed = 1.5f;
    *(f32*)&((BaddieState*)state)->eventFlags = initSpeed;
    ((BaddieState*)state)->unk321 = 1;
    pathStepInit = 1.0f;
    ((BaddieState*)state)->unk318 = pathStepInit;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = initSpeed;
    zero = 0.0f;
    *(f32*)(state + 0x324) = zero;
    *(f32*)(state + 0x328) = zero;
    *(f32*)(state + 0x32c) = zero;
    ((BaddieState*)state)->pathStep = pathStepInit;
    switch (obj->anim.seqId)
    {
    case 0x7c6:
        ((BaddieState*)state)->userData2 = 1;
        break;
    default:
        ((BaddieState*)state)->userData2 = 0;
        break;
    }
}

void fn_8015355C(GameObject* obj, int state)
{
    u8 count = 0;
    switch (obj->anim.currentMove)
    {
    case 1:
        count = 1;
        break;
    case 2:
        count = 1;
        break;
    case 3:
        count = 1;
        break;
    case 5:
        if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
        {
            count = 0xa;
        }
        break;
    case 7:
        break;
    }
    if (count != 0 && (((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) == 0)
    {
        u8 spawn = count;
        while (spawn != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, MAGICPLANT_PARTFX, NULL, 2, -1, NULL);
            spawn--;
        }
    }
}
