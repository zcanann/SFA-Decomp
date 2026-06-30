/*
 * sidekick-toy baddie reaction + update handlers (EN v1.0 0x801504F8,
 * 0x80150910, 0x80150EDC). The object is a curve-following toy/pet baddie
 * driven by per-family anim tables keyed off BaddieState.inWhirlpoolGroup
 * (state[0x33b]):
 *   - fn_801504F8: hit/message reaction handler. Maps incoming message ids
 *     (0xe..0x1f) onto reaction flags (BaddieState.reactionFlags 8/0x10/0x28),
 *     starts a new anim move from the per-family row tables, decrements the
 *     hit counter and plays the impact sfx (0x13/0x14/0x22).
 *   - fn_80150910 / fn_80150EDC: per-frame update. Run the timer-driven 16B
 *     anim chain (state[0x338] walks the SeqRow16 table), follow the rom
 *     curve (path-chase with distance/turn speed shaping when controlFlags
 *     0x2000 is set), and fall back to randomised idle anims otherwise.
 * Group 5 (the whirlpool group) sets game bit 0x1c8 once it is active.
 * Tables: lbl_8031F16C is the per-family table-of-tables (0x28-stride rows);
 * lbl_8031DD30 holds per-anim move-progress floats.
 */
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gamebits.h"
#include "main/dll/objfsa.h"
#include "main/dll/fx_800944A0_shared.h"
extern u8 lbl_8031DD30[];   /* per-anim move-progress floats, indexed anim*4 */

/* per-family table-of-tables row (0x28 bytes); holds pointers to the
 * sub-tables that drive a family's anim sequencing. */
typedef struct
{
    u8* tbl0;     /* 0x00 */
    u8* tbl4;     /* 0x04 */
    u8  pad08[0x14]; /* 0x08 */
    u8* tbl1c;    /* 0x1c */
    u8  pad20[0x08]; /* 0x20 */
} FamilyTable;

extern FamilyTable lbl_8031F16C[];   /* per-family table-of-tables, 0x28-byte rows */
extern int Sfx_PlayFromObject(void* obj, int sfxId);
extern void fn_8015039C(void* p1, void* p2);
extern u32 fn_8014FFB4(void* p1, void* p2, int p3);
extern void fn_8014CF7C(void* p1, void* p2, f32 f1, f32 f2, int p5, int p6);
extern void sidekickToy_updateCurveTargetLatch(int* obj);


extern int getAngle(float y, float x);

extern f32 lbl_803E2740;  /* 0.0f */
extern f32 lbl_803E274C;
extern f32 lbl_803E2768;
extern f32 lbl_803E276C;
extern f32 lbl_803E27A0;
extern f32 lbl_803E2748;
extern f32 lbl_803E2754;
extern f32 lbl_803E2778;
extern f32 gSidekickToyDistToSpeedScale;
extern f32 lbl_803E2780;
extern f32 gSidekickToyAngleWrapNegFull;
extern f32 gSidekickToyAngleWrapHalf;
extern f32 gSidekickToyAngleWrapFull;
extern f32 gSidekickToyAngleWrapNegHalf;
extern f32 lbl_803E2794;
extern f32 lbl_803E2798;
extern f32 lbl_803E279C;

/* per-family anim-table row: speed + flags + anim ids and chain links */
typedef struct
{
    f32 speed; /* 0x0 */
    u32 flags; /* 0x4 */
    u8 anim;   /* 0x8 */
    u8 next;   /* 0x9 */
    u8 alt;    /* 0xa */
    u8 padB;   /* 0xb */
    u32 extra; /* 0xc */
} SeqRow16;

typedef struct
{
    f32 speed; /* 0x0 */
    u32 flags; /* 0x4 */
    u8 anim;   /* 0x8 */
    u8 next;   /* 0x9 */
    u16 padA;  /* 0xa */
} IdleRow;

int fn_801504F8(int* obj, u8* state, int* attacker, int msgId, int arrIdx, int damage)
{
    u8* slot = (u8*)lbl_8031F16C;
    u8* animRows;
    u8* rowsC;
    u8* rowsB;
    u8* trig;
    int ret;
    u8 type = state[0x33b];

    slot += type * 0x28;
    animRows = *(u8**)(slot + 0x10);
    rowsC = *(u8**)(slot + 0x24);
    rowsB = *(u8**)(slot + 0x1c);
    trig = *(u8**)(slot + 0x20);
    ret = 0;

    if (type == 5)
    {
        ((BaddieState*)state)->reactionFlags |= 0x10;
        return 0;
    }
    if (msgId == 0xe)
    {
        damage = damage * 0xa;
    }
    if (((GameObject*)obj)->anim.currentMove == animRows[0x128])
    {
        return 0;
    }
    if (msgId == 0x10)
    {
        ((BaddieState*)state)->reactionFlags |= 0x28;
        return 0;
    }
    if ((((BaddieState*)state)->controlFlags & 0x40) != 0 ||
        (trig[arrIdx] != 0 && ((u32)(msgId - 0xe) <= 1 || msgId == 0x13)))
    {
        if (msgId != 0x11)
        {
            f32 z;
            if (msgId != 0x1a && ((GameObject*)attacker)->anim.seqId != 0x6d &&
                ((GameObject*)attacker)->anim.seqId != 0x754)
            {
                Sfx_PlayFromObject(obj, 0x255);
                Sfx_PlayFromObject(obj, 0x16);
            }
            ((BaddieState*)state)->reactionFlags |= 0x10;
            {
                IdleRow* row = &((IdleRow*)rowsC)[state[0x33c]];
                Baddie_SetMove(obj, state, row->anim,
                            *(f32*)(rowsC + state[0x33c] * 12), 0,
                            (u8)row->flags);
            }
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
                (ObjAnimComponent*)obj,
                *(f32*)(lbl_8031DD30 + rowsC[state[0x33c] * 12 + 8] * 4));
            if (rowsC[state[0x33c] * 12 + 0xa] != 0)
            {
                state[0x33a] = rowsC[state[0x33c] * 12 + 0xa];
            }
            ret = rowsC[state[0x33c] * 12 + 9];
            *(f32*)(state + 0x32c) = *(f32*)(state + 0x330);
            z = lbl_803E2740;
            *(f32*)(state + 0x324) = z;
            *(f32*)(state + 0x334) = z;
        }
    }
    else
    {
        u32 amount;
        f32 z;

        if (msgId == 0x11)
        {
            amount = 0x18;
        }
        else
        {
            amount = state[0x2f1] & 0x1f;
            if ((u32)(state[0x2f1] & 0x1f) > 0x18)
            {
                amount = 0;
            }
        }
        z = lbl_803E2740;
        *(f32*)(state + 0x324) = z;
        if (state[0x2f1] & 0x18)
        {
            if (state[0x2f1] & 1)
            {
                *(f32*)(state + 0x334) = lbl_803E2768;
            }
            else
            {
                *(f32*)(state + 0x334) = lbl_803E276C;
            }
        }
        else
        {
            *(f32*)(state + 0x334) = z;
        }
        if (*(f32*)(state + 0x328) != lbl_803E2740 && *(u16*)(state + 0x338) != 0)
        {
            {
                SeqRow16* row = &((SeqRow16*)rowsB)[rowsB[*(u16*)(state + 0x338) * 16 + 0xb]];
                Baddie_SetMove(obj, state,
                            row->anim,
                            *(f32*)(rowsB + rowsB[*(u16*)(state + 0x338) * 16 + 0xb] * 16), 0,
                            (u8)row->flags);
            }
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
                (ObjAnimComponent*)obj,
                *(f32*)(lbl_8031DD30 +
                    rowsB[rowsB[*(u16*)(state + 0x338) * 16 + 0xb] * 16 + 8] * 4));
        }
        else
        {
            int off = (u8)amount * 12;

            {
                IdleRow* row = (IdleRow*)(animRows + off);
                Baddie_SetMove(obj, state, row->anim,
                            *(f32*)(animRows + (u8)amount * 12), 0,
                            (u8)row->flags);
            }
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj,
                                    *(f32*)(lbl_8031DD30 + animRows[off + 8] * 4));
            *(u16*)(state + 0x338) = animRows[off + 9];
            *(f32*)(state + 0x328) = (f32)(u32) * (u16*)(state + 0x2ec);
        }
        ((BaddieState*)state)->reactionFlags |= 8;
        if (((GameObject*)attacker)->anim.classId == 0x1c)
        {
            return 0;
        }
        {
            int* other = (int*)((GameObject*)attacker)->ownerObj;
            if (other != 0 && ((GameObject*)other)->anim.classId == 0x1c)
            {
                return 0;
            }
        }
        if (state[0x2f1] & 0x10)
        {
            damage = 0x14;
        }
        else
        {
            state[0x2f5] = 0;
        }
        if (damage > ((BaddieState*)state)->hitCounter)
        {
            ((BaddieState*)state)->hitCounter = 0;
        }
        else
        {
            ((BaddieState*)state)->hitCounter = ((BaddieState*)state)->hitCounter - damage;
        }
        if (((BaddieState*)state)->hitCounter == 0)
        {
            Sfx_PlayFromObject(obj, 0x13);
        }
        else
        {
            Sfx_PlayFromObject(obj, 0x14);
        }
        if (msgId != 0x1a && msgId != 0x1f && ((GameObject*)attacker)->anim.seqId != 0x6d &&
            ((GameObject*)attacker)->anim.seqId != 0x754)
        {
            Sfx_PlayFromObject(obj, 0x22);
        }
    }
    return ret;
}

/* EN v1.0 0x80150EDC  size: 870b  sidekick-toy anim-chain advance: timer-driven
 * 16-stride SeqRow16 chain + curve-follow speed shaping, called from the
 * fn_80150910 update path. */
void fn_80150EDC(void* obj, void* state)
{
    u8* table = lbl_8031DD30;
    u8 idx = ((BaddieState*)state)->inWhirlpoolGroup;
    void* animCtrl = *(void**)(table + idx * 0x28 + 0x143c);
    void* idleSrc = *(void**)(table + idx * 0x28 + 0x1454);
    u8* seqRows = *(u8**)(table + idx * 0x28 + 0x1458);

    if (idx == 5 && (((BaddieState*)state)->controlFlags & 0x800000) != 0)
    {
        GameBit_Set(0x1c8, 1);
    }

    if (((BaddieState*)state)->trackedObj != NULL &&
        ((GameObject*)((BaddieState*)state)->trackedObj)->anim.classId == 1)
    {
        fn_8001FEA8();
    }

    fn_8015039C(obj, state);

    {
        if (*(f32*)((u8*)state + 0x328) != lbl_803E2740 &&
            *(u16*)((u8*)state + 0x338) != 0)
        {
            f32 zero = lbl_803E2740;
            *(f32*)((u8*)state + 0x328) = *(f32*)((u8*)state + 0x328) - timeDelta;
            if (*(f32*)((u8*)state + 0x328) <= zero)
            {
                *(f32*)((u8*)state + 0x328) = zero;
                ((BaddieState*)state)->controlFlags |= 0x40000000LL; /* BADDIE_CONTROL_SEQUENCE_DRIVEN (LL form preserves codegen) */
                {
                    SeqRow16* seqRow16 = (SeqRow16*)seqRows;
                    *(u16*)((u8*)state + 0x338) =
                        seqRow16[*(u16*)((u8*)state + 0x338)].alt;
                }
            }
        }
    }

    if ((u8)fn_8014FFB4(obj, state, 0) != 0)
    {
        return;
    }

    if ((((BaddieState*)state)->controlFlags & 0x20000000) != 0 &&
        (*(u32*)((u8*)state + 0x2e0) & 0x20000000) == 0)
    {
        Sfx_PlayFromObject(obj, SFXdn_boar5_c);
        ((BaddieState*)state)->controlFlags |= 0x40000000LL; /* BADDIE_CONTROL_SEQUENCE_DRIVEN (LL form preserves codegen) */
    }

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        SeqRow16* seqRow16 = (SeqRow16*)seqRows;
        if (*(u16*)((u8*)state + 0x338) != 0)
        {
            *(u8*)((u8*)state + 0x2f2) =
                seqRow16[*(u16*)((u8*)state + 0x338)].extra;
            Baddie_SetMove(obj, state,
                        seqRow16[*(u16*)((u8*)state + 0x338)].anim,
                        *(f32*)(seqRows + (*(u16*)((u8*)state + 0x338) << 4)), 0,
                        (u8)seqRow16[*(u16*)((u8*)state + 0x338)].flags);
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
                (ObjAnimComponent*)obj,
                *(f32*)(table + (seqRow16[*(u16*)((u8*)state + 0x338)].anim << 2)));
            *(u16*)((u8*)state + 0x338) = seqRow16[*(u16*)((u8*)state + 0x338)].next;
        }
        else
        {
            IdleRow* idleRows = (IdleRow*)idleSrc;
            u8 v8;
            *(u8*)((u8*)state + 0x2f2) = 0;
            *(u8*)((u8*)state + 0x2f3) = 0;
            *(u8*)((u8*)state + 0x2f4) = 0;
            v8 = idleRows[*(u16*)((u8*)state + 0x2a0)].anim;
            if (v8 == 0)
            {
                *(u8*)((u8*)state + 0x323) = 3;
                ObjAnim_SetCurrentMove((int)obj, *(u8*)((u8*)animCtrl + 0x2c), lbl_803E2740, 0);
            }
            else
            {
                Baddie_SetMove(obj, state, v8,
                            idleRows[*(u16*)((u8*)state + 0x2a0)].speed, 0, 0xb);
                ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
                    (ObjAnimComponent*)obj,
                    *(f32*)(table + (idleRows[*(u16*)((u8*)state + 0x2a0)].anim << 2)));
            }
        }
    }

    if ((s32)((GameObject*)obj)->anim.currentMove == *(u8*)((u8*)animCtrl + 0x2c))
    {
        ((BaddieState*)state)->unk308 =
            ((BaddieState*)state)->pathStep *
            (((f32)(u32)*(u16*)((u8*)state + 0x2a4) /
                    ((BaddieState*)state)->unk2A8 / lbl_803E274C) *
                ((f32*)(table + 0x1538))[((BaddieState*)state)->inWhirlpoolGroup]);
        if (((BaddieState*)state)->unk308 < lbl_803E27A0)
        {
            ((BaddieState*)state)->unk308 = *(f32*)&lbl_803E27A0;
        }
    }

    if ((*(u8*)((u8*)state + 0x323) & 8) == 0)
    {
        void* p_29c = ((BaddieState*)state)->trackedObj;
        fn_8014CF7C(obj, state, ((GameObject*)p_29c)->anim.localPosX,
                    ((GameObject*)p_29c)->anim.localPosZ, 0xf, 0);
    }
}

/* EN v1.0 0x80150910  size: 1484b  sidekick-toy main update: timer-driven
 * 16-stride anim chain, curve chase with speed/turn shaping, idle anims. */

void fn_80150910(int* obj, u8* state)
{
    RomCurveWalker* path = *(RomCurveWalker**)state;
    u8* tbl4;
    u8* tbl0;
    u8* tbl1c;
    u32 flags;

    tbl4 = lbl_8031F16C[state[0x33b]].tbl4;
    tbl0 = lbl_8031F16C[state[0x33b]].tbl0;
    tbl1c = lbl_8031F16C[state[0x33b]].tbl1c;

    if (state[0x33b] == 5 && (((BaddieState*)state)->controlFlags & 0x800000))
    {
        GameBit_Set(0x1c8, 1);
    }
    fn_8015039C(obj, state);
    {
        f32 t = *(f32*)(state + 0x328);
        f32 z = lbl_803E2740;
        if (t != z && *(u16*)(state + 0x338) != 0)
        {
            *(f32*)(state + 0x328) = t - timeDelta;
            if (*(f32*)(state + 0x328) <= z)
            {
                *(f32*)(state + 0x328) = z;
                ((BaddieState*)state)->controlFlags |= 0x40000000LL; /* BADDIE_CONTROL_SEQUENCE_DRIVEN (LL form preserves codegen) */
                *(u16*)(state + 0x338) = tbl1c[*(u16*)(state + 0x338) * 16 + 0xa];
            }
        }
    }
    if ((u8)fn_8014FFB4(obj, state, 0) != 0)
    {
        return;
    }
    if (state[0x33d] != 0)
    {
        if (((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN)
        {
            f32 z = lbl_803E2740;
            ((GameObject*)obj)->anim.velocityZ = z;
            ((GameObject*)obj)->anim.velocityY = z;
            ((GameObject*)obj)->anim.velocityX = z;
            {
                IdleRow* idleRows = (IdleRow*)tbl4;
                Baddie_SetMove(obj, state, idleRows[state[0x33d]].anim,
                            *(f32*)(tbl4 + state[0x33d] * 12), 0,
                            (u8)idleRows[state[0x33d]].flags);
            }
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj,
                                    *(f32*)(lbl_8031DD30 + tbl4[state[0x33d] * 12 + 8] * 4));
            state[0x33d] = tbl4[state[0x33d] * 12 + 9];
            state[0x33e] = 0;
        }
        if (state[0x33e] == 0)
        {
            return;
        }
    }
    if ((((BaddieState*)state)->controlFlags & 0x80000000) && state[0x33d] == 0)
    {
        sidekickToy_updateCurveTargetLatch(obj);
    }
    flags = ((BaddieState*)state)->controlFlags;
    if (flags & 0x2000)
    {
        f32 d;
        f32 delta;

        {
            f32 dx = path->posX - ((GameObject*)obj)->anim.localPosX;
            f32 dz = path->posZ - ((GameObject*)obj)->anim.localPosZ;
            d = sqrtf(dx * dx + dz * dz);
        }
        if (d > lbl_803E2778)
        {
            d = lbl_803E2778;
        }
        {
            f32 diff = *(f32*)&lbl_803E2778 - d;
            f32 spd = diff * gSidekickToyDistToSpeedScale;
            *(f32*)(state + 0x310) = spd * ((BaddieState*)state)->pathStep;
        }
        if (*(f32*)(state + 0x310) < lbl_803E2780)
        {
            *(f32*)(state + 0x310) = *(f32 *)&lbl_803E2780;
        }
        if (Curve_AdvanceAlongPath(path, *(f32*)(state + 0x310)) != 0 || path->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(path) != 0)
            {
                sidekickToy_updateCurveTargetLatch(obj);
            }
        }
        delta = (f32)(int)((u16)getAngle(path->tangentX, path->tangentZ) + 0x8000 -
            (u16)((GameObject*)obj)->anim.rotX);
        if (delta > gSidekickToyAngleWrapHalf)
        {
            delta = gSidekickToyAngleWrapNegFull + delta;
        }
        if (delta < gSidekickToyAngleWrapNegHalf)
        {
            delta = gSidekickToyAngleWrapFull + delta;
        }
        ((BaddieState*)state)->unk308 =
            (((BaddieState*)state)->pathStep - *(f32*)(state + 0x310)) / lbl_803E274C *
            (lbl_803E2748 - ((delta >= lbl_803E2740) ? delta : -delta) / gSidekickToyAngleWrapFull);
        if (*(f32*)(state + 0x308) < lbl_803E2754)
        {
            *(f32*)(state + 0x308) = *(f32*)&lbl_803E2754;
        }
        if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) && state[0x33d] == 0)
        {
            if (*(u16*)(state + 0x338) != 0)
            {
                SeqRow16* seqRow16 = (SeqRow16*)tbl1c;
                Baddie_SetMove(obj, state, seqRow16[*(u16*)(state + 0x338)].anim,
                            *(f32*)(tbl1c + *(u16*)(state + 0x338) * 16), 0,
                            (u8)seqRow16[*(u16*)(state + 0x338)].flags);
                ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
                    (ObjAnimComponent*)obj,
                    *(f32*)(lbl_8031DD30 + tbl1c[*(u16*)(state + 0x338) * 16 + 8] * 4));
                *(u16*)(state + 0x338) = tbl1c[*(u16*)(state + 0x338) * 16 + 9];
            }
            else if (*(f32*)(state + 0x310) > lbl_803E2794)
            {
                state[0x2f2] = 0;
                state[0x2f3] = 0;
                state[0x2f4] = 0;
                if (*(f32*)(state + 0x310) > lbl_803E2798)
                {
                    state[0x323] = 1;
                    ObjAnim_SetCurrentMove((int)obj, tbl0[0x20], lbl_803E2740, 0);
                }
                else
                {
                    state[0x323] = 1;
                    ObjAnim_SetCurrentMove((int)obj, tbl0[0x14], lbl_803E2740, 0);
                }
            }
            else
            {
                state[0x2f2] = 0;
                state[0x2f3] = 0;
                state[0x2f4] = 0;
                state[0x323] = 1;
                *(f32*)(state + 0x308) = lbl_803E279C;
                ObjAnim_SetCurrentMove((int)obj, tbl0[8], lbl_803E2740, 0);
                *(f32*)(state + 0x310) = lbl_803E2740;
            }
        }
        fn_8014CF7C(obj, state, path->posX, path->posZ, 0xf, 0);
    }
    else
    {
        if (state[0x33d] == 0 && (flags & 0x40000000))
        {
            u8 r = randomGetRange(1, tbl4[8]);
            if (*(u16*)(state + 0x338) != 0)
            {
                {
                    SeqRow16* seqRow16 = (SeqRow16*)tbl1c;
                    state[0x2f2] = (u8)seqRow16[*(u16*)(state + 0x338)].extra;
                    Baddie_SetMove(obj, state,
                                seqRow16[*(u16*)(state + 0x338)].anim,
                                *(f32*)(tbl1c + *(u16*)(state + 0x338) * 16), 0,
                                (u8)seqRow16[*(u16*)(state + 0x338)].flags);
                }
                ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
                    (ObjAnimComponent*)obj,
                    *(f32*)(lbl_8031DD30 + tbl1c[*(u16*)(state + 0x338) * 16 + 8] * 4));
                *(u16*)(state + 0x338) = tbl1c[*(u16*)(state + 0x338) * 16 + 9];
            }
            else
            {
                int off;
                IdleRow* row;
                if (((GameObject*)obj)->anim.currentMove != (r = (row = (IdleRow*)(tbl4 + (off = r * 12)))->anim) || r != 0)
                {
                    state[0x2f2] = 0;
                    state[0x2f3] = 0;
                    state[0x2f4] = 0;
                    Baddie_SetMove(obj, state, row->anim, *(f32*)(tbl4 + off), 0, 3);
                    ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj,
                                            *(f32*)(lbl_8031DD30 + row->anim * 4));
                }
            }
        }
    }
}
