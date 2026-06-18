#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"

extern int GameBit_Set(int bit, int value);
extern int Sfx_PlayFromObject(void* obj, int sfxId);
extern void fn_8001FEA8(void);
extern void fn_8015039C(void* p1, void* p2);
extern u32 fn_8014FFB4(void* p1, void* p2, int p3);
extern void fn_8014CF7C(void* p1, void* p2, f32 f1, f32 f2, int p5, int p6);

extern u8 lbl_8031DD30[];

typedef struct
{
    f32 speed; /* 0x0 */
    u32 flags; /* 0x4 */
    u8 anim; /* 0x8 */
    u8 next; /* 0x9 */
    u8 alt; /* 0xa */
    u8 padB; /* 0xb */
    u32 extra; /* 0xc */
} SeqRow16;

typedef struct
{
    f32 speed; /* 0x0 */
    u32 unk4; /* 0x4 */
    u8 anim; /* 0x8 */
    u8 pad9; /* 0x9 */
    u8 padA; /* 0xa */
    u8 padB; /* 0xb */
} SeqRow12;

extern f32 timeDelta;
extern const f32 lbl_803E2740;
extern f32 lbl_803E274C;
extern f32 lbl_803E2768;
extern f32 lbl_803E276C;
extern f32 lbl_803E27A0;

extern u8 lbl_8031F16C[];

extern void sidekickToy_updateCurveTargetLatch(int* obj);
extern int Curve_AdvanceAlongPath(RomCurveWalker* curve, f32 t);
extern f32 sqrtf(f32 x);
extern int getAngle(f32 a, f32 b);
extern u32 randomGetRange(int min, int max);
extern f32 lbl_803E2748;
extern f32 lbl_803E2754;
extern f32 lbl_803E2778;
extern f32 lbl_803E277C;
extern f32 lbl_803E2780;
extern f32 lbl_803E2784;
extern f32 lbl_803E2788;
extern f32 lbl_803E278C;
extern f32 lbl_803E2790;
extern f32 lbl_803E2794;
extern f32 lbl_803E2798;
extern f32 lbl_803E279C;

int fn_801504F8(int* obj, u8* state, int* p3, int msgId, int arrIdx, int p6)
{
    u8* base = lbl_8031F16C;
    SeqRow12* animRows = *(SeqRow12**)(base + state[0x33b] * 0x28 + 0x10);
    SeqRow12* rowsC = *(SeqRow12**)(base + state[0x33b] * 0x28 + 0x24);
    SeqRow16* rowsB = *(SeqRow16**)(base + state[0x33b] * 0x28 + 0x1c);
    u8* trig = *(u8**)(base + state[0x33b] * 0x28 + 0x20);
    int ret = 0;

    if (state[0x33b] == 5)
    {
        ((BaddieState*)state)->reactionFlags |= 0x10;
        return 0;
    }
    if (msgId == 0xe)
    {
        p6 = p6 * 0xa;
    }
    if (((GameObject*)obj)->anim.currentMove == ((u8*)animRows)[0x128])
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
            if (msgId != 0x1a && ((GameObject*)p3)->anim.seqId != 0x6d &&
                ((GameObject*)p3)->anim.seqId != 0x754)
            {
                Sfx_PlayFromObject(obj, 0x255);
                Sfx_PlayFromObject(obj, 0x16);
            }
            ((BaddieState*)state)->reactionFlags |= 0x10;
            Baddie_SetMove(obj, state, rowsC[state[0x33c]].anim,
                        rowsC[state[0x33c]].speed, 0,
                        (u8)rowsC[state[0x33c]].unk4);
            ObjAnim_SetMoveProgress(
                *(f32*)(lbl_8031DD30 + rowsC[state[0x33c]].anim * 4),
                (ObjAnimComponent*)obj);
            if (rowsC[state[0x33c]].padA != 0)
            {
                state[0x33a] = rowsC[state[0x33c]].padA;
            }
            ret = rowsC[state[0x33c]].pad9;
            *(f32*)(state + 0x32c) = *(f32*)(state + 0x330);
            *(f32*)(state + 0x324) = lbl_803E2740;
            *(f32*)(state + 0x334) = lbl_803E2740;
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
            if (amount > 0x18)
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
            Baddie_SetMove(obj, state,
                        rowsB[rowsB[*(u16*)(state + 0x338)].padB].anim,
                        rowsB[rowsB[*(u16*)(state + 0x338)].padB].speed, 0,
                        (u8)rowsB[rowsB[*(u16*)(state + 0x338)].padB].flags);
            ObjAnim_SetMoveProgress(
                *(f32*)(lbl_8031DD30 +
                    rowsB[rowsB[*(u16*)(state + 0x338)].padB].anim * 4),
                (ObjAnimComponent*)obj);
        }
        else
        {
            u8 ai = (u8)amount;

            Baddie_SetMove(obj, state, animRows[ai].anim, animRows[ai].speed, 0,
                        (u8)animRows[ai].unk4);
            ObjAnim_SetMoveProgress(*(f32*)(lbl_8031DD30 + animRows[ai].anim * 4),
                                    (ObjAnimComponent*)obj);
            *(u16*)(state + 0x338) = animRows[ai].pad9;
            *(f32*)(state + 0x328) = (f32)(u32) * (u16*)(state + 0x2ec);
        }
        ((BaddieState*)state)->reactionFlags |= 8;
        if (((GameObject*)p3)->anim.classId == 0x1c)
        {
            return 0;
        }
        {
            int* other = (int*)((GameObject*)p3)->ownerObj;
            if (other != 0 && ((GameObject*)other)->anim.classId == 0x1c)
            {
                return 0;
            }
        }
        if (state[0x2f1] & 0x10)
        {
            p6 = 0x14;
        }
        else
        {
            state[0x2f5] = 0;
        }
        if (p6 > ((BaddieState*)state)->hitCounter)
        {
            ((BaddieState*)state)->hitCounter = 0;
        }
        else
        {
            ((BaddieState*)state)->hitCounter = ((BaddieState*)state)->hitCounter - p6;
        }
        if (((BaddieState*)state)->hitCounter == 0)
        {
            Sfx_PlayFromObject(obj, 0x13);
        }
        else
        {
            Sfx_PlayFromObject(obj, 0x14);
        }
        if (msgId != 0x1a && msgId != 0x1f && ((GameObject*)p3)->anim.seqId != 0x6d &&
            ((GameObject*)p3)->anim.seqId != 0x754)
        {
            Sfx_PlayFromObject(obj, 0x22);
        }
    }
    return ret;
}

void fn_80150EDC(void* p1, void* p2)
{
    u8* table = lbl_8031DD30;
    u8 idx = ((BaddieState*)p2)->inWhirlpoolGroup;
    u8* entry = table + idx * 0x28;
    void* r30 = *(void**)(entry + 0x143c);
    void* r29 = *(void**)(entry + 0x1454);
    SeqRow16* r28 = *(SeqRow16**)(entry + 0x1458);

    if (idx == 5 && (((BaddieState*)p2)->controlFlags & 0x800000) != 0)
    {
        GameBit_Set(0x1c8, 1);
    }

    if (((BaddieState*)p2)->trackedObj != NULL &&
        ((GameObject*)((BaddieState*)p2)->trackedObj)->anim.classId == 1)
    {
        fn_8001FEA8();
    }

    fn_8015039C(p1, p2);

    {
        f32 zero = lbl_803E2740;
        if (*(f32*)((u8*)p2 + 0x328) != zero &&
        *(u16*)((u8*)p2 + 0x338) != 0)
    {
        *(f32*)((u8*)p2 + 0x328) = *(f32*)((u8*)p2 + 0x328) - timeDelta;
        if (*(f32*)((u8*)p2 + 0x328) <= zero)
        {
            *(f32*)((u8*)p2 + 0x328) = zero;
            ((BaddieState*)p2)->controlFlags |= 0x40000000LL;
            *(u16*)((u8*)p2 + 0x338) = r28[*(u16*)((u8*)p2 + 0x338)].alt;
        }
    }
    }

    if ((u8)fn_8014FFB4(p1, p2, 0) != 0)
    {
        return;
    }

    if ((((BaddieState*)p2)->controlFlags & 0x20000000) != 0 &&
        (*(u32*)((u8*)p2 + 0x2e0) & 0x20000000) == 0)
    {
        Sfx_PlayFromObject(p1, SFXdn_boar5_c);
        ((BaddieState*)p2)->controlFlags |= 0x40000000LL;
    }

    if ((((BaddieState*)p2)->controlFlags & 0x40000000) != 0)
    {
        u16 cur338 = *(u16*)((u8*)p2 + 0x338);
        if (cur338 != 0)
        {
            *(u8*)((u8*)p2 + 0x2f2) = (u8)r28[cur338].extra;
            Baddie_SetMove(p1, p2, r28[*(u16*)((u8*)p2 + 0x338)].anim,
                        r28[*(u16*)((u8*)p2 + 0x338)].speed, 0,
                        (u8)r28[*(u16*)((u8*)p2 + 0x338)].flags);
            ObjAnim_SetMoveProgress(
                *(f32*)(table + (r28[*(u16*)((u8*)p2 + 0x338)].anim << 2)),
                (ObjAnimComponent*)p1);
            *(u16*)((u8*)p2 + 0x338) =
                r28[*(u16*)((u8*)p2 + 0x338)].next;
        }
        else
        {
            SeqRow12* r29rows = (SeqRow12*)r29;
            u8 v8;
            *(u8*)((u8*)p2 + 0x2f2) = 0;
            *(u8*)((u8*)p2 + 0x2f3) = 0;
            *(u8*)((u8*)p2 + 0x2f4) = 0;
            v8 = r29rows[*(u16*)((u8*)p2 + 0x2a0)].anim;
            if (v8 == 0)
            {
                *(u8*)((u8*)p2 + 0x323) = 3;
                ObjAnim_SetCurrentMove((int)p1, *(u8*)((u8*)r30 + 0x2c), lbl_803E2740, 0);
            }
            else
            {
                Baddie_SetMove(p1, p2, v8,
                            r29rows[*(u16*)((u8*)p2 + 0x2a0)].speed, 0, 0xb);
                ObjAnim_SetMoveProgress(
                    *(f32*)(table + (r29rows[*(u16*)((u8*)p2 + 0x2a0)].anim << 2)),
                    (ObjAnimComponent*)p1);
            }
        }
    }

    if ((s32)((GameObject*)p1)->anim.currentMove == *(u8*)((u8*)r30 + 0x2c))
    {
        ((BaddieState*)p2)->unk308 =
            ((BaddieState*)p2)->pathStep *
            (((f32)(u32) * (u16*)((u8*)p2 + 0x2a4) /
                    ((BaddieState*)p2)->unk2A8 / lbl_803E274C) *
                ((f32*)(table + 0x1538))[((BaddieState*)p2)->inWhirlpoolGroup]);
        if (((BaddieState*)p2)->unk308 < lbl_803E27A0)
        {
            ((BaddieState*)p2)->unk308 = lbl_803E27A0;
        }
    }

    if ((*(u8*)((u8*)p2 + 0x323) & 8) == 0)
    {
        void* p_29c = ((BaddieState*)p2)->trackedObj;
        fn_8014CF7C(p1, p2, ((GameObject*)p_29c)->anim.localPosX,
                    ((GameObject*)p_29c)->anim.localPosZ, 0xf, 0);
    }
}

/* EN v1.0 0x80150910  size: 1484b  sidekick-toy main update: timer-driven
 * 16-stride anim chain, curve chase with speed/turn shaping, idle anims. */

void fn_80150910(int* obj, u8* state)
{
    RomCurveWalker* path = *(RomCurveWalker**)state;
    u8* base = lbl_8031F16C;
    SeqRow12* tbl4 = *(SeqRow12**)(base + state[0x33b] * 0x28 + 4);
    u8* tbl0 = *(u8**)(base + state[0x33b] * 0x28);
    SeqRow16* tbl1c = *(SeqRow16**)(base + state[0x33b] * 0x28 + 0x1c);
    u32 flags;

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
                ((BaddieState*)state)->controlFlags |= 0x40000000LL;
                *(u16*)(state + 0x338) = tbl1c[*(u16*)(state + 0x338)].alt;
            }
        }
    }
    if ((u8)fn_8014FFB4(obj, state, 0) != 0)
    {
        return;
    }
    if (state[0x33d] != 0)
    {
        if (((BaddieState*)state)->controlFlags & 0x40000000)
        {
            f32 z = lbl_803E2740;
            ((GameObject*)obj)->anim.velocityZ = z;
            ((GameObject*)obj)->anim.velocityY = z;
            ((GameObject*)obj)->anim.velocityX = z;
            Baddie_SetMove(obj, state, tbl4[state[0x33d]].anim,
                        tbl4[state[0x33d]].speed, 0,
                        (u8)tbl4[state[0x33d]].unk4);
            ObjAnim_SetMoveProgress(*(f32*)(lbl_8031DD30 + tbl4[state[0x33d]].anim * 4),
                                    (ObjAnimComponent*)obj);
            state[0x33d] = tbl4[state[0x33d]].pad9;
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
            f32 spd = (lbl_803E2778 - d) * lbl_803E277C;
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
            (u16) * (s16*)obj);
        if (delta > lbl_803E2788)
        {
            delta = lbl_803E2784 + delta;
        }
        if (delta < lbl_803E2790)
        {
            delta = lbl_803E278C + delta;
        }
        *(f32*)(state + 0x308) =
            (((BaddieState*)state)->pathStep - *(f32*)(state + 0x310)) / lbl_803E274C *
            (lbl_803E2748 - ((delta >= lbl_803E2740) ? delta : -delta) / lbl_803E278C);
        if (*(f32*)(state + 0x308) < lbl_803E2754)
        {
            *(f32*)(state + 0x308) = lbl_803E2754;
        }
        if ((((BaddieState*)state)->controlFlags & 0x40000000) && state[0x33d] == 0)
        {
            if (*(u16*)(state + 0x338) != 0)
            {
                Baddie_SetMove(obj, state, tbl1c[*(u16*)(state + 0x338)].anim,
                            tbl1c[*(u16*)(state + 0x338)].speed, 0,
                            (u8)tbl1c[*(u16*)(state + 0x338)].flags);
                ObjAnim_SetMoveProgress(
                    *(f32*)(lbl_8031DD30 + tbl1c[*(u16*)(state + 0x338)].anim * 4),
                    (ObjAnimComponent*)obj);
                *(u16*)(state + 0x338) = tbl1c[*(u16*)(state + 0x338)].next;
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
            u8 r = (u8)randomGetRange(1, ((u8*)tbl4)[8]);
            if (*(u16*)(state + 0x338) != 0)
            {
                state[0x2f2] = (u8)tbl1c[*(u16*)(state + 0x338)].extra;
                Baddie_SetMove(obj, state, tbl1c[*(u16*)(state + 0x338)].anim,
                            tbl1c[*(u16*)(state + 0x338)].speed, 0,
                            (u8)tbl1c[*(u16*)(state + 0x338)].flags);
                ObjAnim_SetMoveProgress(
                    *(f32*)(lbl_8031DD30 + tbl1c[*(u16*)(state + 0x338)].anim * 4),
                    (ObjAnimComponent*)obj);
                *(u16*)(state + 0x338) = tbl1c[*(u16*)(state + 0x338)].next;
            }
            else
            {
                u8 ri = r;
                if (((GameObject*)obj)->anim.currentMove != tbl4[ri].anim || tbl4[ri].anim != 0)
                {
                    state[0x2f2] = 0;
                    state[0x2f3] = 0;
                    state[0x2f4] = 0;
                    Baddie_SetMove(obj, state, tbl4[ri].anim, tbl4[ri].speed, 0, 3);
                    ObjAnim_SetMoveProgress(*(f32*)(lbl_8031DD30 + tbl4[ri].anim * 4),
                                            (ObjAnimComponent*)obj);
                }
            }
        }
    }
}
