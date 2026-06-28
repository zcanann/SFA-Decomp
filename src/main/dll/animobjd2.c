/*
 * Tricky companion "circle the enemy" combat behaviour (part of the
 * tricky AI module; operates on TrickyState, the per-object scratch at
 * GameObject.extra).
 *
 * trickyFindCirclingTarget       - picks the object Tricky should circle:
 *                                   the current follow target if it is the
 *                                   special seqId 0x6a3 actor, else the
 *                                   player's lock-on target, validated
 *                                   against ObjGroup 3 by a triangle-
 *                                   inequality distance test.
 * trickyUpdateCirclingTargetPosition
 *                                - orbits Tricky around followObj: picks a
 *                                   random spin direction once, advances the
 *                                   orbit angle while it stays near the seed
 *                                   heading, and writes the desired
 *                                   x/y/z onto the state; trickyFn_8013b368
 *                                   then steers toward it.
 * fn_8013E0D0                    - the circling state machine, dispatched on
 *                                   substate ((TrickyState*)st)->substate (0 acquire, 1 approach,
 *                                   2/3/4 the special charge/spawn/finish
 *                                   path, 5 orbit-and-pick-best). It spawns
 *                                   helper objects (ids 0x17b, 0x4f0),
 *                                   plays/loops bark and effect sounds, and
 *                                   drives the shared TRICKY_* state macros.
 */
#include "main/dll/tricky_state.h"
#include "main/dll/player_target.h"
#include "main/game_object.h"
#include "main/objlib.h"
extern f32 Vec_xzDistance(f32* a, f32* b);
extern int randomGetRange(int lo, int hi);
extern float fsin16Precise(int angle);
extern float fcos16Precise(int angle);
extern int trickyFn_8013b368(void* p1, f32 radius, void* p2);
extern void* trickyFindNearestUsableBaddie(void* p, f32 r, int p3);
extern void objAnimFn_8013a3f0(int* obj, int anim, f32 p3, int p4);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int id);
extern int Obj_SetupObject(int o, int p2, int p3, int p4, int p5);
/* Sfx_* use int* obj / int sfx (not engine_shared.h's u32/u16) so the int* obj
   passed at the call sites needs no cast; including the header would conflict. */
extern void Sfx_PlayFromObject(int* obj, int sfx);
extern void Sfx_AddLoopedObjectSound(int* obj, int sfx);
extern void Sfx_RemoveLoopedObjectSound(int* obj, int sfx);
extern void objSetAnimSpeedTo1(int o);
extern int Sfx_IsPlayingFromObjectChannel(int* obj, int ch);
extern void objAudioFn_800393f8(int* obj, void* p2, int sfx, int p4, int p5, int p6);
extern f32 getXZDistance(f32* a, f32* b);
extern char lbl_8031D2E8[]; /* tricky debug format-string table */
extern const char sTrickyShouldNeverStopCirclingError[];
extern f32 timeDelta;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23F8;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E2418;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E2488;
extern f32 lbl_803E24A8;
extern f32 lbl_803E24D4;
extern f32 lbl_803E24D8;
extern f32 lbl_803E24DC;
extern f32 lbl_803E24E0;
extern f32 lbl_803E24E4;
extern f32 lbl_803E24E8;

#pragma dont_inline on
#pragma opt_common_subs off
void* trickyFindCirclingTarget(void* obj, void* arg2)
{
    void* target;
    void** list;
    int count;
    int i;
    f32 d1, d2, d3;

    target = *(void**)((u8*)arg2 + 0x24);
    if (((GameObject*)target)->anim.seqId == 0x6a3)
    {
        return target;
    }

    target = (void*)Player_GetTargetObject(*(int*)((u8*)arg2 + 0x4));
    if (target == NULL) goto fail;

    list = (void**)ObjGroup_GetObjects(3, &count);
    for (i = 0; i < count; i++)
    {
        if (list[i] == target)
        {
            d1 = Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX,
                                &((GameObject*)target)->anim.worldPosX);
            d2 = Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX,
                                &((GameObject*)*(void**)((u8*)arg2 + 0x4))->anim.worldPosX);
            d3 = Vec_xzDistance(&((GameObject*)target)->anim.worldPosX,
                                &((GameObject*)*(void**)((u8*)arg2 + 0x4))->anim.worldPosX);
            if ((d1 + d2) < lbl_803E23F8 * d3)
            {
                return target;
            }
            goto fail;
        }
    }
fail:
    return NULL;
}
#pragma opt_common_subs reset
#pragma dont_inline reset

void trickyUpdateCirclingTargetPosition(void* p1, void* p2)
{
    GameObject* obj = (GameObject*)p1;
    GameObject* target = *(GameObject**)&((TrickyState*)p2)->followObj;
    f32 dx = target->anim.worldPosX - obj->anim.worldPosX;
    f32 dz = target->anim.worldPosZ - obj->anim.worldPosZ;
    int angle = atan2_8002178c(dx, dz);
    s32 delta;
    s32 absDelta;

    if (((TrickyState*)p2)->substate == 0)
    {
        *(s32*)&((TrickyState*)p2)->unk700 = randomGetRange(0, 1);
        if (*(s32*)&((TrickyState*)p2)->unk700 == 0)
        {
            *(s32*)&((TrickyState*)p2)->unk700 = -1;
        }
        *(s32*)&((TrickyState*)p2)->unk704 = angle;
        ((TrickyState*)p2)->substate = 1;
    }

    delta = angle - (s32)(u16) * (volatile s32*)((u8*)p2 + 0x704);
    if (delta > 0x8000) delta -= 0xFFFF;
    if (delta < -0x8000) delta += 0xFFFF;

    if (delta >= 0)
    {
        absDelta = delta;
    }
    else
    {
        absDelta = -delta;
    }
    if (absDelta < 0x2000)
    {
        *(s32*)&((TrickyState*)p2)->unk704 =
            *(volatile s32*)((u8*)p2 + 0x704) + (*(s32*)&((TrickyState*)p2)->unk700 << 11);
    }

    *(f32*)&((TrickyState*)p2)->unk708 =
        (*(GameObject**)&((TrickyState*)p2)->followObj)->anim.worldPosX -
        lbl_803E24D4 * fsin16Precise((u16) * &((TrickyState*)p2)->unk704);
    *(f32*)&((TrickyState*)p2)->unk70C =
        (*(GameObject**)&((TrickyState*)p2)->followObj)->anim.worldPosY;
    ((TrickyState*)p2)->unk710 =
        (*(GameObject**)&((TrickyState*)p2)->followObj)->anim.worldPosZ -
        lbl_803E24D4 * fcos16Precise((u16) * &((TrickyState*)p2)->unk704);

    if (trickyFn_8013b368(p1, lbl_803E2488, p2) == 0)
    {
        trickyReportError(sTrickyShouldNeverStopCirclingError);
    }
}

typedef struct TrickyPackedSlots
{
    u8 a : 2;
    u8 b : 2;
    u8 c : 2;
    u8 d : 2;
} TrickyPackedSlots;

typedef struct
{
    u8 a : 1;
    u8 b : 1;
    u8 c : 6;
} TrickyCfgBits;

#define TRICKY_STATE_FLAGS_OFFSET 0x54
#define TRICKY_STATE_FLAG_4 0x4
#define TRICKY_STATE_FLAG_800 0x800
#define TRICKY_STATE_FLAG_1000 0x1000
#define TRICKY_STATE_FLAG_8000000 0x8000000
#define TRICKY_STATE_TARGET_DIRTY_FLAG 0x00000400LL
#define TRICKY_STATE_RESET_FLAG_10 0x00000010LL
#define TRICKY_STATE_RESET_FLAG_10000 0x00010000LL
#define TRICKY_STATE_RESET_FLAG_20000 0x00020000LL
#define TRICKY_STATE_RESET_FLAG_40000 0x00040000LL

#define TRICKY_RETARGET(st, X) \
    { \
        u32 px = (u32)&((GameObject *)(X))->anim.worldPosX; \
        if (*(u32 *)((st) + 0x28) != px) { \
            *(u32 *)((st) + 0x28) = px; \
            *(s32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_TARGET_DIRTY_FLAG; \
            *(u16 *)((st) + 0xd2) = 0; \
        } \
    }

#define TRICKY_RESET_TAIL(st) \
    { \
        f32 z = lbl_803E23DC; \
        *(f32 *)((st) + 0x71c) = z; \
        *(f32 *)((st) + 0x720) = z; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_RESET_FLAG_10; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_RESET_FLAG_10000; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_RESET_FLAG_20000; \
        *(u32 *)((st) + TRICKY_STATE_FLAGS_OFFSET) &= ~TRICKY_STATE_RESET_FLAG_40000; \
        *(s8 *)((st) + 0xd) = -1; \
    }
#define TRICKY_RESET(st) \
    *(u8 *)((st) + 8) = 1; \
    *(u8 *)((st) + 0xa) = 0; \
    TRICKY_RESET_TAIL(st)

#define TRICKY_BARK(obj, snd, p4) \
    { \
        u8 *cfg = *(u8 **)((char *)(obj) + 0xb8); \
        if (!((TrickyCfgBits *)(cfg + 0x58))->b) { \
            s16 a0 = ((GameObject *)(obj))->anim.currentMove; \
            if (a0 >= 0x30 || a0 < 0x29) { \
                if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) { \
                    objAudioFn_800393f8(obj, cfg + 0x3a8, snd, p4, -1, 0); \
                } \
            } \
        } \
    }

#pragma opt_loop_invariants off
#pragma opt_common_subs off
void fn_8013E0D0(int* obj, register u8* st)
{
    char* str = lbl_8031D2E8;
    int* best = NULL;
    f32 bestd = lbl_803E23DC;

    switch (((TrickyState*)st)->substate)
    {
    case 0:
        {
            u8 ok;
            int go;
            trickyDebugPrint(str + 0x5a0);
            ok = trickyFn_8013b368(obj, lbl_803E24D4, st);
            if ((((TrickyState*)st)->followObj = trickyFindNearestUsableBaddie(*(void**)&((TrickyState*)st)->playerObj, lbl_803E24D8, 0)) != NULL)
            {
                TRICKY_RETARGET(st, *(int*)&((TrickyState*)st)->followObj);
                go = 1;
            }
            else
            {
                ((TrickyState*)st)->unk08 = 1;
                go = 0;
                ((TrickyState*)st)->substate = go;
                TRICKY_RESET_TAIL(st)
            }
            if (go != 0)
            {
                if (*(int*)&((TrickyState*)st)->unk728 == 0)
                {
                    {
                        void* ct = trickyFindCirclingTarget(obj, st);
                        *(void**)&((TrickyState*)st)->unk720 = ct;
                        if (ct != NULL)
                        {
                            *(int*)&((TrickyState*)st)->followObj = *(int*)&((TrickyState*)st)->unk720;
                            *(int*)&((TrickyState*)st)->unk724 = 0;
                            ((TrickyState*)st)->substate = 5;
                            break;
                        }
                    }
                }
                if (ok == 2)
                {
                    TRICKY_RESET(st);
                    break;
                }
                if (getXZDistance(&((GameObject*)obj)->anim.worldPosX,
                                  &((GameObject*)*(int*)&((TrickyState*)st)->followObj)->anim.worldPosX) < lbl_803E24DC)
                {
                    int b;
                    ((TrickyState*)st)->substate = 1;
                    ((TrickyState*)st)->unk71C = lbl_803E23DC;
                    b = lbl_803E23DC != ((TrickyState*)st)->waterLevel
                        && (lbl_803E2410 == ((TrickyState*)st)->unk2B0
                            || ((TrickyState*)st)->unk2B4 - ((TrickyState*)st)->unk2B0 > lbl_803E2414);
                    if (b != 0)
                    {
                        objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                        ((TrickyState*)st)->unk79C = lbl_803E2440;
                        ((TrickyState*)st)->unk838 = lbl_803E23DC;
                        trickyDebugPrint(str + 0x184);
                    }
                    else
                    {
                        objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                        trickyDebugPrint(str + 0x190);
                    }
                }
            }
            break;
        }
    case 1:
        {
            u8 ok;
            int go;
            trickyDebugPrint(str + 0x5b4, **(u8**)&((TrickyState*)st)->progressPtr, *(int*)&((TrickyState*)st)->unk728);
            ok = trickyFn_8013b368(obj, lbl_803E24D4, st);
            if ((((TrickyState*)st)->followObj = trickyFindNearestUsableBaddie(*(void**)&((TrickyState*)st)->playerObj, lbl_803E24D8, 0)) != NULL)
            {
                TRICKY_RETARGET(st, *(int*)&((TrickyState*)st)->followObj);
                go = 1;
            }
            else
            {
                ((TrickyState*)st)->unk08 = 1;
                go = 0;
                ((TrickyState*)st)->substate = go;
                TRICKY_RESET_TAIL(st)
            }
            if (go != 0)
            {
                if (*(int*)&((TrickyState*)st)->unk728 == 0)
                {
                    {
                        void* ct = trickyFindCirclingTarget(obj, st);
                        *(void**)&((TrickyState*)st)->unk720 = ct;
                        if (ct != NULL)
                        {
                            *(int*)&((TrickyState*)st)->followObj = *(int*)&((TrickyState*)st)->unk720;
                            *(int*)&((TrickyState*)st)->unk724 = 0;
                            ((TrickyState*)st)->substate = 5;
                            break;
                        }
                    }
                }
                if (ok == 2)
                {
                    TRICKY_RESET(st);
                    break;
                }
                if (ok == 0)
                {
                    objAnimFn_8013a3f0(obj, 0x33, lbl_803E243C, 0);
                }
                if (*(int*)&((TrickyState*)st)->unk728 != 0)
                {
                    if (**(u8**)&((TrickyState*)st)->progressPtr < 2)
                    {
                        *(int*)&((TrickyState*)st)->unk728 = 0;
                        if (Obj_IsLoadingLocked() != 0)
                        {
                            *(u32*)(st + TRICKY_STATE_FLAGS_OFFSET) |= TRICKY_STATE_FLAG_4;
                            TRICKY_RESET(st);
                            if (((TrickyState*)st)->child == NULL)
                            {
                                int o = Obj_AllocObjectSetup(0x20, 0x17b);
                                s8 slots[4];
                                int free_;
                                slots[0] = -1;
                                slots[1] = -1;
                                slots[2] = -1;
                                if (((TrickyState*)st)->unk7A8 != NULL)
                                {
                                    slots[((TrickyPackedSlots*)((char*)st + 0x7bc))->a] = 1;
                                }
                                if (((TrickyState*)st)->unk7B0 != NULL)
                                {
                                    slots[((TrickyPackedSlots*)((char*)st + 0x7bc))->b] = 1;
                                }
                                if (((TrickyState*)st)->child != NULL)
                                {
                                    slots[((TrickyPackedSlots*)((char*)st + 0x7bc))->c] = 1;
                                }
                                if (slots[0] == -1)
                                {
                                    free_ = 0;
                                }
                                else if (slots[1] == -1)
                                {
                                    free_ = 1;
                                }
                                else if (slots[2] == -1)
                                {
                                    free_ = 2;
                                }
                                else if (slots[3] == -1)
                                {
                                    free_ = 3;
                                }
                                else
                                {
                                    free_ = -1;
                                }
                                ((TrickyPackedSlots*)((char*)st + 0x7bc))->c = free_;
                                *(int*)&((TrickyState*)st)->child = Obj_SetupObject(o, 4, -1, -1,
                                                                      *(int*)&((GameObject*)obj)->anim.parent);
                                ObjLink_AttachChild((int)obj, *(int*)&((TrickyState*)st)->child, ((TrickyPackedSlots*)((char*)st + 0x7bc))->c);
                                {
                                    f32 z3 = lbl_803E23DC;
                                    ((TrickyState*)st)->unk7C0 = z3;
                                    ((TrickyState*)st)->unk7C4 = z3;
                                    ((TrickyState*)st)->unk7C8 = z3;
                                }
                            }
                        }
                    }
                    else
                    {
                        ((TrickyState*)st)->substate = 2;
                        break;
                    }
                }
                if (getXZDistance(&((GameObject*)obj)->anim.worldPosX,
                                  &((GameObject*)*(int*)&((TrickyState*)st)->followObj)->anim.worldPosX) > lbl_803E24E0)
                {
                    ((TrickyState*)st)->substate = 0;
                    break;
                }
                ((TrickyState*)st)->unk71C -= timeDelta;
                if (((TrickyState*)st)->unk71C < lbl_803E23DC)
                {
                    ((TrickyState*)st)->unk71C = (f32)(s32)
                    randomGetRange(0xc8, 0x258) * lbl_803E24A8;
                    TRICKY_BARK(obj, 0x29b, 0x1000);
                }
            }
            break;
        }
    case 2:
        {
            u8 ok;
            int go;
            trickyDebugPrint(str + 0x5cc);
            ok = trickyFn_8013b368(obj, lbl_803E24E4, st);
            if ((((TrickyState*)st)->followObj = trickyFindNearestUsableBaddie(*(void**)&((TrickyState*)st)->playerObj, lbl_803E24D8, 0)) != NULL)
            {
                TRICKY_RETARGET(st, *(int*)&((TrickyState*)st)->followObj);
                go = 1;
            }
            else
            {
                ((TrickyState*)st)->unk08 = 1;
                go = 0;
                ((TrickyState*)st)->substate = go;
                TRICKY_RESET_TAIL(st)
            }
            if (go != 0 && ok != 1)
            {
                objAnimFn_8013a3f0(obj, 0x34, lbl_803E2444, 0x4000000);
                *(u32*)(st + TRICKY_STATE_FLAGS_OFFSET) |= 0x10;
                ((TrickyState*)st)->substate = 3;
                *(int*)&((TrickyState*)st)->unk728 = 0;
            }
            break;
        }
    case 3:
        if (((GameObject*)obj)->anim.currentMove != 0x34)
        {
            break;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E24E8)
        {
            if (Obj_IsLoadingLocked() != 0)
            {
                *(u32*)(st + TRICKY_STATE_FLAGS_OFFSET) |= TRICKY_STATE_FLAG_800;
                {
                    int i = 0;
                    u8* p = st;
                    for (; i < 7; i++)
                    {
                        int o = Obj_AllocObjectSetup(0x24, 0x4f0);
                        *(u8*)(o + 4) = 2;
                        *(u8*)(o + 5) = 1;
                        *(s16*)(o + 0x1a) = i;
                        *(int*)(p + 0x700) = Obj_SetupObject(o, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                                             *(int*)&((GameObject*)obj)->anim.parent);
                        p += 4;
                    }
                }
                Sfx_PlayFromObject(obj, 0x3db);
                Sfx_AddLoopedObjectSound(obj, 0x3dc);
            }
            **(u8**)&((TrickyState*)st)->progressPtr -= 2;
            ((TrickyState*)st)->substate = 4;
        }
        break;
    case 4:
        {
            u32 fl;
            trickyDebugPrint(str + 0x5e4);
            fl = *(u32*)(st + TRICKY_STATE_FLAGS_OFFSET);
            if (fl & TRICKY_STATE_FLAG_8000000)
            {
                *(u32*)(st + TRICKY_STATE_FLAGS_OFFSET) = fl & ~0x800LL;
                *(u32*)(st + TRICKY_STATE_FLAGS_OFFSET) |= TRICKY_STATE_FLAG_1000;
                {
                    int i = 0;
                    u8* p = st;
                    for (; i < 7; i++)
                    {
                        objSetAnimSpeedTo1(*(int*)(p + 0x700));
                        p += 4;
                    }
                }
                Sfx_RemoveLoopedObjectSound(obj, 0x3dc);
                TRICKY_BARK(obj, 0x29d, 0);
                *(u32*)(st + TRICKY_STATE_FLAGS_OFFSET) &= ~0x10LL;
                ((TrickyState*)st)->substate = 0;
            }
            break;
        }
    case 5:
        {
            int* t;
            void* found = trickyFindNearestUsableBaddie(*(void**)&((TrickyState*)st)->playerObj, lbl_803E24D8, 0);
            if (found != NULL && ((GameObject*)found)->anim.seqId == 0x6a3)
            {
                t = found;
            }
            else
            {
                t = (int*)Player_GetTargetObject(((TrickyState*)st)->playerObj);
            }
            if ((u32)t != *(u32*)&((TrickyState*)st)->unk720 || *(int*)&((TrickyState*)st)->unk728 != 0)
            {
                TRICKY_RETARGET(st, *(int*)&((TrickyState*)st)->followObj);
                ((TrickyState*)st)->substate = 0;
            }
            else
            {
                int count;
                int i = 0;
                void** list = (void**)ObjGroup_GetObjects(0x4b, &count);
                f32 ratio = lbl_803E23F8;
                for (; i < count; i++)
                {
                    f32 d1 = Vec_xzDistance(&((GameObject*)list[0])->anim.worldPosX,
                                            &((GameObject*)t)->anim.worldPosX);
                    f32 d2 = Vec_xzDistance(&((GameObject*)list[0])->anim.worldPosX,
                                            &((GameObject*)*(void**)&((TrickyState*)st)->playerObj)->anim.worldPosX);
                    f32 d3 = Vec_xzDistance(&((GameObject*)t)->anim.worldPosX,
                                            &((GameObject*)*(void**)&((TrickyState*)st)->playerObj)->anim.worldPosX);
                    if (d1 + d2 > ratio * d3)
                    {
                        f32 d4 = Vec_xzDistance(&((GameObject*)list[0])->anim.worldPosX,
                                                &((GameObject*)obj)->anim.worldPosX);
                        if (d2 - d4 > bestd)
                        {
                            bestd = d2 - d4;
                            best = list[0];
                        }
                    }
                    list++;
                }
                {
                    int* c = *(int**)&((TrickyState*)st)->unk724;
                    if (c != NULL && (((GameObject*)c)->objectFlags & 0x40))
                    {
                        *(int*)&((TrickyState*)st)->unk724 = 0;
                        TRICKY_RETARGET(st, ((TrickyState*)st)->playerObj);
                    }
                }
                if (best != NULL)
                {
                    /* unk724 NULL-checks kept raw: typing as ->unk724 shifts
                       saved-register coloring and regresses (the int reads/
                       stores below are byte-neutral as fields). */
                    if (*(void**)(st + 0x724) == NULL)
                    {
                        TRICKY_BARK(obj, 0x35b, 0x500);
                    }
                    if (*(void**)(st + 0x724) == NULL || *(int**)&((TrickyState*)st)->unk724 != best)
                    {
                        *(int**)&((TrickyState*)st)->unk724 = best;
                        TRICKY_RETARGET(st, *(int*)&((TrickyState*)st)->unk724);
                    }
                }
            }
            {
                u8 r;
                if (*(void**)(st + 0x724) != NULL)
                {
                    r = trickyFn_8013b368(obj, lbl_803E2488, st);
                }
                else
                {
                    r = trickyFn_8013b368(obj, lbl_803E2418, st);
                }
                if (r != 1)
                {
                    int b = lbl_803E23DC != ((TrickyState*)st)->waterLevel
                        && (lbl_803E2410 == ((TrickyState*)st)->unk2B0
                            || ((TrickyState*)st)->unk2B4 - ((TrickyState*)st)->unk2B0 > lbl_803E2414);
                    if (b != 0)
                    {
                        objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                        ((TrickyState*)st)->unk79C = lbl_803E2440;
                        ((TrickyState*)st)->unk838 = lbl_803E23DC;
                        trickyDebugPrint(str + 0x184);
                    }
                    else
                    {
                        objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                        trickyDebugPrint(str + 0x190);
                    }
                }
            }
            break;
        }
    }
}
