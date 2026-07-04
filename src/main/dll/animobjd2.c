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
#include "main/audio/sfx_trigger_ids.h"
#include "main/obj_placement.h"
#define ANIMOBJD2_OBJFLAG_FREED 0x40

/* fn_8013E0D0 circling substate machine (TrickyState.substate; this object's
 * own values, not a globally shared TrickyState enum). */
enum AnimObjD2Substate
{
    ANIMOBJD2_SUBSTATE_ACQUIRE = 0, /* find/lock onto a target        */
    ANIMOBJD2_SUBSTATE_APPROACH = 1, /* close on the seed heading      */
    ANIMOBJD2_SUBSTATE_CHARGE = 2,   /* retarget + start charge anim   */
    ANIMOBJD2_SUBSTATE_SPAWN = 3,    /* spawn the 7 drip helper objects*/
    ANIMOBJD2_SUBSTATE_FINISH = 4,   /* speed up helpers, bark, reset  */
    ANIMOBJD2_SUBSTATE_ORBIT = 5     /* orbit and pick the best target */
};

/* Spawn-setup buffer seeded in the substate-3 drip burst (defNo 0x4f0).
 * Reuses ObjPlacement's color head and adds the class-specific index at
 * 0x1a; store widths per target asm (stb color, sth index). */
typedef struct AnimObjD2DripSetup
{
    ObjPlacement head; /* 0x00: color[0..1] written */
    u8 pad18[0x1a - 0x18];
    s16 index;         /* 0x1a */
} AnimObjD2DripSetup;
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

void* trickyFindCirclingTarget(void* obj, void* arg2);

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
            *(s16 *)((st) + 0xd2) = 0; \
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
        *(u8 *)((st) + 0xd) = 0xFF; \
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
void fn_8013E0D0(int* obj, u8* st)
{
    GameObject* gobj = (GameObject*)obj;
    TrickyState* t = (TrickyState*)st;
    char* str = lbl_8031D2E8;
    int* best = NULL;
    f32 bestd = lbl_803E23DC;
    int count;

    switch (t->substate)
    {
    case ANIMOBJD2_SUBSTATE_ACQUIRE:
        {
            u8 ok;
            int go;
            trickyDebugPrint(str + 0x5a0);
            ok = trickyFn_8013b368(gobj, lbl_803E24D4, t);
            if ((t->followObj = trickyFindNearestUsableBaddie(*(void**)&t->playerObj, lbl_803E24D8, 0)) != NULL)
            {
                TRICKY_RETARGET((u8*)t, *(int*)&t->followObj);
                go = 1;
            }
            else
            {
                t->unk08 = 1;
                go = 0;
                t->substate = go;
                TRICKY_RESET_TAIL((u8*)t)
            }
            if (go != 0)
            {
                if (*(int*)&t->unk728 == 0)
                {
                    {
                        void* ct = trickyFindCirclingTarget(gobj, t);
                        *(void**)&t->unk720 = ct;
                        if (ct != NULL)
                        {
                            *(int*)&t->followObj = *(int*)&t->unk720;
                            *(int*)&t->unk724 = 0;
                            t->substate = ANIMOBJD2_SUBSTATE_ORBIT;
                            break;
                        }
                    }
                }
                if (ok == 2)
                {
                    TRICKY_RESET((u8*)t);
                    break;
                }
                if (getXZDistance(&gobj->anim.worldPosX,
                                  &((GameObject*)*(int*)&t->followObj)->anim.worldPosX) < lbl_803E24DC)
                {
                    int b;
                    f32 z;
                    t->substate = ANIMOBJD2_SUBSTATE_APPROACH;
                    b = 1;
                    z = lbl_803E23DC;
                    t->unk71C = z;
                    if (z == t->waterLevel)
                    {
                        b = 0;
                    }
                    else if (lbl_803E2410 != t->eventTime
                             && !(t->currentTime - t->eventTime > lbl_803E2414))
                    {
                        b = 0;
                    }
                    if (b != 0)
                    {
                        objAnimFn_8013a3f0((int*)gobj, 8, lbl_803E243C, 0);
                        t->unk79C = lbl_803E2440;
                        t->unk838 = lbl_803E23DC;
                        trickyDebugPrint(str + 0x184);
                    }
                    else
                    {
                        objAnimFn_8013a3f0((int*)gobj, 0, lbl_803E2444, 0);
                        trickyDebugPrint(str + 0x190);
                    }
                }
            }
            break;
        }
    case ANIMOBJD2_SUBSTATE_APPROACH:
        {
            u8 ok;
            int go;
            trickyDebugPrint(str + 0x5b4, **(u8**)&t->progressPtr, *(int*)&t->unk728);
            ok = trickyFn_8013b368(gobj, lbl_803E24D4, t);
            if ((t->followObj = trickyFindNearestUsableBaddie(*(void**)&t->playerObj, lbl_803E24D8, 0)) != NULL)
            {
                TRICKY_RETARGET((u8*)t, *(int*)&t->followObj);
                go = 1;
            }
            else
            {
                t->unk08 = 1;
                go = 0;
                t->substate = go;
                TRICKY_RESET_TAIL((u8*)t)
            }
            if (go != 0)
            {
                if (*(int*)&t->unk728 == 0)
                {
                    {
                        void* ct = trickyFindCirclingTarget(gobj, t);
                        *(void**)&t->unk720 = ct;
                        if (ct != NULL)
                        {
                            *(int*)&t->followObj = *(int*)&t->unk720;
                            *(int*)&t->unk724 = 0;
                            t->substate = ANIMOBJD2_SUBSTATE_ORBIT;
                            break;
                        }
                    }
                }
                if (ok == 2)
                {
                    TRICKY_RESET((u8*)t);
                    break;
                }
                if (ok == 0)
                {
                    objAnimFn_8013a3f0((int*)gobj, 0x33, lbl_803E243C, 0);
                }
                if (*(int*)&t->unk728 != 0)
                {
                    if (**(u8**)&t->progressPtr < 2)
                    {
                        *(int*)&t->unk728 = 0;
                        if (Obj_IsLoadingLocked() != 0)
                        {
                            t->stateFlags |= TRICKY_STATE_FLAG_4;
                            TRICKY_RESET((u8*)t);
                            if (t->child == NULL)
                            {
                                int o = Obj_AllocObjectSetup(0x20, 0x17b);
                                s8 slots[4];
                                int free_;
                                slots[0] = -1;
                                slots[1] = -1;
                                slots[2] = -1;
                                if (t->unk7A8 != NULL)
                                {
                                    slots[((TrickyPackedSlots*)((char*)t + 0x7bc))->a] = 1;
                                }
                                if (t->unk7B0 != NULL)
                                {
                                    slots[((TrickyPackedSlots*)((char*)t + 0x7bc))->b] = 1;
                                }
                                if (t->child != NULL)
                                {
                                    slots[((TrickyPackedSlots*)((char*)t + 0x7bc))->c] = 1;
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
                                ((TrickyPackedSlots*)((char*)t + 0x7bc))->c = free_;
                                *(int*)&t->child = Obj_SetupObject(o, 4, -1, -1,
                                                                      *(int*)&gobj->anim.parent);
                                ObjLink_AttachChild((int)gobj, *(int*)&t->child, ((TrickyPackedSlots*)((char*)t + 0x7bc))->c);
                                {
                                    f32 z3 = lbl_803E23DC;
                                    t->unk7C0 = z3;
                                    t->unk7C4 = z3;
                                    t->unk7C8 = z3;
                                }
                            }
                        }
                    }
                    else
                    {
                        t->substate = ANIMOBJD2_SUBSTATE_CHARGE;
                        break;
                    }
                }
                if (getXZDistance(&gobj->anim.worldPosX,
                                  &((GameObject*)*(int*)&t->followObj)->anim.worldPosX) > lbl_803E24E0)
                {
                    t->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
                    break;
                }
                t->unk71C -= timeDelta;
                if (t->unk71C < lbl_803E23DC)
                {
                    t->unk71C = (f32)(s32)
                    randomGetRange(0xc8, 0x258) * lbl_803E24A8;
                    TRICKY_BARK((int*)gobj, 0x29b, 0x1000);
                }
            }
            break;
        }
    case ANIMOBJD2_SUBSTATE_CHARGE:
        {
            u8 ok;
            int go;
            trickyDebugPrint(str + 0x5cc);
            ok = trickyFn_8013b368(gobj, lbl_803E24E4, t);
            if ((t->followObj = trickyFindNearestUsableBaddie(*(void**)&t->playerObj, lbl_803E24D8, 0)) != NULL)
            {
                TRICKY_RETARGET((u8*)t, *(int*)&t->followObj);
                go = 1;
            }
            else
            {
                t->unk08 = 1;
                go = 0;
                t->substate = go;
                TRICKY_RESET_TAIL((u8*)t)
            }
            if (go != 0 && ok != 1)
            {
                objAnimFn_8013a3f0((int*)gobj, 0x34, lbl_803E2444, 0x4000000);
                t->stateFlags |= TRICKY_STATE_RESET_FLAG_10;
                t->substate = ANIMOBJD2_SUBSTATE_SPAWN;
                *(int*)&t->unk728 = 0;
            }
            break;
        }
    case ANIMOBJD2_SUBSTATE_SPAWN:
        if (gobj->anim.currentMove != 0x34)
        {
            break;
        }
        if (gobj->anim.currentMoveProgress > lbl_803E24E8)
        {
            if (Obj_IsLoadingLocked() != 0)
            {
                t->stateFlags |= TRICKY_STATE_FLAG_800;
                {
                    int i = 0;
                    u8* p = (u8*)t;
                    for (; i < 7; i++)
                    {
                        int o = Obj_AllocObjectSetup(0x24, 0x4f0);
                        ((AnimObjD2DripSetup*)o)->head.color[0] = 2;
                        ((AnimObjD2DripSetup*)o)->head.color[1] = 1;
                        ((AnimObjD2DripSetup*)o)->index = i;
                        *(int*)(p + 0x700) = Obj_SetupObject(o, 5, gobj->anim.mapEventSlot, -1,
                                                             *(int*)&gobj->anim.parent);
                        p += 4;
                    }
                }
                Sfx_PlayFromObject((int*)gobj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound((int*)gobj, SFXTRIG_trpopn_c);
            }
            **(u8**)&t->progressPtr -= 2;
            t->substate = ANIMOBJD2_SUBSTATE_FINISH;
        }
        break;
    case ANIMOBJD2_SUBSTATE_FINISH:
        {
            u32 fl;
            trickyDebugPrint(str + 0x5e4);
            fl = t->stateFlags;
            if (fl & TRICKY_STATE_FLAG_8000000)
            {
                t->stateFlags = fl & ~(u64)TRICKY_STATE_FLAG_800;
                t->stateFlags |= TRICKY_STATE_FLAG_1000;
                {
                    u8* p;
                    int i = 0;
                    p = (u8*)t;
                    for (; i < 7; i++)
                    {
                        objSetAnimSpeedTo1(*(int*)(p + 0x700));
                        p += 4;
                    }
                }
                Sfx_RemoveLoopedObjectSound((int*)gobj, SFXTRIG_trpopn_c);
                TRICKY_BARK((int*)gobj, 0x29d, 0);
                t->stateFlags &= ~TRICKY_STATE_RESET_FLAG_10;
                t->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
            }
            break;
        }
    case ANIMOBJD2_SUBSTATE_ORBIT:
        {
            void** p;
            int* tgt;
            void* found = trickyFindNearestUsableBaddie(*(void**)&t->playerObj, lbl_803E24D8, 0);
            if (found != NULL && ((GameObject*)found)->anim.seqId == 0x6a3)
            {
                tgt = found;
            }
            else
            {
                tgt = (int*)Player_GetTargetObject(t->playerObj);
            }
            if ((u32)tgt != *(u32*)&t->unk720 || *(int*)&t->unk728 != 0)
            {
                TRICKY_RETARGET((u8*)t, *(int*)&t->followObj);
                t->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
            }
            else
            {
                void** list = (void**)ObjGroup_GetObjects(0x4b, &count);
                int i = 0;
                f32 ratio;
                p = list;
                ratio = lbl_803E23F8;
                for (; i < count; i++)
                {
                    f32 d1 = Vec_xzDistance(&((GameObject*)p[0])->anim.worldPosX,
                                            &((GameObject*)tgt)->anim.worldPosX);
                    f32 d2 = Vec_xzDistance(&((GameObject*)p[0])->anim.worldPosX,
                                            &((GameObject*)*(void**)&t->playerObj)->anim.worldPosX);
                    f32 d3 = Vec_xzDistance(&((GameObject*)tgt)->anim.worldPosX,
                                            &((GameObject*)*(void**)&t->playerObj)->anim.worldPosX);
                    if (d1 + d2 > ratio * d3)
                    {
                        f32 d4 = Vec_xzDistance(&((GameObject*)p[0])->anim.worldPosX,
                                                &gobj->anim.worldPosX);
                        if (d2 - d4 > bestd)
                        {
                            bestd = d2 - d4;
                            best = p[0];
                        }
                    }
                    p++;
                }
                {
                    int* c = *(int**)&t->unk724;
                    if (c != NULL && (((GameObject*)c)->objectFlags & ANIMOBJD2_OBJFLAG_FREED))
                    {
                        *(int*)&t->unk724 = 0;
                        TRICKY_RETARGET((u8*)t, t->playerObj);
                    }
                }
                if (best != NULL)
                {
                    /* unk724 NULL-checks kept raw: typing as ->unk724 shifts
                       saved-register coloring and regresses (the int reads/
                       stores below are byte-neutral as fields). */
                    if (*(void**)((u8*)t + 0x724) == NULL)
                    {
                        TRICKY_BARK((int*)gobj, 0x35b, 0x500);
                    }
                    if (*(void**)((u8*)t + 0x724) == NULL || *(int**)&t->unk724 != best)
                    {
                        *(int**)&t->unk724 = best;
                        TRICKY_RETARGET((u8*)t, *(int*)&t->unk724);
                    }
                }
            }
            {
                u8 r;
                if (*(void**)((u8*)t + 0x724) != NULL)
                {
                    r = trickyFn_8013b368(gobj, lbl_803E2488, t);
                }
                else
                {
                    r = trickyFn_8013b368(gobj, lbl_803E2418, t);
                }
                if (r != 1)
                {
                    int b;
                    if (lbl_803E23DC == t->waterLevel)
                    {
                        b = 0;
                    }
                    else if (lbl_803E2410 == t->eventTime)
                    {
                        b = 1;
                    }
                    else if (t->currentTime - t->eventTime > lbl_803E2414)
                    {
                        b = 1;
                    }
                    else
                    {
                        b = 0;
                    }
                    if (b != 0)
                    {
                        objAnimFn_8013a3f0((int*)gobj, 8, lbl_803E243C, 0);
                        t->unk79C = lbl_803E2440;
                        t->unk838 = lbl_803E23DC;
                        trickyDebugPrint(str + 0x184);
                    }
                    else
                    {
                        objAnimFn_8013a3f0((int*)gobj, 0, lbl_803E2444, 0);
                        trickyDebugPrint(str + 0x190);
                    }
                }
            }
            break;
        }
    }
}
#pragma opt_common_subs reset
#pragma opt_loop_invariants reset

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

    target = (void*)fn_80296118(*(int*)((u8*)arg2 + 0x4));
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

    if (((TrickyState*)p2)->substate == ANIMOBJD2_SUBSTATE_ACQUIRE)
    {
        *(s32*)&((TrickyState*)p2)->unk700 = randomGetRange(0, 1);
        if (*(s32*)&((TrickyState*)p2)->unk700 == 0)
        {
            *(s32*)&((TrickyState*)p2)->unk700 = -1;
        }
        *(s32*)&((TrickyState*)p2)->unk704 = angle;
        ((TrickyState*)p2)->substate = ANIMOBJD2_SUBSTATE_APPROACH;
    }

    delta = angle - (s32)(u16) * (s32*)((u8*)p2 + 0x704);
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
            *(s32*)((int)p2 + 0x704) + (*(s32*)&((TrickyState*)p2)->unk700 << 11);
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


const char sTrickyShouldNeverStopCirclingError[] = "error tricky should never stop when circling\n";
