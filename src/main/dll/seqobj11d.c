/*
 * seqobj11d - a family of ground/walking baddie variants sharing one
 * sequence-driven animation update. The variant is selected by anim.seqId
 * in fn_80151954 (init) into a 0..5 type index (state+0x33b) that selects
 * per-type tables (PTR_DAT_8031fd*, lbl_8031F16C entries) of movement
 * sequence entries (SeqEntry: anim id + reaction mask + colour bytes).
 *
 * The per-frame update walks those tables to pick the next animation,
 * stepping the seq-entry index (state+0x33a) until it finds an entry whose
 * reaction mask matches the baddie's control flags, then drives the model
 * (fn_8014D08C / ObjAnim_SetMoveProgress) and the hit-volume priority
 * (ObjHitsPriorityState). fn_801511E8 picks the next move when far from the
 * target; fn_801513AC steers toward a tracked object using getAngle.
 * fn_80151C68 is a pay-to-trigger interaction (spends 25 money, sets a
 * placement game bit, runs object trigger sequences). fn_80151DB8 pushes
 * the player out of a cylinder around the object. fn_80152004 plays a dirt
 * step sfx and sets a reaction flag. FUN_80151844 (still referenced by the
 * wisp baddie DLL) is a shared variant of the sequence stepper.
 */
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/dll/baddie_state.h"
#include "main/object_transform.h"
#include "main/objseq.h"
#include "main/dll/player_target.h"
#include "main/dll/VF/vf_shared.h"

typedef struct
{
    f32 speed;
    u32 mask;
    u8 anim;
    u8 pad9;
    u8 r;
    u8 g;
    u8 b;
    u8 pad13[3];
} SeqEntry;

/* Routines live in sibling baddie/seq TUs (fn_8014*, getAngle, math*,
   player*, hud, ObjModelChain). DAT_/lbl_/PTR_ are shared .data/.sdata
   tables and FP constants. */

extern u32 FUN_800305c4();
extern int FUN_8014c78c();
extern u32 FUN_8014d4c8();
extern void fn_8014D08C(int obj, u8* state, int a, f32 f, int b, int c);
extern int fn_8014C11C(int obj, f32 f, int a, int b, u8* tbl);
extern void fn_8015039C(int obj, u8* state);
extern u8 fn_8014FFB4(int obj, u8* state, int a);
extern void fn_8014CF7C(int obj, u8* state, f32 x, f32 z, int a, int b);
extern int playerGetMoney(void* player);
extern void playerAddMoney(u8* player, int amount);
extern void hudFn_8011f38c(u8 x);
extern float mathCosf(float x);
extern float mathSinf(float x);
extern f32 sqrtf(f32 x);
extern u32 DAT_8031e980;
extern u32 DAT_803ad088;
extern u32 DAT_803ad08c;
extern u32 DAT_803dc8f0;
extern void* PTR_DAT_8031fdc8;
extern char lbl_8031F16C[];
extern char lbl_8031DD30[];
extern u8 gGroundBaddieTargetSearchResult[];
extern u8 gGroundBaddieAngleSectorOffsets[8];
extern u16 gGroundBaddieTriggerResponseSeq[4];
extern f32 gGroundBaddieModelChainDesc;
extern f32 lbl_803E2740;
extern f32 lbl_803E2748;
extern f32 lbl_803E2754;
extern f32 lbl_803E3440;
extern f32 lbl_803E27A4;
extern f32 lbl_803E27A8;
extern f32 lbl_803E27AC;
extern f32 lbl_803E27B0;
extern f32 lbl_803E27B4;
extern f32 lbl_803E27B8;
extern f32 lbl_803E27BC;
extern f32 lbl_803E27C0;
extern f32 lbl_803E27C4;
extern f32 lbl_803E27C8;
extern f32 lbl_803E27CC;
extern f32 lbl_803E27D0;
extern f32 lbl_803E27D8;
extern f32 lbl_803E27DC;
extern f32 gGroundBaddiePi;
extern f32 gGroundBaddieAngleUnitScale;
extern f32 lbl_803E27E8;

#pragma scheduling on
#pragma peephole on

void FUN_80151844(u64 param_1, u64 param_2, double param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  short* obj, int state)
{
    short angleDelta;
    int entryOff;
    u32 angle;
    u32 in_r8;
    u32 in_r9;
    u32 in_r10;
    u8* entry;
    double speed;

    entry = (&PTR_DAT_8031fdc8)[(u32) * (u8*)(state + 0x33b) * 10];
    entryOff = FUN_8014c78c(obj, 1, 0x10, &DAT_803ad088);
    if (0 < entryOff)
    {
        if (((DAT_803ad08c < 0x29) && (*(short*)(state + 0x2a0) != 3)) &&
            (*(short*)(state + 0x2a0) != 4))
        {
            entryOff = FUN_80017730();
            angleDelta = entryOff - *obj;
            angle = angleDelta;
            if (0x8000 < angle)
            {
                angle = (u32)(short)(angleDelta + 1);
            }
            if ((short)angle < -0x8000)
            {
                angle = (u32)(short)((short)angle + -1);
            }
            ((GroundBaddieState*)state)->baddie.seqEntryIndex =
                entry[8] + (&DAT_803dc8f0)[(short)((angle & 0xffff) >> 0xd)];
        }
        else if (DAT_803ad08c < 0x47)
        {
            while ((entry[(u32) * (u8*)(state + 0x33a) * 0x10 + 10] & 1) != 0)
            {
                *(char*)&((GroundBaddieState*)state)->baddie.seqEntryIndex = *(char*)&((GroundBaddieState*)state)->baddie.seqEntryIndex + '\x01';
                if ((u8)entry[8] < *(u8*)(state + 0x33a))
                {
                    ((GroundBaddieState*)state)->baddie.seqEntryIndex = 1;
                }
            }
        }
    }
    speed = (double)(f32)(u32) * (u16*)(state + 0x2a4);
    if (speed < (double)(lbl_803E3440 * ((GroundBaddieState*)state)->baddie.speedScale))
    {
        *(char*)&((GroundBaddieState*)state)->baddie.seqEntryIndex = entry[8] + '\x01';
    }
    while (true)
    {
        if ((*(u32*)(entry + (u32) * (u8*)(state + 0x33a) * 0x10 + 4) == 0) ||
            ((((GroundBaddieState*)state)->baddie.controlFlags &
                *(u32*)(entry + (u32) * (u8*)(state + 0x33a) * 0x10 + 4)) != 0))
            break;
        *(char*)&((GroundBaddieState*)state)->baddie.seqEntryIndex = *(char*)&((GroundBaddieState*)state)->baddie.seqEntryIndex + '\x01';
        if ((u8)entry[8] < *(u8*)(state + 0x33a))
        {
            ((GroundBaddieState*)state)->baddie.seqEntryIndex = 1;
        }
    }
    *(u8*)(state + 0x2f2) = entry[(u32) * (u8*)(state + 0x33a) * 0x10 + 10];
    *(u8*)(state + 0x2f3) = entry[(u32) * (u8*)(state + 0x33a) * 0x10 + 0xb];
    *(u8*)(state + 0x2f4) = entry[(u32) * (u8*)(state + 0x33a) * 0x10 + 0xc];
    entryOff = (u32) * (u8*)(state + 0x33a) * 0x10;
    FUN_8014d4c8((double)*(float*)(entry + entryOff), speed, param_3, param_4, param_5, param_6, param_7,
                 param_8, obj, state, (u32)(u8)entry[entryOff + 8], 0, 3, in_r8, in_r9, in_r10);
    FUN_800305c4((double)*(float*)(&DAT_8031e980 +
                     (u32)(u8)entry[(u32) * (u8*)(state + 0x33a) * 0x10 + 8] *
                 4), obj
    )
    ;
    *(char*)&((GroundBaddieState*)state)->baddie.seqEntryIndex = *(char*)&((GroundBaddieState*)state)->baddie.seqEntryIndex + '\x01';
    if ((u8)entry[8] < *(u8*)(state + 0x33a))
    {
        ((GroundBaddieState*)state)->baddie.seqEntryIndex = 1;
    }
}

#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
void fn_801511E8(int obj, u8* state)
{
    u8* entry;
    u32 idx;
    char* base;

    base = lbl_8031F16C;
    base += state[0x33b] * 40;
    entry = *(u8**)(base + 12);
    if ((f32) * (u16*)(state + 0x2a4) > lbl_803E27A4 * ((GroundBaddieState*)state)->baddie.speedScale)
    {
        if ((f32) * (u16*)(state + 0x2a4) > lbl_803E27A8 * ((GroundBaddieState*)state)->baddie.speedScale)
        {
            state[0x33a] = (u8)(entry[8] + 2);
        }
        else
        {
            state[0x33a] = (u8)(entry[8] + 3);
        }
    }
    while (*(u32*)(entry + (idx = state[0x33a]) * 16 + 4) != 0
        && (((GroundBaddieState*)state)->baddie.controlFlags & *(u32*)(entry + idx * 16 + 4)) == 0)
    {
        (((GroundBaddieState*)state)->baddie.seqEntryIndex)++;
        if (state[0x33a] > entry[8])
        {
            state[0x33a] = 1;
        }
    }
    *(u8*)(state + 0x2f2) = (entry + state[0x33a] * 16)[10];
    *(u8*)(state + 0x2f3) = (entry + state[0x33a] * 16)[11];
    *(u8*)(state + 0x2f4) = (entry + state[0x33a] * 16)[12];
    fn_8014D08C(obj, state, (entry + state[0x33a] * 16)[8], ((SeqEntry*)(entry + state[0x33a] * 16))->speed, 0, 3);
    ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
        (ObjAnimComponent*)obj,
        *(f32*)(lbl_8031DD30 + entry[state[0x33a] * 16 + 8] * 4));
    (((GroundBaddieState*)state)->baddie.seqEntryIndex)++;
    if (state[0x33a] > entry[8])
    {
        state[0x33a] = 1;
    }
}
#pragma dont_inline reset

void fn_801513AC(int obj, u8* state)
{
    u8* entry;
    u32 idx;
    s16 d;
    char* base;

    base = lbl_8031F16C;
    base += state[0x33b] * 40;
    entry = *(u8**)(base + 12);
    if (fn_8014C11C(obj, lbl_803E27AC, 1, 16, gGroundBaddieTargetSearchResult) >= 1)
    {
        if (*(u16*)(gGroundBaddieTargetSearchResult + 4) <= 40
            && *(u16*)(state + 0x2a0) != 3
            && *(u16*)(state + 0x2a0) != 4)
        {
            d = getAngle(((GameObject*)obj)->anim.localPosX - *(f32*)(*(int*)gGroundBaddieTargetSearchResult + 0xc),
                         ((GameObject*)obj)->anim.localPosZ - *(f32*)(*(int*)gGroundBaddieTargetSearchResult + 0x14))
                - (u16)((GameObject*)obj)->anim.rotX;
            if (d > 0x8000)
            {
                d = (d - 0x10000) + 1;
            }
            if (d < -0x8000)
            {
                d = (d + 0x10000) - 1;
            }
            state[0x33a] = (u8)(gGroundBaddieAngleSectorOffsets[(s16)((u32)(u16)d >> 13)] + entry[8]);
        }
        else if (*(u16*)(gGroundBaddieTargetSearchResult + 4) <= 70)
        {
            while ((*(u8*)(entry + state[0x33a] * 16 + 10) & 1) != 0)
            {
                (((GroundBaddieState*)state)->baddie.seqEntryIndex)++;
                if (state[0x33a] > entry[8])
                {
                    state[0x33a] = 1;
                }
            }
        }
    }
    if ((f32) * (u16*)(state + 0x2a4) < lbl_803E27A8 * ((GroundBaddieState*)state)->baddie.speedScale)
    {
        state[0x33a] = (u8)(entry[8] + 1);
    }
    while (*(u32*)(entry + (idx = state[0x33a]) * 16 + 4) != 0
        && (((GroundBaddieState*)state)->baddie.controlFlags & *(u32*)(entry + idx * 16 + 4)) == 0)
    {
        (((GroundBaddieState*)state)->baddie.seqEntryIndex)++;
        if (state[0x33a] > entry[8])
        {
            state[0x33a] = 1;
        }
    }
    *(u8*)(state + 0x2f2) = (entry + state[0x33a] * 16)[10];
    *(u8*)(state + 0x2f3) = (entry + state[0x33a] * 16)[11];
    *(u8*)(state + 0x2f4) = (entry + state[0x33a] * 16)[12];
    fn_8014D08C(obj, state, (entry + state[0x33a] * 16)[8], ((SeqEntry*)(entry + state[0x33a] * 16))->speed, 0, 3);
    ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
        (ObjAnimComponent*)obj,
        *(f32*)(lbl_8031DD30 + entry[state[0x33a] * 16 + 8] * 4));
    (((GroundBaddieState*)state)->baddie.seqEntryIndex)++;
    if (state[0x33a] > entry[8])
    {
        state[0x33a] = 1;
    }
}

void fn_8015165C(int obj, u8* state)
{
    u8* player;
    u8* p20;
    u8* p28;
    u8 t;
    f32 tv;
    f32 fz;
    char* base;

    base = lbl_8031F16C;
    t = state[0x33b];
    base += t * 40;
    p20 = *(u8**)(base + 20);
    p28 = *(u8**)(base + 28);
    if (t == 5 && (((GroundBaddieState*)state)->baddie.controlFlags & 0x800000) != 0)
    {
        GameBit_Set(456, 1);
    }
    if (((GroundBaddieState*)state)->baddie.trackedObj != NULL && ((GameObject*)*(int*)&((GroundBaddieState*)state)->baddie.
        trackedObj)->anim.classId == 1)
    {
        fn_8001FEA8();
    }
    fn_8015039C(obj, state);
    tv = *(f32*)(state + 0x328);
    fz = lbl_803E2740;
    if (tv != fz && *(u16*)(state + 0x338) != 0)
    {
        *(f32*)(state + 0x328) = tv - timeDelta;
        if (*(f32*)(state + 0x328) <= fz)
        {
            *(f32*)(state + 0x328) = fz;
            ((GroundBaddieState*)state)->baddie.controlFlags |= 0x40000000LL;
            *(u16*)(state + 0x338) = (p28 + *(u16*)(state + 0x338) * 16)[10];
        }
    }
    if ((u8)fn_8014FFB4(obj, state, 1) == 0)
    {
        if ((((GroundBaddieState*)state)->baddie.controlFlags & 0x40000000) != 0)
        {
            player = Obj_GetPlayerObject();
            fn_8014C11C(obj, lbl_803E27AC, 3, 16, gGroundBaddieTargetSearchResult);
            if (*(u16*)(state + 0x338) != 0)
            {
                {
                    u8* p28c = p28 + 12;
                    *(u8*)(state + 0x2f2) = (u8) * (u32*)(p28c + *(u16*)(state + 0x338) * 16);
                }
                fn_8014D08C(obj, state, (p28 + *(u16*)(state + 0x338) * 16)[8],
                            *(f32*)(p28 + *(u16*)(state + 0x338) * 16), 0,
                            (u8) * &(p28 + *(u16*)(state + 0x338) * 16)[4]);
                ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
                    (ObjAnimComponent*)obj,
                    *(f32*)(lbl_8031DD30 + (p28 + *(u16*)(state + 0x338) * 16)[8] * 4));
                *(u16*)(state + 0x338) = (p28 + *(u16*)(state + 0x338) * 16)[9];
            }
            else
            {
                if (player != NULL && ((((GroundBaddieState*)state)->baddie.controlFlags & 0x800080) != 0 ||
                    (void*)Player_GetTargetObject((int)player) == NULL))
                {
                    fn_801511E8(obj, state);
                }
                else
                {
                    fn_801513AC(obj, state);
                }
            }
        }
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 0;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 0;
        if (((GameObject*)obj)->anim.currentMove == p20[8])
        {
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = (s8) * (int*)(p20 + 4);
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = p20[9];
        }
        if (((GameObject*)obj)->anim.currentMove == p20[0x14])
        {
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = (s8) * (int*)(p20 + 0x10);
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = p20[0x15];
        }
        if (((GameObject*)obj)->anim.currentMove == p20[0x20])
        {
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = (s8) * (int*)(p20 + 0x1c);
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = p20[0x21];
        }
        if ((state[0x323] & 8) == 0)
        {
            fn_8014CF7C(obj, state, ((GameObject*)((GroundBaddieState*)state)->baddie.trackedObj)->anim.localPosX,
                        ((GameObject*)((GroundBaddieState*)state)->baddie.trackedObj)->anim.localPosZ, 10, 0);
        }
    }
}

void fn_80151954(int obj, u8* state)
{
    u8* setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    f32 fz;
    f32 fz2;
    int z;

    ((GroundBaddieState*)state)->baddie.unk2E4 = 11;
    *(u32*)&((GroundBaddieState*)state)->baddie.unk2E4 |= 0x402B0LL;
    *(u32*)&((GroundBaddieState*)state)->baddie.unk2E4 |= 0x3040;
    *(u32*)&((GroundBaddieState*)state)->baddie.unk2E4 |= 0x40300000LL;
    *(u32*)&((GroundBaddieState*)state)->baddie.unk2E4 |= 0xC00;
    ((GroundBaddieState*)state)->baddie.unk308 = lbl_803E2754;
    ((GroundBaddieState*)state)->baddie.animDeltaScale = lbl_803E27B0;
    ((GroundBaddieState*)state)->baddie.unk304 = lbl_803E27B4;
    state[0x320] = 35;
    fz = lbl_803E2748;
    *(f32*)&((GroundBaddieState*)state)->baddie.eventFlags = fz;
    state[0x321] = 34;
    ((GroundBaddieState*)state)->baddie.unk318 = lbl_803E27B8;
    state[0x322] = 6;
    ((GroundBaddieState*)state)->baddie.unk31C = fz;
    ((GroundBaddieState*)state)->baddie.pathStep *= lbl_803E27BC;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 314:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 51;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C0;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 40;
        state[0x33b] = 0;
        break;
    case 17:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 51;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C0;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 40;
        state[0x33b] = 1;
        break;
    case 1505:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 1529;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C0;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 50;
        state[0x33b] = 2;
        break;
    case 1463:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 1530;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C4;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 50;
        state[0x33b] = 3;
        break;
    case 1464:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 1534;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C0;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 60;
        state[0x33b] = 4;
        break;
    case 1465:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 51;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C0;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 1;
        state[0x33b] = 1;
        break;
    case 1958:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 1957;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C0;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 160;
        state[0x33b] = 5;
        z = 0;
        state[0x320] = z;
        fz2 = lbl_803E2748;
        *(f32*)&((GroundBaddieState*)state)->baddie.eventFlags = fz2;
        state[0x321] = 21;
        ((GroundBaddieState*)state)->baddie.unk318 = lbl_803E27B8;
        state[0x322] = z;
        ((GroundBaddieState*)state)->baddie.unk31C = fz2;
        *(int*)(state + 0x36c) = (int)ObjModelChain_Alloc(&gGroundBaddieModelChainDesc, 1);
        ObjModelChain_SetOrigin((ObjModelChain*)*(int*)(state + 0x36c), lbl_803E27C8, lbl_803E27CC, lbl_803E27D0);
        *(int*)(obj + 0x108) = (int)baddieAfterUpdateBonesCb;
        ObjModelChain_SetEnabled((ObjModelChain*)*(int*)(state + 0x36c), 1);
        break;
    }
    if (*(s8*)(setup + 0x2e) != -1)
    {
        ((GroundBaddieState*)state)->baddie.controlFlags |= 1;
    }
}

void fn_80151C68(int obj, u8* state)
{
    u8* player;
    u8* setup;

    player = Obj_GetPlayerObject();
    setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    if ((*gGameUIInterface)->isEventReady(446) != 0)
    {
        if (player != NULL && playerGetMoney(player) >= 25)
        {
            playerAddMoney(player, -25);
            GameBit_Set(*(s16*)(setup + 0x1c), 1);
            *(u16*)(state + 0x338) = gGroundBaddieTriggerResponseSeq[2];
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            hudFn_8011f38c(2);
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
        }
        else
        {
            hudFn_8011f38c(2);
            *(u16*)(state + 0x338) = gGroundBaddieTriggerResponseSeq[1];
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        }
    }
    else
    {
        hudFn_8011f38c(2);
        *(u16*)(state + 0x338) = gGroundBaddieTriggerResponseSeq[0];
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
    }
}

void fn_80151DB8(int obj, u8* state)
{
    GameObject* player;
    ObjPlacement* setup;
    f32 dy;
    f32 px0;
    f32 pz0;
    f32 cosA;
    f32 sinA;
    f32 base;
    f32 f5;
    f32 f2v;
    f32 dx;
    f32 dz;

    player = (GameObject*)Obj_GetPlayerObject();
    setup = ((GameObject*)obj)->anim.placement;
    dy = player->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    dy = (dy >= lbl_803E27D8) ? dy : -dy;
    if (dy > lbl_803E27DC)
    {
        return;
    }
    px0 = setup->posX - lbl_803E27DC * mathSinf(gGroundBaddiePi * (f32)((GameObject*)obj)->anim.rotX / gGroundBaddieAngleUnitScale);
    pz0 = setup->posZ - lbl_803E27DC * mathCosf(gGroundBaddiePi * (f32)((GameObject*)obj)->anim.rotX / gGroundBaddieAngleUnitScale);
    dx = player->anim.worldPosX - px0;
    dz = player->anim.worldPosZ - pz0;
    if (sqrtf(dx * dx + dz * dz) < ((GroundBaddieState*)state)->baddie.speedScale)
    {
        cosA = mathSinf(gGroundBaddiePi * (f32)((GameObject*)obj)->anim.rotX / gGroundBaddieAngleUnitScale);
        sinA = mathCosf(gGroundBaddiePi * (f32)((GameObject*)obj)->anim.rotX / gGroundBaddieAngleUnitScale);
        base = -(cosA * (px0 - cosA) + sinA * (pz0 - sinA));
        f5 = base + (cosA * player->anim.previousWorldPosX + sinA * player->anim.previousWorldPosZ);
        f2v = base + (cosA * player->anim.worldPosX + sinA * player->anim.worldPosZ);
        if (f2v > lbl_803E27D8)
        {
            if (!(f5 >= lbl_803E27E8))
            {
                return;
            }
            player->anim.worldPosX = player->anim.worldPosX - cosA * f5;
            player->anim.worldPosZ = player->anim.worldPosZ - sinA * f5;
            Obj_TransformWorldPointToLocal(player->anim.worldPosX, player->anim.worldPosY, player->anim.worldPosZ,
                                           &player->anim.localPosX, &player->anim.localPosY, &player->anim.localPosZ,
                                           (u32)player->anim.parent);
        }
    }
}

void fn_80152004(int obj, int* state)
{
    Sfx_PlayFromObject((u32)obj, SFXen_cavedirt22);
    ((GroundBaddieState*)state)->baddie.reactionFlags |= 0x10;
}
