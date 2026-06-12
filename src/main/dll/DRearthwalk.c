/* === moved from main/dll/IM/IMsnowbike.c [801D9B1C-801D9BDC) (TU re-split, docs/boundary_audit.md) === */
#include "main/game_object.h"





/*
 * --INFO--
 *
 * Function: sh_levelcontrol_update
 * EN v1.0 Address: 0x801D8D20
 * EN v1.0 Size: 2452b
 * EN v1.1 Address: 0x801D90F0
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */




/* 8b "li r3, N; blr" returners. */
int sh_staff_getExtraSize(void) { return 0x74; }






/* render-with-objRenderFn_8003b8f4 pattern. */

void sh_staff_free(int* obj, int p2)
{
    int* state = ((GameObject*)obj)->extra;
    char* p;
    int idx;

    if (p2 != 0) return;

    for (idx = 0; idx < 8; idx += 4)
    {
        int* child;
        p = (char*)state + idx * 5;
        child = *(int**)(p + 56);
        if (child != NULL)
        {
            *(s16*)((char*)child + 6) = (s16)(*(s16*)((char*)child + 6) | 0x4000);
        }
        child = *(int**)(p + 60);
        if (child != NULL)
        {
            *(s16*)((char*)child + 6) = (s16)(*(s16*)((char*)child + 6) | 0x4000);
        }
        child = *(int**)(p + 64);
        if (child != NULL)
        {
            *(s16*)((char*)child + 6) = (s16)(*(s16*)((char*)child + 6) | 0x4000);
        }
        child = *(int**)(p + 68);
        if (child != NULL)
        {
            *(s16*)((char*)child + 6) = (s16)(*(s16*)((char*)child + 6) | 0x4000);
        }
        child = *(int**)(p + 72);
        if (child != NULL)
        {
            *(s16*)((char*)child + 6) = (s16)(*(s16*)((char*)child + 6) | 0x4000);
        }
        p += 20;
    }
}

#include "main/dll/DR/DRearthwalk.h"
#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objseq.h"

#include "main/dll/DR/shstaff_state.h"

typedef struct ShStaffPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 pad6[0x7 - 0x6];
    u8 unk7;
    u8 pad8[0x18 - 0x8];
    u8 unk18;
    u8 unk19;
    u8 pad1A[0x20 - 0x1A];
} ShStaffPlacement;


typedef struct ShBeaconPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} ShBeaconPlacement;


/* sh_beacon_getExtraSize == 0x18. */
typedef struct ShBeaconState
{
    int childObj; /* 0x00: spawned 0x55 flame object */
    f32 seqTimer; /* 0x04 */
    f32 fadeTimer; /* 0x08 */
    f32 burstTimer; /* 0x0c */
    f32 modeTimer; /* 0x10 */
    u8 mode; /* 0x14: 0 unlit, 1 lit, 2 igniting */
    u8 flags15; /* 0x15: bit 7 = looping sfx active (BeaconFlags) */
    u8 pad16[2];
} ShBeaconState;

STATIC_ASSERT(sizeof(ShBeaconState) == 0x18);


extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointLocalMtx();
extern undefined4 ObjPath_GetPointModelMtx();
extern undefined4 ObjPath_GetPointWorldPosition();


/*
 * --INFO--
 *
 * Function: sh_staff_render
 * EN v1.0 Address: 0x801D9BDC
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801DA010
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void* Obj_GetPlayerObject(void);
extern void Obj_BuildWorldTransformMatrix(int obj, f32* mtx, int p3);
extern void PSMTXInverse(int src, f32* dst);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * dst);
extern void objSetMtxFn_800412d4(f32 * mtx);
extern void objRenderModel(int obj);
extern f32 timeDelta;
extern f32 lbl_803E54D0;
extern f32 lbl_803E54D4;
extern f32 lbl_803E54D8;
extern f32 lbl_803E54DC;
extern f32 lbl_803E54E0;
extern f32 lbl_803E54E4;
extern f32 lbl_803E54E8;
extern f32 lbl_803E54EC;
extern f32 lbl_803E54F0;
extern f32 lbl_803E54F4;
extern f32 lbl_803E54F8;

void sh_staff_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(int obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale); /* #57 */
    ShStaffState* state;
    int player;
    int i;
    int j;
    int* slotPtr;
    int o;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 spd;
    f32 t;
    f32 scale;
    f32 bx;
    f32 cur2;
    f32 mtxB[12];
    f32 mtxA[12];
    f32 z0;
    f32 y0;
    f32 x0;
    f32 z1;
    f32 y1;
    f32 x1;

    state = ((GameObject*)obj)->extra;
    player = (int)Obj_GetPlayerObject();
    if (visible != 0)
    {
        if (state->phase == 3)
        {
            Obj_BuildWorldTransformMatrix(obj, mtxB, 0);
            PSMTXInverse((int)ObjPath_GetPointModelMtx((void*)player, 0), mtxA);
            PSMTXConcat(mtxA, mtxB, state->carryMtx);
            state->phase = 5;
        }
        if (state->phase == 4)
        {
            ObjPath_GetPointLocalMtx((void*)player, 0, state->carryMtx);
            state->phase = 5;
        }
        if (state->phase == 5)
        {
            PSMTXConcat((f32*)ObjPath_GetPointModelMtx((void*)player, 0), state->carryMtx, mtxB);
            objSetMtxFn_800412d4(mtxB);
            objRenderModel(obj);
        }
        else
        {
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E54D0);
        }
        ObjPath_GetPointWorldPosition(obj, 0, &x0, &y0, &z0, 0);
        ObjPath_GetPointWorldPosition(obj, 1, &x1, &y1, &z1, 0);
        dx = x1 - x0;
        dy = y1 - y0;
        dz = z1 - z0;
        if (((state->flags & 1) != 0) && ((state->flags & 2) == 0))
        {
            slotPtr = &state->slots[2];
            for (i = 2; i < 10; i += 2)
            {
                if ((u32) * slotPtr == 0)
                {
                    state->pending[i] = 1;
                    break;
                }
                slotPtr += 2;
            }
            if (i >= 10)
            {
                state->flags |= 2;
            }
        }
        if (((state->flags & 4) != 0) && ((state->flags & 8) == 0))
        {
            slotPtr = &state->slots[1];
            for (i = 1; i < 10; i += 2)
            {
                if ((u32) * slotPtr == 0)
                {
                    state->pending[i] = 1;
                    break;
                }
                slotPtr += 2;
            }
            if (i >= 10)
            {
                state->flags |= 8;
            }
        }
        if (state->flags != 0)
        {
            if ((state->flags & 0x20) != 0)
            {
                i = 5;
                slotPtr = &state->slots[5];
                for (; i < 5; i++)
                {
                    o = *slotPtr;
                    if ((uint)o != 0)
                    {
                        *(s16*)(o + 6) |= 0x4000;
                        *slotPtr = 0;
                    }
                    slotPtr++;
                }
                if ((state->flags & 0x10) != 0)
                {
                    state->fadeTimer = state->fadeTimer - timeDelta;
                    if (state->fadeTimer <= lbl_803E54D4)
                    {
                        spd = lbl_803E54D8;
                    }
                    else
                    {
                        state->fadeTimer = state->fadeTimer - timeDelta;
                        spd = lbl_803E54DC * state->fadeTimer;
                    }
                }
                else
                {
                    state->fadeTimer = state->fadeTimer + timeDelta;
                    if (state->fadeTimer >= lbl_803E54E0)
                    {
                        state->fadeTimer = lbl_803E54E0;
                    }
                    spd = lbl_803E54E4 * state->fadeTimer;
                }
                j = 0;
                slotPtr = state->slots;
                for (; j < 5; j++)
                {
                    if (((u32) * slotPtr != 0) && ((u32)state->slots[4] != 0))
                    {
                        o = *slotPtr;
                        t = lbl_803E54E8 + (f32)j / lbl_803E54EC;
                        bx = *(f32*)(state->slots[4] + 0xc);
                        *(f32*)(o + 0xc) = t * (x0 - bx) + bx;
                        *(f32*)(o + 0x10) =
                            t * (y0 - *(f32*)(state->slots[4] + 0x10)) + *(f32*)(state->slots[4] + 0x10);
                        *(f32*)(o + 0x14) =
                            t * (z0 - *(f32*)(state->slots[4] + 0x14)) + *(f32*)(state->slots[4] + 0x14);
                        *(f32*)(o + 8) = spd;
                    }
                    slotPtr++;
                }
                j = 9;
                slotPtr = &state->slots[9];
                for (; j > 4; j--)
                {
                    if (((u32) * slotPtr != 0) && ((u32)state->slots[5] != 0))
                    {
                        o = *slotPtr;
                        t = lbl_803E54E8 + (f32)(9 - j) / lbl_803E54EC;
                        bx = *(f32*)(state->slots[5] + 0xc);
                        *(f32*)(o + 0xc) = t * (x1 - bx) + bx;
                        *(f32*)(o + 0x10) =
                            t * (y1 - *(f32*)(state->slots[5] + 0x10)) + *(f32*)(state->slots[5] + 0x10);
                        *(f32*)(o + 0x14) =
                            t * (z1 - *(f32*)(state->slots[5] + 0x14)) + *(f32*)(state->slots[5] + 0x14);
                        *(f32*)(o + 8) = spd;
                    }
                    slotPtr--;
                }
            }
            else
            {
                spd = lbl_803E54D8;
                if ((state->flags & 0x10) != 0)
                {
                    state->fadeTimer = state->fadeTimer - timeDelta;
                    if (state->fadeTimer <= lbl_803E54D4)
                    {
                        state->flags &= ~0x10;
                    }
                    else
                    {
                        spd = lbl_803E54E4 * state->fadeTimer;
                    }
                }
                for (j = 0; j < 10; j++)
                {
                    if ((u32)state->slots[j] != 0)
                    {
                        o = state->slots[j];
                        t = lbl_803E54F0 * (f32)j;
                        t = t + (f32)(int)
                        randomGetRange(-0x32, 0x32) / lbl_803E54F4;
                        *(f32*)(o + 0xc) = dx * t + x0;
                        *(f32*)(o + 0x10) = dy * t + y0;
                        *(f32*)(o + 0x14) = dz * t + z0;
                        *(f32*)(o + 8) = spd;
                    }
                }
            }
        }
        else
        {
            scale = lbl_803E54F8;
            cur2 = state->fadeTimer;
            bx = lbl_803E54D4;
            if (cur2 != bx)
            {
                state->fadeTimer = cur2 - timeDelta;
                if (state->fadeTimer <= bx)
                {
                    o = state->slots[0];
                    if ((uint)o != 0)
                    {
                        *(s16*)(o + 6) |= 0x4000;
                        state->slots[0] = 0;
                        state->fadeTimer = bx;
                    }
                }
                else
                {
                    scale = lbl_803E54E4 * state->fadeTimer;
                }
            }
            if ((u32)state->slots[0] != 0)
            {
                o = state->slots[0];
                *(f32*)(o + 0xc) = dx * state->pulseTimer + x0;
                *(f32*)(o + 0x10) = dy * state->pulseTimer + y0;
                *(f32*)(o + 0x14) = dz * state->pulseTimer + z0;
                *(f32*)(o + 8) = scale;
            }
        }
    }
}


/* 8b "li r3, N; blr" returners. */
int sh_beacon_getExtraSize(void) { return 0x18; }

extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);
extern void Obj_FreeObject(int obj);
extern void ObjHits_PollPriorityHitEffectWithCooldown(int obj, int a, int b, int c, int d,
                                                      int e, void* f);
extern f32 lbl_803E5518;
extern f32 lbl_803E551C;
extern f32 lbl_803E5520;
extern f32 lbl_803E5528;
extern f32 lbl_803E552C;

/* 96b: render via objRenderFn + fn_80098B18 with 3-float local. */
void sh_staffhaze_render(int obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5)
{
    extern void objRenderFn_8003b8f4(int obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale); /* #57 */
    float local[3];
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E5518);
    local[0] = lbl_803E551C;
    local[1] = lbl_803E5520;
    local[2] = lbl_803E551C;
    fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 4, 0, 0, (int)&local[0]);
}

/* 48b: free if 0x4000 flag set. */
void sh_staffhaze_update(int obj)
{
    if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
    {
        Obj_FreeObject(obj);
    }
}

/* 120b: tick a float timer; on wrap optionally trigger an effect. */
int sh_beacon_SeqFn(int obj)
{
    int extra = *(int*)&((GameObject*)obj)->extra;
    ((ShBeaconState*)extra)->seqTimer = ((ShBeaconState*)extra)->seqTimer + timeDelta;
    if (((ShBeaconState*)extra)->seqTimer >= lbl_803E5528)
    {
        ((ShBeaconState*)extra)->seqTimer = ((ShBeaconState*)extra)->seqTimer - lbl_803E5528;
        if ((*(unsigned short*)(obj + 0xb0) & 0x800) != 0)
        {
            fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 0, 2, 0, 0);
        }
    }
    return 0;
}

/* 20b: reset extra->field_0x8 = lbl_803E552C, return 1. */
int fn_801DA9CC(int obj)
{
    ((ShBeaconState*)*(int*)&((GameObject*)obj)->extra)->fadeTimer = lbl_803E552C;
    return 1;
}

/* 112b: vtable cleanup then maybe Obj_FreeObject. */
void sh_beacon_free(int obj, int param_2)
{
    int extra = *(int*)&((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (param_2 == 0)
    {
        void* p = *(void**)&((ShBeaconState*)extra)->childObj;
        if (p != NULL && (*(unsigned short*)((char*)p + 0xb0) & 0x40) == 0)
        {
            Obj_FreeObject((int)p);
        }
    }
}

/* 56b: single-call hit-effect poll. */
void sh_emptytumblew_update(int obj);

/* TODO stubs to align function set with v1.0 asm. Bodies are large
 * state-machine and animation logic; filling them is a follow-up task. */
extern u8 Obj_IsLoadingLocked(void);
extern int* Obj_AllocObjectSetup(int a, int b);
extern int loadObjectAtObject(int obj, int* setup);
extern void hudFn_8011f38c(int a);
extern void fn_801DA4A8(int obj, ShStaffState* state, int a);
extern f32 lbl_803E5508;

int sh_staff_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    ShStaffState* state = ((GameObject*)obj)->extra;
    int i;

    for (i = 0; i < 10; i++)
    {
        if (state->pending[i] != 0)
        {
            int loadResult;
            if ((u8)Obj_IsLoadingLocked() == 0)
            {
                loadResult = 0;
            }
            else
            {
                int* newSetup = Obj_AllocObjectSetup(0x20, 0x659);
                *(u8*)((char*)newSetup + 4) = 2;
                *(u8*)((char*)newSetup + 7) = 0xff;
                loadResult = loadObjectAtObject(obj, newSetup);
            }
            state->slots[i] = loadResult;
            state->pending[i] = 0;
        }
    }

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 v = animUpdate->eventIds[i];
        switch (v)
        {
        case 0:
            state->phase = 3;
            break;
        case 1:
            state->hudFlag = 1;
            break;
        case 2:
            state->hudFlag = 0;
            break;
        case 3:
            fn_801DA4A8(obj, state, 1);
            break;
        case 4:
            state->phase = 4;
            break;
        case 5:
            hudFn_8011f38c(1);
            break;
        case 6:
            state->flags = (u8)(state->flags | 1);
            break;
        case 7:
            state->flags = (u8)(state->flags | 4);
            break;
        case 8:
            state->flags = (u8)(state->flags | 0x10);
            state->fadeTimer = lbl_803E54E0;
            break;
        case 9:
            state->flags = (u8)(state->flags | 0x20);
            state->fadeTimer = lbl_803E54D4;
            break;
        case 0xa:
            state->flags = (u8)(state->flags | 0x10);
            state->flags = (u8)(state->flags | 0xa);
            state->fadeTimer = lbl_803E5508;
            break;
        case 0xb:
        case 0xc:
            break;
        }
    }

    if (state->hudFlag != 0)
    {
        ((void (*)(s16, int, int))((int*)*gGameUIInterface)[0x34 / 4])
            (*(s16*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x7e), 0xa0, 0x8c);
    }
    state->pulseTimer = lbl_803E54D8 * timeDelta + state->pulseTimer;
    if (state->pulseTimer > lbl_803E54D0)
    {
        state->pulseTimer = lbl_803E54D4;
    }
    return 0;
}

extern f32 getXZDistance(f32 * a, f32 * b);
extern void* fn_802966CC(int player);
extern int fn_80295CF4(int player, int a);
extern int fn_8029672C(int player, int a);
extern int ObjTrigger_IsSet(int obj);
extern void mapUnload(int idx, int flags);
extern void loadMapAndParent(int mapId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f32 lbl_803E550C;
extern f32 lbl_803E5510;
extern f32 lbl_803E5514;

void fn_801DA4A8(int obj, ShStaffState* state, int clearChildren)
{
    int player;
    void* child;
    int* childSlots;
    int i;
    int zero;

    player = (int)Obj_GetPlayerObject();
    ObjHits_DisableObject(obj);
    ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);

    if (clearChildren != 0)
    {
        fn_80295CF4(player, 1);
        fn_8029672C(player, 1);
        zero = 0;
        childSlots = state->slots;
        for (i = 0; i < 8; i += 4)
        {
            child = (void*)childSlots[0];
            if (child != NULL)
            {
                *(s16*)((char*)child + 6) = (s16)(*(s16*)((char*)child + 6) | 0x4000);
                childSlots[0] = zero;
            }
            child = (void*)childSlots[1];
            if (child != NULL)
            {
                *(s16*)((char*)child + 6) = (s16)(*(s16*)((char*)child + 6) | 0x4000);
                childSlots[1] = zero;
            }
            child = (void*)childSlots[2];
            if (child != NULL)
            {
                *(s16*)((char*)child + 6) = (s16)(*(s16*)((char*)child + 6) | 0x4000);
                childSlots[2] = zero;
            }
            child = (void*)childSlots[3];
            if (child != NULL)
            {
                *(s16*)((char*)child + 6) = (s16)(*(s16*)((char*)child + 6) | 0x4000);
                childSlots[3] = zero;
            }
            child = (void*)childSlots[4];
            if (child != NULL)
            {
                *(s16*)((char*)child + 6) = (s16)(*(s16*)((char*)child + 6) | 0x4000);
                childSlots[4] = zero;
            }
            childSlots += 5;
        }
    }

    state->phase = 6;
}

void sh_staff_update(int obj)
{
    ShStaffState* state = ((GameObject*)obj)->extra;
    int setup = *(int*)&((GameObject*)obj)->anim.placementData;
    void* player = Obj_GetPlayerObject();
    f32 dist = getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)((int)player + 0x18));
    u8 mode = state->phase;

    if (mode == 0)
    {
        if (player == NULL) goto end;
        if (fn_802966CC((int)player) == 0) goto end;
        if (GameBit_Get(0x18b) != 0)
        {
            fn_801DA4A8(obj, state, 0);
        }
        else
        {
            int loadResult;
            fn_80295CF4((int)player, 0);
            ObjAnim_SetMoveProgress(lbl_803E54D0, (ObjAnimComponent*)obj);
            ((GameObject*)obj)->anim.rotY = (s16)(((ShStaffPlacement*)setup)->unk19 << 8);
            ((GameObject*)obj)->anim.rotZ = (s16)(((ShStaffPlacement*)setup)->unk18 << 8);
            ((GameObject*)obj)->animEventCallback = (void*)sh_staff_SeqFn;
            state->phase = 1;
            if (Obj_IsLoadingLocked() == 0)
            {
                loadResult = 0;
            }
            else
            {
                int* newSetup = Obj_AllocObjectSetup(0x20, 0x659);
                *(u8*)((char*)newSetup + 4) = 2;
                *(u8*)((char*)newSetup + 7) = 0xff;
                loadResult = loadObjectAtObject(obj, newSetup);
            }
            state->slots[0] = loadResult;
            state->sfxTimer = lbl_803E550C;
        }
    }
    else if (mode == 1)
    {
        if (ObjTrigger_IsSet(obj) != 0)
        {
            int target = ObjGroup_FindNearestObject(0xf, (u32)obj, 0);
            (*gObjectTriggerInterface)->runSequence(0, (void*)target, -1);
            state->phase = 2;
            state->fadeTimer = lbl_803E54E0;
            GameBit_Set(0x18b, 1);
        }
        else if (dist > lbl_803E5510)
        {
            if (state->mapLoaded != 0)
            {
                state->mapLoaded = 0;
                mapUnload(0x13, 0x20000000);
            }
        }
        else if (dist < lbl_803E5514)
        {
            if (state->mapLoaded == 0)
            {
                state->mapLoaded = 1;
                loadMapAndParent(8);
            }
        }
    }
    else
    {
        if (state->mapLoaded != 0)
        {
            state->mapLoaded = 0;
            mapUnload(0x13, 0x20000000);
            GameBit_Set(0x3b8, 1);
        }
    }
end:
    hudFn_8011f38c(0);
    state->pulseTimer = lbl_803E54D8 * timeDelta + state->pulseTimer;
    if (state->pulseTimer > lbl_803E54D0)
    {
        state->pulseTimer = lbl_803E54D4;
    }
    state->sfxTimer = lbl_803E54D8 * timeDelta + state->sfxTimer;
    if (state->sfxTimer > lbl_803E54D0)
    {
        state->sfxTimer = lbl_803E54D4;
        if (state->phase == 1)
        {
            Sfx_PlayFromObject(obj, 0x3fe);
        }
    }
}

void sh_beacon_init(int obj, int defData)
{
    int state;
    int* setup;

    state = *(int*)&((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32) * (s8*)(defData + 0x18) << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x4000);

    ((ShBeaconState*)state)->mode = (u8)GameBit_Get(*(s16*)(defData + 0x1e));
    if (((ShBeaconState*)state)->mode == 0)
    {
        if (GameBit_Get(*(s16*)(defData + 0x20)) != 0)
        {
            ((ShBeaconState*)state)->mode = 2;
        }
    }

    if (((ShBeaconState*)state)->mode != 0 && Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(0x20, 0x55);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(u8*)((char*)setup + 4) = 2;
        *(u8*)((char*)setup + 5) = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 5);
        *(u8*)((char*)setup + 7) = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 7);
        ((ShBeaconState*)state)->childObj = loadObjectAtObject(obj, setup);
    }

    ((GameObject*)obj)->animEventCallback = (void*)sh_beacon_SeqFn;
}

extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern int GameBit_Set(int eventId, int value);
extern void gameBitDecrement(int eventId);
extern void* getTrickyObject(void);
extern void fn_8002B6D8(int obj, int p2, int p3, int p4, int p5, int p6);
extern f32 lbl_803E5530;
extern f32 lbl_803E5534;
extern f32 lbl_803E5538;
extern f32 lbl_803E553C;
extern int lbl_803DDBF8;

typedef struct
{
    u8 looping : 1;
    u8 rest : 7;
} BeaconFlags;

/*
 * --INFO--
 *
 * Function: sh_beacon_update
 * EN v1.0 Address: 0x801DAA58
 * EN v1.0 Size: 1080b
 */
void sh_beacon_update(int obj)
{
    u8* state;
    int def;
    int tmp;
    int* setup;
    int mode;
    int state2;

    state = ((GameObject*)obj)->extra;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    switch (((ShBeaconState*)state)->mode)
    {
    case 0:
        if (((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0) &&
            ((*gGameUIInterface)->isEventReady(0x194) != 0))
        {
            gameBitDecrement(0x194);
            GameBit_Set(((ShBeaconPlacement*)def)->unk20, 1);
            if (Obj_IsLoadingLocked() != 0)
            {
                setup = Obj_AllocObjectSetup(0x20, 0x55);
                ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
                ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                *(u8*)((char*)setup + 4) = 2;
                *(u8*)((char*)setup + 5) = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 5);
                *(u8*)((char*)setup + 7) = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 7);
                ((ShBeaconState*)state)->childObj = loadObjectAtObject(obj, setup);
            }
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            ((ShBeaconState*)state)->mode = 2;
        }
    case 2:
        state2 = *(int*)&((GameObject*)obj)->extra;
        ((ShBeaconState*)state2)->seqTimer = ((ShBeaconState*)state2)->seqTimer + timeDelta;
        if (((ShBeaconState*)state2)->seqTimer >= lbl_803E5528)
        {
            ((ShBeaconState*)state2)->seqTimer = ((ShBeaconState*)state2)->seqTimer - lbl_803E5528;
            if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
            {
                fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 0, 2, 0, 0);
            }
        }
        break;
    case 1:
        if ((((BeaconFlags*)&((ShBeaconState*)state)->flags15)->looping) == 0)
        {
            Sfx_AddLoopedObjectSound(obj, 0x9e);
            ((BeaconFlags*)&((ShBeaconState*)state)->flags15)->looping = 1;
        }
        if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
        {
            ((ShBeaconState*)state)->modeTimer = ((ShBeaconState*)state)->modeTimer + timeDelta;
            if (((ShBeaconState*)state)->modeTimer > lbl_803E5530)
            {
                mode = 2;
                ((ShBeaconState*)state)->modeTimer = ((ShBeaconState*)state)->modeTimer - lbl_803E5530;
            }
            else
            {
                mode = 0;
            }
            ((ShBeaconState*)state)->burstTimer = ((ShBeaconState*)state)->burstTimer + timeDelta;
            if (((ShBeaconState*)state)->burstTimer > lbl_803E5534)
            {
                ((ShBeaconState*)state)->burstTimer = ((ShBeaconState*)state)->burstTimer - lbl_803E5534;
                fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 2, mode, 0, 0);
            }
        }
        break;
    }
    if (((ShBeaconState*)state)->mode != 1)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
        if (((ShBeaconState*)state)->mode == 2)
        {
            fn_8002B6D8(obj, 0, 0, 0, 0, 8);
        }
        else if ((((ShBeaconState*)state)->mode == 0) && (GameBit_Get(0x194) == 0))
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
        }
        tmp = (int)getTrickyObject();
        if (((void*)tmp != NULL) && ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0))
        {
            (*(code*)(*(int*)(*(int*)(tmp + 0x68)) + 0x28))(tmp, obj, 1, 4);
        }
    }
    else
    {
        if ((GameBit_Get(0x193) != 0) || (((ShBeaconPlacement*)def)->unk1E != 0x95))
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
        }
    }
    if (((ShBeaconState*)state)->fadeTimer > lbl_803E5538)
    {
        ((ShBeaconState*)state)->fadeTimer = ((ShBeaconState*)state)->fadeTimer - timeDelta;
        if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
        {
            fn_80098B18(obj, lbl_803E553C * ((GameObject*)obj)->anim.rootMotionScale, 3, 0, 0, 0);
        }
        if ((((ShBeaconState*)state)->fadeTimer <= lbl_803E5538) && (((ShBeaconState*)state)->mode == 2))
        {
            ((ShBeaconState*)state)->mode = 1;
            GameBit_Set(((ShBeaconPlacement*)def)->unk1E, 1);
            if ((GameBit_Get(0x190) != 0) && (GameBit_Get(0x191) != 0) && (GameBit_Get(0x192) != 0))
            {
                Sfx_PlayFromObject(0, 0x7e);
            }
            else
            {
                Sfx_PlayFromObject(0, 0x409);
            }
        }
    }
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129, &lbl_803DDBF8);
}
