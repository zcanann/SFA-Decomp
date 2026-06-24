/*
 * shstaff (DLL 0x1B1) - the Krazoa Staff pickup object and its trailing
 * ring of light orbs.
 *
 * sh_staff_render positions the staff (carried, attached to the player's
 * hand matrix in the carry phases) and animates up to ten light-orb child
 * objects spread along the staff's two path points. sh_staff_SeqFn spawns
 * the orbs on demand and consumes the carry/HUD animation events;
 * sh_staff_update runs the pickup proximity / map-load state machine
 * (phase 0 idle -> 1 carried -> 2 done). fn_801DA4A8 hides the staff and
 * releases the orbs.
 */
#include "main/game_object.h"
#include "main/dll/player_objects.h"

int sh_staff_getExtraSize(void) { return 0x74; }

#pragma opt_strength_reduction on
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
            ((GameObject*)child)->anim.flags = (s16)(((GameObject*)child)->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
        child = *(int**)(p + 60);
        if (child != NULL)
        {
            ((GameObject*)child)->anim.flags = (s16)(((GameObject*)child)->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
        child = *(int**)(p + 64);
        if (child != NULL)
        {
            ((GameObject*)child)->anim.flags = (s16)(((GameObject*)child)->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
        child = *(int**)(p + 68);
        if (child != NULL)
        {
            ((GameObject*)child)->anim.flags = (s16)(((GameObject*)child)->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
        child = *(int**)(p + 72);
        if (child != NULL)
        {
            ((GameObject*)child)->anim.flags = (s16)(((GameObject*)child)->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
    }
}
#pragma opt_strength_reduction reset

#include "main/dll/DR/DRearthwalk.h"
#include "main/obj_placement.h"
#include "main/game_ui_interface.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/dll/DR/shstaff_state.h"
#include "main/audio/sfx.h"
#include "main/sfa_shared_decls.h"

typedef struct ShStaffPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 pad6[0x7 - 0x6];
    u8 unk7;
    u8 pad8[0x18 - 0x8];
    u8 rotZByte; /* 0x18: rotZ in 1/256 turns */
    u8 rotYByte; /* 0x19: rotY in 1/256 turns */
    u8 pad1A[0x20 - 0x1A];
} ShStaffPlacement;

extern u32 GameBit_Get(int eventId);
extern int randomGetRange(int lo, int hi);
extern int ObjGroup_FindNearestObject(int group, u32 obj, float* maxDistance);
extern int ObjTrigger_IsSet();
extern u32 ObjPath_GetPointLocalMtx();

extern void ObjPath_GetPointWorldPosition(int obj, int pointIndex, float* outX, float* outY, float* outZ, int useInputPosition);
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
    extern void objRenderFn_8003b8f4(int obj, u32 p2, u32 p3, u32 p4, u32 p5, double scale);
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
            for (i = 2; i < 10; i += 2)
            {
                if ((u32)state->slots[i] == 0)
                {
                    state->pending[i] = 1;
                    break;
                }
            }
            if (i >= 10)
            {
                state->flags |= 2;
            }
        }
        if (((state->flags & 4) != 0) && ((state->flags & 8) == 0))
        {
            for (i = 1; i < 10; i += 2)
            {
                if ((u32)state->slots[i] == 0)
                {
                    state->pending[i] = 1;
                    break;
                }
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
                for (; i < 5; i++)
                {
                    if ((u32)state->slots[i] != 0)
                    {
                        ((GameObject*)state->slots[i])->anim.flags |= OBJANIM_FLAG_HIDDEN;
                        state->slots[i] = 0;
                    }
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
                        state->fadeTimer = *(f32*)&lbl_803E54E0;
                    }
                    spd = lbl_803E54E4 * state->fadeTimer;
                }
                j = 0;
                for (; j < 5; j++)
                {
                    if (((u32)state->slots[j] != 0) && ((u32)state->slots[4] != 0))
                    {
                        t = lbl_803E54E8 + j / lbl_803E54EC;
                        bx = ((GameObject*)state->slots[4])->anim.localPosX;
                        ((GameObject*)state->slots[j])->anim.localPosX = t * (x0 - bx) + bx;
                        ((GameObject*)state->slots[j])->anim.localPosY =
                            t * (y0 - ((GameObject*)state->slots[4])->anim.localPosY) + ((GameObject*)state->slots[4])->anim.localPosY;
                        ((GameObject*)state->slots[j])->anim.localPosZ =
                            t * (z0 - ((GameObject*)state->slots[4])->anim.localPosZ) + ((GameObject*)state->slots[4])->anim.localPosZ;
                        ((GameObject*)state->slots[j])->anim.rootMotionScale = spd;
                    }
                }
                j = 9;
                for (; j > 4; j--)
                {
                    if (((u32)state->slots[j] != 0) && ((u32)state->slots[5] != 0))
                    {
                        t = lbl_803E54E8 + (f32)(9 - j) / lbl_803E54EC;
                        bx = ((GameObject*)state->slots[5])->anim.localPosX;
                        ((GameObject*)state->slots[j])->anim.localPosX = t * (x1 - bx) + bx;
                        ((GameObject*)state->slots[j])->anim.localPosY =
                            t * (y1 - ((GameObject*)state->slots[5])->anim.localPosY) + ((GameObject*)state->slots[5])->anim.localPosY;
                        ((GameObject*)state->slots[j])->anim.localPosZ =
                            t * (z1 - ((GameObject*)state->slots[5])->anim.localPosZ) + ((GameObject*)state->slots[5])->anim.localPosZ;
                        ((GameObject*)state->slots[j])->anim.rootMotionScale = spd;
                    }
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
                        t = lbl_803E54F0 * j;
                        t = t + (f32)(int)
                        randomGetRange(-0x32, 0x32) / lbl_803E54F4;
                        ((GameObject*)state->slots[j])->anim.localPosX = dx * t + x0;
                        ((GameObject*)state->slots[j])->anim.localPosY = dy * t + y0;
                        ((GameObject*)state->slots[j])->anim.localPosZ = dz * t + z0;
                        ((GameObject*)state->slots[j])->anim.rootMotionScale = spd;
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
                    if ((u32)o != 0)
                    {
                        ((GameObject*)o)->anim.flags |= OBJANIM_FLAG_HIDDEN;
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
                ((GameObject*)state->slots[0])->anim.localPosX = dx * state->pulseTimer + x0;
                ((GameObject*)state->slots[0])->anim.localPosY = dy * state->pulseTimer + y0;
                ((GameObject*)state->slots[0])->anim.localPosZ = dz * state->pulseTimer + z0;
                ((GameObject*)state->slots[0])->anim.rootMotionScale = scale;
            }
        }
    }
}

extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int loadObjectAtObject(int obj, int* setup);

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
                ((ObjPlacement*)newSetup)->color[0] = 2;
                ((ObjPlacement*)newSetup)->color[3] = 0xff;
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
            (((GameObject*)obj)->anim.modelInstance->helpTextIds[1], 0xa0, 0x8c);
    }
    state->pulseTimer = lbl_803E54D8 * timeDelta + state->pulseTimer;
    if (state->pulseTimer > lbl_803E54D0)
    {
        state->pulseTimer = lbl_803E54D4;
    }
    return 0;
}

extern f32 getXZDistance(f32* a, f32* b);
extern void fn_80295CF4(int obj, int a);
extern void fn_8029672C(int obj, int mode);
extern int ObjTrigger_IsSet(int obj);



extern f32 lbl_803E550C;
extern f32 gShStaffMapUnloadDistSq;
extern f32 gShStaffMapLoadDistSq;

#pragma optimization_level 1
#pragma opt_strength_reduction on
void fn_801DA4A8(int obj, ShStaffState* state, int clearChildren)
{
    int player;
    void* child;
    int i;
    int zero;

    player = (int)Obj_GetPlayerObject();
    ObjHits_DisableObject(obj);
    ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);

    if (clearChildren != 0)
    {
        fn_80295CF4(player, 1);
        fn_8029672C(player, 1);
        zero = 0;
        {
            char* p = (char*)state;
            for (i = 0; i < 8; i += 4)
            {
            child = *(void**)(p + 56);
            if (child != NULL)
            {
                ((GameObject*)child)->anim.flags = (s16)(((GameObject*)child)->anim.flags | OBJANIM_FLAG_HIDDEN);
                *(int*)(p + 56) = zero;
            }
            child = *(void**)(p + 60);
            if (child != NULL)
            {
                ((GameObject*)child)->anim.flags = (s16)(((GameObject*)child)->anim.flags | OBJANIM_FLAG_HIDDEN);
                *(int*)(p + 60) = zero;
            }
            child = *(void**)(p + 64);
            if (child != NULL)
            {
                ((GameObject*)child)->anim.flags = (s16)(((GameObject*)child)->anim.flags | OBJANIM_FLAG_HIDDEN);
                *(int*)(p + 64) = zero;
            }
            child = *(void**)(p + 68);
            if (child != NULL)
            {
                ((GameObject*)child)->anim.flags = (s16)(((GameObject*)child)->anim.flags | OBJANIM_FLAG_HIDDEN);
                *(int*)(p + 68) = zero;
            }
            child = *(void**)(p + 72);
            if (child != NULL)
            {
                ((GameObject*)child)->anim.flags = (s16)(((GameObject*)child)->anim.flags | OBJANIM_FLAG_HIDDEN);
                *(int*)(p + 72) = zero;
            }
            p += 20;
            }
        }
    }

    state->phase = 6;
}
#pragma opt_strength_reduction reset
#pragma optimization_level reset

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
        if ((void*)Player_GetStaffObject((int)player) == NULL) goto end;
        if (GameBit_Get(0x18b) != 0)
        {
            fn_801DA4A8(obj, ((GameObject*)obj)->extra, 0);
        }
        else
        {
            int loadResult;
            fn_80295CF4((int)player, 0);
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj, lbl_803E54D0);
            ((GameObject*)obj)->anim.rotY = (s16)(((ShStaffPlacement*)setup)->rotYByte << 8);
            ((GameObject*)obj)->anim.rotZ = (s16)(((ShStaffPlacement*)setup)->rotZByte << 8);
            ((GameObject*)obj)->animEventCallback = sh_staff_SeqFn;
            state->phase = 1;
            if (Obj_IsLoadingLocked() == 0)
            {
                loadResult = 0;
            }
            else
            {
                int* newSetup = Obj_AllocObjectSetup(0x20, 0x659);
                ((ObjPlacement*)newSetup)->color[0] = 2;
                ((ObjPlacement*)newSetup)->color[3] = 0xff;
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
            int target = ObjGroup_FindNearestObject(0xf, obj, 0);
            (*gObjectTriggerInterface)->runSequence(0, (void*)target, -1);
            state->phase = 2;
            state->fadeTimer = lbl_803E54E0;
            GameBit_Set(0x18b, 1);
        }
        else if (dist > gShStaffMapUnloadDistSq)
        {
            if (state->mapLoaded != 0)
            {
                state->mapLoaded = 0;
                mapUnload(0x13, 0x20000000);
            }
        }
        else if (dist < gShStaffMapLoadDistSq)
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

extern int GameBit_Set(int eventId, int value);
