/* DLL 0x0188 (cclightfoot) - CloudRunner Lightfoot object.
 * The LightFoot enemies in the CloudRunner capture/escape encounter (they
 * chase the player; target actors CCLIGHTFOOT_TARGET_ACTOR_A/B).
 * GAMEBIT_LIGHTFOOT_TRIGGERED is the per-encounter latch: the first creature
 * to reach state 0xC sets it (when its ObjTrigger fires), and on (re)spawn any
 * creature that sees it already set despawns immediately (state 0 -> 0xE).
 * GAMEBIT_CC_COMPLETE marks full completion. Nothing else in the game writes
 * the trigger latch. */
#include "main/dll/DIM/dimlogfire.h"

#define GAMEBIT_LIGHTFOOT_TRIGGERED 9
#define GAMEBIT_CC_COMPLETE 0x24
#define CCLIGHTFOOT_TARGET_ACTOR_A 0x45d7d
#define CCLIGHTFOOT_TARGET_ACTOR_B 0x45d7f

extern void ObjLink_AttachChild(int parent, int child, u16 linkMode);
extern f32 timeDelta;

extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int allocResult, int a, int b, int c, int d);
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/dll/DIM/DIMsnowball.h"
#include "main/dll/player_target.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/objhits.h"
#include "main/audio/sfx.h"
extern int ObjHits_PollPriorityHitWithCooldown();
extern int ObjTrigger_IsSet();

#pragma scheduling on
#pragma peephole on
int cclightfoot_getExtraSize(void) { return 0x18; }

#pragma scheduling off
#pragma peephole off
void cclightfoot_init(int* obj, int* def)
{
    ((GameObject*)obj)->anim.rotX = (s16)((u32) * (u8*)((char*)def + 26) << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x4000);
    ((GameObject*)obj)->animEventCallback = ccqueen_SeqFn;
}

void cclightfoot_free(int* obj, int p2)
{
    extern u32 ObjLink_DetachChild();
    int* state = ((GameObject*)obj)->extra;
    int* sub = (int*)state[0];
    if (sub != NULL)
    {
        if (((GameObject*)obj)->childObjs[0] != NULL)
        {
            ObjLink_DetachChild(obj, sub);
        }
        if (p2 == 0)
        {
            Obj_FreeObject((int*)state[0]);
        }
    }
}

extern f32 gCcLightfootDistSentinel;
extern f32 lbl_803E4678;
extern f32 lbl_803E467C;

#pragma dont_inline on
#pragma scheduling on
void fn_801AA878(u8* state, int* targetObj, f32 dist)
{
    s16 move;
    if (gCcLightfootDistSentinel == dist)
    {
        state[16] = 12;
        return;
    }
    if ((state[17] & 2) != 0)
    {
        state[16] = 1;
        return;
    }
    if (dist < lbl_803E4678)
    {
        move = ((GameObject*)targetObj)->anim.currentMove;
        if (move == 24 && ((GameObject*)targetObj)->anim.currentMoveProgress > lbl_803E467C)
        {
            state[16] = 8;
            return;
        }
        if (move == 25)
        {
            state[16] = 5;
            return;
        }
        state[16] = 11;
        return;
    }
    state[16] = 2;
}
#pragma dont_inline reset

extern f32 lbl_803E4670;

#pragma scheduling off
int ccqueen_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern u32 ObjLink_DetachChild();
    int* state = ((GameObject*)obj)->extra;
    if (animUpdate->eventCount != 0)
    {
        int i;
        for (i = 0; (u8)i < animUpdate->eventCount; i++)
        {
            int cmd = animUpdate->eventIds[(u8)i];
            switch (cmd)
            {
            case 1:
                if (((GameObject*)obj)->childObjs[0] != NULL)
                {
                    ObjLink_DetachChild(obj, *(int*)state);
                }
                break;
            case 2:
                (*gWaterfxInterface)->spawnSplashBurst(
                    (void*)obj, ((GameObject*)obj)->anim.worldPosX,
                    ((GameObject*)obj)->anim.worldPosY,
                    ((GameObject*)obj)->anim.worldPosZ, lbl_803E4670);
                break;
            }
        }
    }
    return 0;
}

extern int playerIsDisguised(int obj);
extern f32 lbl_803E4680;
extern f32 lbl_803E4684;
extern f32 lbl_803E4688;
extern f32 gCcLightfootTurnRate;
extern f32 lbl_803E4690;
extern f32 lbl_803E4694;
extern f32 lbl_803E4698;
extern u8 gCcLightfootAnimTable[];
extern u8 gCcLightfootHitCooldown[8];
extern int getAngle(float y, float x);
extern f32 fn_8014C5D0(register int obj);
extern void fn_8014C66C(int obj, int target);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_FreeObject(int o);
extern void Obj_SetModelColorFadeRecursive(int obj, int frames, int red, int green, int blue, int startAtHalf);
extern int ObjList_FindObjectById(int id);
extern void objfx_spawnHitEmitterAtPos(f32* pos, u8 a, u8 b, u8 c, u8 d);

typedef struct LightfootAnimTable
{
    u8 stateFlags[0x10]; /* 0x00: per-state flag bits (bit 0 = active hitbox, bit 1 = blend in) */
    u8 animIds[0x10];    /* 0x10: per-state anim/move id */
    f32 animSpeeds[15];  /* 0x20: per-state advance speed */
} LightfootAnimTable;

STATIC_ASSERT(sizeof(LightfootAnimTable) == 0x5C);

void cclightfoot_update(int obj)
{
    extern f32 getXZDistance(f32* a, f32* b);
    extern u32 ObjLink_DetachChild();
    LightfootAnimTable* tbl = (LightfootAnimTable*)gCcLightfootAnimTable;
    u32 fallback;
    int* state = ((GameObject*)obj)->extra;
    u32 targetObj;
    s16 angle;
    u32 o2;
    u32 o1;
    u32 oFar;
    u32 oNear;
    s16 diff;
    int valid;
    u32 off;
    u8 i;
    f32 dist;
    int hitObj;
    f32 dists[2];
    f32 hitPos[3];
    int animId;
    s16 t;
    u8 m;

    fallback = 0;
    if (tbl->stateFlags[*((u8*)state + 0x10)] & 1)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    }
    o1 = state[2];
    if (o1 != 0)
    {
        if (!(fn_8014C5D0(o1) > lbl_803E4680))
        {
            valid = 0;
        }
        else
        {
            valid = GameBit_Get(*(s16*)(*(int*)&((GameObject*)o1)->anim.placementData + 0x18)) != 0 ? 0 : 1;
        }
        if (valid == 0)
        {
            goto cc_else;
        }
        o2 = state[3];
        if (!(fn_8014C5D0(o2) > lbl_803E4680))
        {
            valid = 0;
        }
        else
        {
            valid = GameBit_Get(*(s16*)(*(int*)&((GameObject*)o2)->anim.placementData + 0x18)) != 0 ? 0 : 1;
        }
        if (valid == 0)
        {
            goto cc_else;
        }
        {
            dist = getXZDistance((f32*)(state[1] + 0x18), (f32*)(state[3] + 0x18));
            if (getXZDistance((f32*)(state[1] + 0x18), (f32*)(state[2] + 0x18)) < dist)
            {
                oNear = state[2];
                oFar = state[3];
            }
            else
            {
                oNear = state[3];
                oFar = state[2];
            }
            if ((getXZDistance((f32*)(obj + 0x18), (f32*)(state[1] + 0x18)) < lbl_803E4684
                    || (void*)Player_GetTargetObject(state[1]) == *(void**)(state + 2)
                    || (void*)Player_GetTargetObject(state[1]) == *(void**)(state + 3))
                && playerIsDisguised(state[1]) == 0)
            {
                if ((void*)Player_GetTargetObject(state[1]) == (void*)oFar)
                {
                    u32 tmp = oFar ^ oNear;
                    oNear = oNear ^ tmp;
                    oFar = tmp ^ oNear;
                }
                fn_8014C66C(oNear, state[1]);
                fn_8014C66C(oFar, obj);
                targetObj = oFar;
                dist = getXZDistance((f32*)(obj + 0x18), (f32*)(oFar + 0x18));
            }
            else
            {
                for (i = 0; i < 2; i++)
                {
                    off = i * 4;
                    *(f32*)((u8*)dists + off) =
                        getXZDistance((f32*)(obj + 0x18), (f32*)(*(int*)((u8*)state + off + 8) + 0x18));
                    fn_8014C66C(*(int*)((u8*)state + off + 8), obj);
                }
                if (dists[0] < dists[1])
                {
                    targetObj = state[2];
                    dist = dists[0];
                }
                else
                {
                    targetObj = state[3];
                    dist = dists[1];
                }
            }
        }
        goto cc_endif;
    cc_else:
        {
            o2 = state[2];
            if (!(fn_8014C5D0(o2) > lbl_803E4680))
            {
                valid = 0;
            }
            else
            {
                valid = GameBit_Get(*(s16*)(*(int*)&((GameObject*)o2)->anim.placementData + 0x18)) != 0 ? 0 : 1;
            }
            if (valid != 0)
            {
                fallback = state[2];
            }
            o2 = state[3];
            if (!(fn_8014C5D0(o2) > lbl_803E4680))
            {
                valid = 0;
            }
            else
            {
                valid = GameBit_Get(*(s16*)(*(int*)&((GameObject*)o2)->anim.placementData + 0x18)) != 0 ? 0 : 1;
            }
            if (valid != 0)
            {
                fallback = state[3];
            }
            if (fallback != 0)
            {
                dist = getXZDistance((f32*)(state[1] + 0x18), (f32*)(fallback + 0x18));
                if ((getXZDistance((f32*)(obj + 0x18), (f32*)(fallback + 0x18)) < dist
                        && (void*)Player_GetTargetObject(state[1]) != (void*)fallback)
                    || playerIsDisguised(state[1]) != 0)
                {
                    fn_8014C66C(fallback, obj);
                }
                else
                {
                    fn_8014C66C(fallback, state[1]);
                }
                targetObj = fallback;
                dist = getXZDistance((f32*)(obj + 0x18), (f32*)(fallback + 0x18));
            }
            else
            {
                targetObj = state[1];
                dist = gCcLightfootDistSentinel;
            }
        }
    cc_endif:;
        angle = getAngle(-(((GameObject*)targetObj)->anim.localPosX - ((GameObject*)obj)->anim.localPosX),
                              -(((GameObject*)targetObj)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ));
        diff = (s16)(((GameObject*)obj)->anim.rotX - (u16)angle);
        if (diff > 0x8000)
        {
            diff = (s16)(diff - 0xffff);
        }
        if (diff < -0x8000)
        {
            diff = (s16)(diff + 0xffff);
        }
        if (diff > 0x1000)
        {
            *((u8*)state + 0x11) |= 2;
        }
        else if (diff < -0x1000)
        {
            *((u8*)state + 0x11) |= 2;
        }
        else
        {
            *((u8*)state + 0x11) &= ~2;
        }
    }
    if (*((u8*)state + 0x10) <= 0xb)
    {
        *(f32*)(state + 5) -= timeDelta;
        if (*(f32*)(state + 5) < lbl_803E4680)
        {
            *(f32*)(state + 5) = (f32)(int)
            randomGetRange(0xb4, 0x12c);
            Sfx_PlayFromObject(obj, 0x134);
        }
    }
    switch (*((u8*)state + 0x10))
    {
    case 0:
        if (GameBit_Get(GAMEBIT_LIGHTFOOT_TRIGGERED) != 0)
        {
            *((u8*)state + 0x10) = 0xe;
        }
        else
        {
            if (Obj_IsLoadingLocked() != 0)
            {
                state[0] = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x6f1), 5, -1, -1,
                                           *(int*)&((GameObject*)obj)->anim.parent);
                ObjLink_AttachChild(obj, state[0], 0);
            }
            state[1] = (int)Obj_GetPlayerObject();
            state[2] = ObjList_FindObjectById(CCLIGHTFOOT_TARGET_ACTOR_A);
            state[3] = ObjList_FindObjectById(CCLIGHTFOOT_TARGET_ACTOR_B);
            *((u8*)state + 0x10) = 1;
            *(f32*)(state + 5) = (f32)(int)
            randomGetRange(0xb4, 0x12c);
        }
        break;
    case 1:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E467C && ((GameObject*)obj)->anim.currentMoveProgress
            < lbl_803E4688)
        {
            if (diff > 0x400)
            {
                ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX - (int)(gCcLightfootTurnRate * timeDelta));
            }
            else if (diff < -0x400)
            {
                ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + (int)(gCcLightfootTurnRate * timeDelta));
            }
            else
            {
                ((GameObject*)obj)->anim.rotX = angle;
            }
        }
        if (*((u8*)state + 0x11) & 1)
        {
            fn_801AA878((u8*)state, (int*)targetObj, dist);
        }
        break;
    case 2:
        if (*((u8*)state + 0x11) & 1)
        {
            if (dist < lbl_803E4678)
            {
                *((u8*)state + 0x10) = 4;
            }
            else
            {
                *((u8*)state + 0x10) = 3;
            }
        }
        break;
    case 3:
        if (*((u8*)state + 0x11) & 1)
        {
            *((u8*)state + 0x10) = 4;
        }
        break;
    case 4:
        if (*((u8*)state + 0x11) & 1)
        {
            fn_801AA878((u8*)state, (int*)targetObj, dist);
        }
        break;
    case 5:
        if (((GameObject*)targetObj)->anim.currentMove != 0x19)
        {
            *((u8*)state + 0x10) = 7;
        }
        if (*((u8*)state + 0x11) & 1)
        {
            *((u8*)state + 0x10) = 6;
        }
        break;
    case 6:
        if (((GameObject*)targetObj)->anim.currentMove != 0x19)
        {
            *((u8*)state + 0x10) = 7;
        }
        break;
    case 7:
        t = ((GameObject*)targetObj)->anim.currentMove;
        if (t == 0x18 && ((GameObject*)targetObj)->anim.currentMoveProgress > lbl_803E467C)
        {
            *((u8*)state + 0x10) = 8;
        }
        else if (t == 0x19)
        {
            *((u8*)state + 0x10) = 5;
        }
        else if (*((u8*)state + 0x11) & 1)
        {
            fn_801AA878((u8*)state, (int*)targetObj, dist);
        }
        break;
    case 8:
        t = ((GameObject*)targetObj)->anim.currentMove;
        if (t != 0x18 ||
            (t == 0x18 && ((GameObject*)targetObj)->anim.currentMoveProgress < lbl_803E467C))
        {
            *((u8*)state + 0x10) = 0xa;
        }
        if (*((u8*)state + 0x11) & 1)
        {
            *((u8*)state + 0x10) = 9;
        }
        break;
    case 9:
        t = ((GameObject*)targetObj)->anim.currentMove;
        if (t != 0x18 ||
            (t == 0x18 && ((GameObject*)targetObj)->anim.currentMoveProgress < lbl_803E467C))
        {
            *((u8*)state + 0x10) = 0xa;
        }
        break;
    case 10:
        t = ((GameObject*)targetObj)->anim.currentMove;
        if (t == 0x18 && ((GameObject*)targetObj)->anim.currentMoveProgress > lbl_803E467C)
        {
            *((u8*)state + 0x10) = 8;
        }
        else if (t == 0x19)
        {
            *((u8*)state + 0x10) = 5;
        }
        else if (*((u8*)state + 0x11) & 1)
        {
            fn_801AA878((u8*)state, (int*)targetObj, dist);
        }
        break;
    case 0xb:
        fn_801AA878((u8*)state, (int*)targetObj, dist);
        break;
    case 0xc:
        if (GameBit_Get(GAMEBIT_LIGHTFOOT_TRIGGERED) != 0)
        {
            if (GameBit_Get(GAMEBIT_CC_COMPLETE) != 0)
            {
                *((u8*)state + 0x10) = 0xe;
            }
        }
        else
        {
            if (ObjTrigger_IsSet(obj) != 0)
            {
                GameBit_Set(GAMEBIT_LIGHTFOOT_TRIGGERED, 1);
            }
            else if (*((u8*)state + 0x11) & 2)
            {
                *((u8*)state + 0x10) = 0xd;
            }
        }
        break;
    case 0xd:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E467C && ((GameObject*)obj)->anim.currentMoveProgress
            < lbl_803E4688)
        {
            if (diff > 0x400)
            {
                ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX - (int)(gCcLightfootTurnRate * timeDelta));
            }
            else if (diff < -0x400)
            {
                ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + (int)(gCcLightfootTurnRate * timeDelta));
            }
            else
            {
                ((GameObject*)obj)->anim.rotX = angle;
            }
        }
        if (*((u8*)state + 0x11) & 1)
        {
            *((u8*)state + 0x10) = 0xc;
        }
        break;
    case 0xe:
        if ((u32)state[0] != 0)
        {
            if (((GameObject*)obj)->childObjs[0] != NULL)
            {
                ObjLink_DetachChild(obj, state[0]);
            }
            Obj_FreeObject(state[0]);
            state[0] = 0;
        }
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x8000);
        ObjHits_DisableObject(obj);
        return;
    }
    m = *((u8*)state + 0x10);
    if (m >= 5 && m <= 0xa)
    {
        if (ObjHits_PollPriorityHitWithCooldown(obj, gCcLightfootHitCooldown, 0, hitPos) != 0)
        {
            if (getXZDistance((f32*)(obj + 0x18), (f32*)(state[1] + 0x18)) < lbl_803E4690)
            {
                objfx_spawnHitEmitterAtPos(hitPos, 8, 0xff, 0xff, 0x78);
                objLightFn_8009a1dc((void*)obj, lbl_803E4694, hitPos, 4, 0);
            }
            Sfx_PlayFromObject(obj, 0x129);
        }
    }
    else
    {
        if (ObjHits_GetPriorityHit(obj, &hitObj, 0, 0) != 0)
        {
            t = ((GameObject*)hitObj)->anim.seqId;
            if (t == 0x11 || t == 0x33)
            {
                Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
            }
        }
    }
    m = *((u8*)state + 0x10);
    {
        u8* pa = &tbl->stateFlags[m];
        animId = pa[0x10];
        if (animId != ((GameObject*)obj)->anim.currentMove)
        {
            if (pa[0] & 2)
            {
                ObjAnim_SetCurrentMove(obj, animId, lbl_803E4698, 0);
            }
            else
            {
                ObjAnim_SetCurrentMove(obj, animId, lbl_803E4680, 0);
            }
        }
    }
    if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, tbl->animSpeeds[*((u8*)state + 0x10)],
                                                                    timeDelta,
                                                                    NULL) != 0)
    {
        *((u8*)state + 0x11) |= 1;
    }
    else
    {
        *((u8*)state + 0x11) &= ~1;
    }
}
