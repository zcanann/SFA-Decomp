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

/* Per-object Lightfoot state block (obj->extra, cclightfoot_getExtraSize = 0x18). */
typedef struct CcLightfootState
{
    int childObj;   /* 0x00: spawned child marker object handle */
    int playerObj;  /* 0x04: cached player object */
    int targetA;    /* 0x08: target actor A object */
    int targetB;    /* 0x0C: target actor B object */
    u8 state;       /* 0x10: state-machine state */
    u8 flags;       /* 0x11: bit0 = hit/advance landed, bit1 = facing target off-axis */
    u8 pad[2];      /* 0x12 */
    f32 sfxTimer;   /* 0x14: countdown to next idle sfx */
} CcLightfootState;

STATIC_ASSERT(sizeof(CcLightfootState) == 0x18);
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/dll/DIM/DIMsnowball.h"
#include "main/dll/player_target.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/objhits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#define CCLIGHTFOOT_OBJFLAG_UPDATE_DISABLED 0x8000
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
    CcLightfootState* state = ((GameObject*)obj)->extra;
    void* sub = (void*)state->childObj;
    if (sub != NULL)
    {
        if (((GameObject*)obj)->childObjs[0] != NULL)
        {
            ObjLink_DetachChild(obj, (int)sub);
        }
        if (p2 == 0)
        {
            Obj_FreeObject(state->childObj);
        }
    }
}

extern f32 gCcLightfootDistSentinel;
extern f32 lbl_803E4678;
extern f32 lbl_803E467C;

#pragma dont_inline on
#pragma scheduling on
void fn_801AA878(CcLightfootState* state, int* targetObj, f32 dist)
{
    s16 move;
    if (gCcLightfootDistSentinel == dist)
    {
        state->state = 12;
        return;
    }
    if ((state->flags & 2) != 0)
    {
        state->state = 1;
        return;
    }
    if (dist < lbl_803E4678)
    {
        move = ((GameObject*)targetObj)->anim.currentMove;
        if (move == 24 && ((GameObject*)targetObj)->anim.currentMoveProgress > lbl_803E467C)
        {
            state->state = 8;
            return;
        }
        if (move == 25)
        {
            state->state = 5;
            return;
        }
        state->state = 11;
        return;
    }
    state->state = 2;
}
#pragma dont_inline reset

extern f32 lbl_803E4670;

#pragma scheduling off
int ccqueen_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern u32 ObjLink_DetachChild();
    CcLightfootState* state = ((GameObject*)obj)->extra;
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
                    ObjLink_DetachChild(obj, state->childObj);
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
    CcLightfootState* state = ((GameObject*)obj)->extra;
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
    if (tbl->stateFlags[state->state] & 1)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    }
    o1 = state->targetA;
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
        o2 = state->targetB;
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
            dist = getXZDistance((f32*)(state->playerObj + 0x18), (f32*)(state->targetB + 0x18));
            if (getXZDistance((f32*)(state->playerObj + 0x18), (f32*)(state->targetA + 0x18)) < dist)
            {
                oNear = state->targetA;
                oFar = state->targetB;
            }
            else
            {
                oNear = state->targetB;
                oFar = state->targetA;
            }
            if ((getXZDistance((f32*)(obj + 0x18), (f32*)(state->playerObj + 0x18)) < lbl_803E4684
                    || (void*)Player_GetTargetObject(state->playerObj) == (void*)state->targetA
                    || (void*)Player_GetTargetObject(state->playerObj) == (void*)state->targetB)
                && playerIsDisguised(state->playerObj) == 0)
            {
                if ((void*)Player_GetTargetObject(state->playerObj) == (void*)oFar)
                {
                    u32 tmp = oFar ^ oNear;
                    oNear = oNear ^ tmp;
                    oFar = tmp ^ oNear;
                }
                fn_8014C66C(oNear, state->playerObj);
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
                    targetObj = state->targetA;
                    dist = dists[0];
                }
                else
                {
                    targetObj = state->targetB;
                    dist = dists[1];
                }
            }
        }
        goto cc_endif;
    cc_else:
        {
            o2 = state->targetA;
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
                fallback = state->targetA;
            }
            o2 = state->targetB;
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
                fallback = state->targetB;
            }
            if (fallback != 0)
            {
                dist = getXZDistance((f32*)(state->playerObj + 0x18), (f32*)(fallback + 0x18));
                if ((getXZDistance((f32*)(obj + 0x18), (f32*)(fallback + 0x18)) < dist
                        && (void*)Player_GetTargetObject(state->playerObj) != (void*)fallback)
                    || playerIsDisguised(state->playerObj) != 0)
                {
                    fn_8014C66C(fallback, obj);
                }
                else
                {
                    fn_8014C66C(fallback, state->playerObj);
                }
                targetObj = fallback;
                dist = getXZDistance((f32*)(obj + 0x18), (f32*)(fallback + 0x18));
            }
            else
            {
                targetObj = state->playerObj;
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
            state->flags |= 2;
        }
        else if (diff < -0x1000)
        {
            state->flags |= 2;
        }
        else
        {
            state->flags &= ~2;
        }
    }
    if (state->state <= 0xb)
    {
        state->sfxTimer -= timeDelta;
        if (state->sfxTimer < lbl_803E4680)
        {
            state->sfxTimer = (f32)(int)
            randomGetRange(0xb4, 0x12c);
            Sfx_PlayFromObject(obj, SFXTRIG_trwhin4);
        }
    }
    switch (state->state)
    {
    case 0:
        if (GameBit_Get(GAMEBIT_LIGHTFOOT_TRIGGERED) != 0)
        {
            state->state = 0xe;
        }
        else
        {
            if (Obj_IsLoadingLocked() != 0)
            {
                state->childObj = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x6f1), 5, -1, -1,
                                           *(int*)&((GameObject*)obj)->anim.parent);
                ObjLink_AttachChild(obj, state->childObj, 0);
            }
            state->playerObj = (int)Obj_GetPlayerObject();
            state->targetA = ObjList_FindObjectById(CCLIGHTFOOT_TARGET_ACTOR_A);
            state->targetB = ObjList_FindObjectById(CCLIGHTFOOT_TARGET_ACTOR_B);
            state->state = 1;
            state->sfxTimer = (f32)(int)
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
        if (state->flags & 1)
        {
            fn_801AA878(state, (int*)targetObj, dist);
        }
        break;
    case 2:
        if (state->flags & 1)
        {
            if (dist < lbl_803E4678)
            {
                state->state = 4;
            }
            else
            {
                state->state = 3;
            }
        }
        break;
    case 3:
        if (state->flags & 1)
        {
            state->state = 4;
        }
        break;
    case 4:
        if (state->flags & 1)
        {
            fn_801AA878(state, (int*)targetObj, dist);
        }
        break;
    case 5:
        if (((GameObject*)targetObj)->anim.currentMove != 0x19)
        {
            state->state = 7;
        }
        if (state->flags & 1)
        {
            state->state = 6;
        }
        break;
    case 6:
        if (((GameObject*)targetObj)->anim.currentMove != 0x19)
        {
            state->state = 7;
        }
        break;
    case 7:
        t = ((GameObject*)targetObj)->anim.currentMove;
        if (t == 0x18 && ((GameObject*)targetObj)->anim.currentMoveProgress > lbl_803E467C)
        {
            state->state = 8;
        }
        else if (t == 0x19)
        {
            state->state = 5;
        }
        else if (state->flags & 1)
        {
            fn_801AA878(state, (int*)targetObj, dist);
        }
        break;
    case 8:
        t = ((GameObject*)targetObj)->anim.currentMove;
        if (t != 0x18 ||
            (t == 0x18 && ((GameObject*)targetObj)->anim.currentMoveProgress < lbl_803E467C))
        {
            state->state = 0xa;
        }
        if (state->flags & 1)
        {
            state->state = 9;
        }
        break;
    case 9:
        t = ((GameObject*)targetObj)->anim.currentMove;
        if (t != 0x18 ||
            (t == 0x18 && ((GameObject*)targetObj)->anim.currentMoveProgress < lbl_803E467C))
        {
            state->state = 0xa;
        }
        break;
    case 10:
        t = ((GameObject*)targetObj)->anim.currentMove;
        if (t == 0x18 && ((GameObject*)targetObj)->anim.currentMoveProgress > lbl_803E467C)
        {
            state->state = 8;
        }
        else if (t == 0x19)
        {
            state->state = 5;
        }
        else if (state->flags & 1)
        {
            fn_801AA878(state, (int*)targetObj, dist);
        }
        break;
    case 0xb:
        fn_801AA878(state, (int*)targetObj, dist);
        break;
    case 0xc:
        if (GameBit_Get(GAMEBIT_LIGHTFOOT_TRIGGERED) != 0)
        {
            if (GameBit_Get(GAMEBIT_CC_COMPLETE) != 0)
            {
                state->state = 0xe;
            }
        }
        else
        {
            if (ObjTrigger_IsSet(obj) != 0)
            {
                GameBit_Set(GAMEBIT_LIGHTFOOT_TRIGGERED, 1);
            }
            else if (state->flags & 2)
            {
                state->state = 0xd;
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
        if (state->flags & 1)
        {
            state->state = 0xc;
        }
        break;
    case 0xe:
        if ((u32)state->childObj != 0)
        {
            if (((GameObject*)obj)->childObjs[0] != NULL)
            {
                ObjLink_DetachChild(obj, state->childObj);
            }
            Obj_FreeObject(state->childObj);
            state->childObj = 0;
        }
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | CCLIGHTFOOT_OBJFLAG_UPDATE_DISABLED);
        ObjHits_DisableObject(obj);
        return;
    }
    m = state->state;
    if (m >= 5 && m <= 0xa)
    {
        if (ObjHits_PollPriorityHitWithCooldown(obj, gCcLightfootHitCooldown, 0, hitPos) != 0)
        {
            if (getXZDistance((f32*)(obj + 0x18), (f32*)(state->playerObj + 0x18)) < lbl_803E4690)
            {
                objfx_spawnHitEmitterAtPos(hitPos, 8, 0xff, 0xff, 0x78);
                objLightFn_8009a1dc((void*)obj, lbl_803E4694, hitPos, 4, 0);
            }
            Sfx_PlayFromObject(obj, SFXTRIG_swdtest222);
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
    m = state->state;
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
    if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, tbl->animSpeeds[state->state],
                                                                    timeDelta,
                                                                    NULL) != 0)
    {
        state->flags |= 1;
    }
    else
    {
        state->flags &= ~1;
    }
}
