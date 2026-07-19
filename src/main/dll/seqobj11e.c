/*
 * seqObj11E - shared baddie-behavior handlers dispatched from the
 * enemy DLL (dll_00C9_enemy) by object type id. Each handler operates on
 * a GameObject plus its BaddieState scratch block; the pairs below are
 * (init, update) sets plus hit/reaction callbacks selected per type:
 *
 *   guardClaw_init / fn_80152514: a child-zapping curve-follower. Init seeds
 *     speed/scale/state flags from the placement row; update runs a child-
 *     zap timer, advances along a rom curve, steps heading from the curve
 *     tangent, plays landing/laser sfx, emits light-pulse + masked-hit fx
 *     while the active flag (objectFlags 0x800) is set, clamps vertical
 *     velocity, and spawns/parents a spark child object.
 *   gcRobotPatrol_init / mikaladon_update: a firefly hover. Init seeds state; update
 *     drives a circular drift, bobs between two heights, periodically
 *     spawns a dropped object, and runs ambient sfx timers.
 *   fn_80152040: a 12-byte-row state-table driver (gSeq11EStateTable) that
 *     advances on GameBit + sequence flags and kicks the matching anim.
 *   gcRobotLight_init: spawns and sets up a child object at the parent's pos.
 *   gcRobotPatrol_updateWhileFrozen / mikaladon_updateWhileFrozen: hit/reaction message callbacks.
 *
 * Object type ids handled (from the enemy dispatch table): 0xd8/0x281
 * (state-table), 0x613 (curve-follower update), 0x642 (firefly).
 */
#include "main/audio/sfx_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/obj_link.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/objtexture.h"
#include "main/dll/seqObj11E.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/seqobj11d_ext.h"
#include "main/dll/groundbaddiepush_ext.h"
#include "main/dll/dll_00C9_enemy_ext.h"
#include "main/dll/dll_0150_gcrobotlightbea.h"

int lbl_803DBCA8[2] = {2, 3};
f32 lbl_803DBCB0 = 0.018f;
f32 lbl_803DBCB4 = 240.0f;

/* gcRobotPatrol (mikaladon_update): periodically dropped object; parented back to
 * the dropper via +0xC4 and announced with SFX 0x249. */
#define SEQOBJ11E_GCROBOT_DROP_OBJ 0x6b5

typedef void (*SeqObj11ESetMovePointerStateFn)(GameObject* obj, void* state, int moveId, f32 speed, int p5,
                                               int flags);

/* fn_80152040: state-table driver: walks the 12-byte gSeq11EStateTable state
 * rows, advancing on GameBit + sequence flags and kicking the matching anim. */

typedef struct
{
    f32 animSpeed; /* 0x0 */
    u32 unk4;      /* 0x4 */
    u8 anim;       /* 0x8 */
    u8 next;       /* 0x9 */
    u8 alt;        /* 0xa */
    u8 flagB;      /* 0xb */
} Seq11ERow;

extern Seq11ERow gSeq11EStateTable[];

void fn_80152040(int* obj, u8* state)
{
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    u32 flags;

    if (((BaddieState*)state)->userData1 == 2 && mainGetBit(*(s16*)((char*)def + 0x1c)) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
            (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
        if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
        {
            fn_80151C68((int)obj, state);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
            (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    }
    flags = ((BaddieState*)state)->controlFlags;
    if (flags & BADDIE_CONTROL_JUST_TRIGGERED)
    {
        if (gSeq11EStateTable[((BaddieState*)state)->userData1].unk4 != 0)
        {
            ((BaddieState*)state)->controlFlags = flags | (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
        }
    }
    flags = ((BaddieState*)state)->controlFlags;
    if (flags & BADDIE_CONTROL_SEQUENCE_DRIVEN)
    {
        int anim;
        u8* animTbl;

        if (((BaddieState*)state)->userData1 == 0)
        {
            if (flags & 0x20000000)
            {
                if (mainGetBit(*(s16*)((char*)def + 0x1c)) != 0)
                {
                    ((BaddieState*)state)->userData1 = gSeq11EStateTable[((BaddieState*)state)->userData1].alt;
                }
                else
                {
                    ((BaddieState*)state)->userData1 = gSeq11EStateTable[((BaddieState*)state)->userData1].next;
                }
            }
        }
        else if (((BaddieState*)state)->userData1 == 2)
        {
            if (mainGetBit(*(s16*)((char*)def + 0x1c)) != 0 || !(((BaddieState*)state)->controlFlags & 0x20000000))
            {
                ((BaddieState*)state)->userData1 = gSeq11EStateTable[((BaddieState*)state)->userData1].next;
            }
        }
        else if (((BaddieState*)state)->userData1 == 3)
        {
            if (mainGetBit(*(s16*)((char*)def + 0x1c)) != 0)
            {
                ((BaddieState*)state)->userData1 = gSeq11EStateTable[((BaddieState*)state)->userData1].alt;
            }
            else
            {
                ((BaddieState*)state)->userData1 = gSeq11EStateTable[((BaddieState*)state)->userData1].next;
            }
        }
        else
        {
            ((BaddieState*)state)->userData1 = gSeq11EStateTable[((BaddieState*)state)->userData1].next;
        }
        anim = ((GameObject*)obj)->anim.currentMove;
        if (anim != (animTbl = (u8*)gSeq11EStateTable + 8)[((BaddieState*)state)->userData1 * 12])
        {
            if (animTbl[((BaddieState*)state)->userData1 * 12] != 0 &&
                animTbl[((BaddieState*)state)->userData1 * 12] != 4)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_baddie_eggsnatch_carry3);
            }
            ((SeqObj11ESetMovePointerStateFn)fn_8014D08C)(
                (GameObject*)obj, state, animTbl[((BaddieState*)state)->userData1 * 12],
                *(f32*)((u8*)gSeq11EStateTable + ((BaddieState*)state)->userData1 * 12), 0, 0xf);
        }
    }
    if (gSeq11EStateTable[((BaddieState*)state)->userData1].flagB != 0)
    {
        groundBaddiePushPlayerOut((int)obj, state);
    }
}

void guardClaw_init(int* obj, u8* state)
{
    int* sub = *(int**)&((GameObject*)obj)->anim.placementData;
    f32 fz;
    ((BaddieState*)state)->speedScale = 200.0f;
    ((BaddieState*)state)->unk2A8 = 300.0f;
    ((BaddieState*)state)->unk2E4 = 1;
    ((BaddieState*)state)->unk2E4 |= 0xC80;
    ((BaddieState*)state)->unk308 = 0.0055555557f;
    ((BaddieState*)state)->animDeltaScale = 0.17f;
    ((BaddieState*)state)->unk304 = 0.97f;
    ((BaddieState*)state)->unk320 = 0;
    fz = 1.0f;
    *(f32*)&((BaddieState*)state)->eventFlags = fz;
    ((BaddieState*)state)->unk321 = 0;
    ((BaddieState*)state)->unk318 = fz;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fz;
    if (*((s8*)sub + 0x2e) != -1)
    {
        *(int*)&((BaddieState*)state)->controlFlags |= 1;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
}

void gcRobotPatrol_updateWhileFrozen(GameObject* obj, int state, int unused, int msg, int wpad0, int wpad1, void* wpad2, int wpad3)
{
    int sub;
    f32 fz;

    sub = *(int*)&obj->anim.placementData;
    if (msg == 16 || msg == 17)
    {
        return;
    }
    Sfx_PlayFromObject((u32)obj, SFXTRIG_wp_pole1_c_23);
    Sfx_PlayFromObject((u32)obj, SFXTRIG_en_lrope_powerdown);
    ((BaddieState*)state)->reactionFlags |= 0x8;
    *(f32*)(state + 0x32c) = (f32)(u32)(u16) * (s16*)(sub + 0x2c);
    fn_8014D08C((GameObject*)(obj), state, 1, 2.5f, 0, 0);
    *(u32*)&((BaddieState*)state)->unk2E4 &= ~0x20LL;
    fz = 0.0f;
    obj->anim.velocityZ = 0.0f;
    obj->anim.velocityY = fz;
    obj->anim.velocityX = fz;
}

/* fn_80152514: main update: child-zap timer, curve follow, heading steps,
 * landing sfx, light-pulse fx, child spark spawn. */


typedef struct
{
    u8 pad[8];
    f32 a;
    f32 b;
    f32 c;
    f32 d;
} SeqFxParams;

void fn_80152514(int* obj, u8* state)
{
    int* def;
    RomCurveWalker* path;
    int attached;
    s16 spd;
    SeqFxParams fx;

    def = *(int**)&((GameObject*)obj)->anim.placementData;
    path = *(RomCurveWalker**)state;
    if (*(f32*)(state + 0x32c) > 0.0f)
    {
        int* child = ((GameObject*)obj)->childObjs[0];
        if (child != 0)
        {
            Obj_FreeObject((GameObject*)child);
            ObjLink_DetachChild((GameObject*)obj, (GameObject*)((GameObject*)obj)->childObjs[0]);
            *(int*)&((GameObject*)obj)->childObjs[0] = 0;
        }
        *(f32*)(state + 0x32c) = *(f32*)(state + 0x32c) - timeDelta;
        if (*(f32*)(state + 0x32c) <= 0.0f)
        {
            *(f32*)(state + 0x32c) = 0.0f;
            *(u32*)&((BaddieState*)state)->unk2E4 |= 0x20;
            Sfx_StopObjectChannel((u32)obj, 4);
            ((SeqObj11ESetMovePointerStateFn)fn_8014D08C)((GameObject*)obj, state, 0, 1.0f, 0, 0);
        }
        else if (!(*(u32*)&((BaddieState*)state)->unk2E4 & 0x20))
        {
            return;
        }
    }
    if (((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW)
    {
        int step;

        if (Curve_AdvanceAlongPath(&path->curve, ((BaddieState*)state)->pathStep) != 0 || path->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(path) != 0)
            {
                if ((*gRomCurveInterface)
                        ->initCurve(*(RomCurveWalker**)state, obj, 700.0f, (int*)&lbl_803DBCA8, -1) != 0)
                {
                    ((BaddieState*)state)->controlFlags &= ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
                }
            }
        }
        ((GameObject*)obj)->anim.velocityX = (path->posX - ((GameObject*)obj)->anim.localPosX) / timeDelta;
        ((GameObject*)obj)->anim.velocityZ = (path->posZ - ((GameObject*)obj)->anim.localPosZ) / timeDelta;
        step = (s8) * ((u8*)def + 0x2a);
        if (step == 0)
        {
            baddieTurnTowardPoint((GameObject*)obj, (int)state, path->posX, path->posZ, 0xf, 0);
        }
        else if (((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW)
        {
            spd = step << 8;
            if ((int)(10.0f * path->tangentY) >= 0)
            {
                step = spd;
            }
            else
            {
                step = -spd;
            }
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX - step;
            baddieTurnTowardPoint((GameObject*)obj, (int)state, path->posX, path->posZ, 0xf, 0);
            if ((int)(10.0f * path->tangentY) >= 0)
            {
                step = spd;
            }
            else
            {
                step = -spd;
            }
            ((GameObject*)obj)->anim.rotX += step;
        }
        else
        {
            step = ((int)(10.0f * path->tangentY) >= 0) ? step : -step;
            ((GameObject*)obj)->anim.rotX += step;
        }
        if (((GameObject*)obj)->anim.localPosY - path->posY < -1.0f)
        {
            if (Sfx_IsPlayingFromObject((u32)obj, SFXTRIG_dn_boar1_c_18d) == 0)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_18d);
            }
            ((BaddieState*)state)->userData1 = 1;
        }
        else
        {
            ((BaddieState*)state)->userData1 = 0;
        }
    }
    else
    {
        if (((GameObject*)obj)->anim.localPosY - ((ObjPlacement*)def)->posY < -0.4f)
        {
            if (Sfx_IsPlayingFromObject((u32)obj, SFXTRIG_dn_boar1_c_18d) == 0)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_18d);
            }
            ((BaddieState*)state)->userData1 = 1;
        }
        else
        {
            ((BaddieState*)state)->userData1 = 0;
        }
        ((GameObject*)obj)->anim.rotX += *(s8*)((char*)def + 0x2a);
    }
    if (((BaddieState*)state)->userData1 != 0)
    {
        ((GameObject*)obj)->anim.velocityY += lbl_803DBCB0 * timeDelta;
    }
    if (((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_RENDERED)
    {
        f32 z = 0.0f;
        fx.b = z;
        fx.c = z;
        fx.d = z;
        fx.a = 1.0f;
        objfx_spawnLightPulseLegacy((GameObject*)(obj), 0.5f, 2, 0, 6, 0.25f, &fx);
        fx.c = 12.0f;
        objfx_spawnMaskedHitEffect(obj, 0.4f, 1, 6, 0x20, &fx);
        fx.b = 0.0f;
        z = -30.0f;
        fx.c = z;
        fx.d = z;
    }
    if (((GameObject*)obj)->anim.velocityY < -0.5f)
    {
        ((GameObject*)obj)->anim.velocityY = -0.5f;
    }
    else if (((GameObject*)obj)->anim.velocityY > 0.5f)
    {
        ((GameObject*)obj)->anim.velocityY = 0.5f;
    }
    if (0.0f == *(f32*)(state + 0x32c))
    {
        int* child2;

        if (*(s8*)((char*)def + 0x2e) != -1 && (child2 = ((GameObject*)obj)->childObjs[0]) != 0 &&
            fn_801A0174(child2) != 0)
        {
            ObjHits_RecordObjectHit(Obj_GetPlayerObject(), (GameObject*)obj, 0x16, 2, 0);
            gcRobotLight_init((GameObject*)obj, 0x3b2);
            Sfx_PlayFromObject((u32)obj, SFXTRIG_wp_rolovr_6);
            *(f32*)(state + 0x32c) = lbl_803DBCB4;
        }
        if ((int)randomGetRange(0, (int)(1000.0f * oneOverTimeDelta)) == 0)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_sp_literun114);
        }
        child2 = ((GameObject*)obj)->childObjs[0];
        if (child2 != 0)
        {
            ObjTextureRuntimeSlot* tex = objFindTexture((GameObject*)(child2), 0, 0);
            int v;
            if (tex != 0)
            {
                v = tex->offsetS - 0x3c;
                if (v < 0)
                {
                    v += 0x2710;
                }
                tex->offsetS = v;
            }
        }
        else
        {
            GameObject* newObj;
            int flag;

            if (*(s8*)((char*)def + 0x2a) != 0)
            {
                attached = 1;
            }
            else
            {
                attached = 0;
            }
            newObj = gcRobotLight_init((GameObject*)obj, 0x639);
            flag = 0;
            if (*(s8*)((char*)def + 0x2a) != 0 && !(((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW))
            {
                flag = 1;
            }
            newObj->userData1 = flag;
            ObjLink_AttachChild((GameObject*)obj, newObj, attached);
        }
    }
}

GameObject* gcRobotLight_init(GameObject* obj, int childId)
{
    int sub;
    u8* setup;

    sub = *(int*)&obj->anim.placementData;
    Obj_GetPlayerObject();
    if (Obj_IsLoadingLocked() == 0)
        return NULL;
    setup = (u8*)Obj_AllocObjectSetup(36, childId);
    *(s16*)(setup + 0) = childId;
    ((ObjPlacement*)setup)->color[0] = ((ObjPlacement*)sub)->color[0];
    ((ObjPlacement*)setup)->color[2] = ((ObjPlacement*)sub)->color[2];
    ((ObjPlacement*)setup)->color[1] = 1;
    ((ObjPlacement*)setup)->color[3] = ((ObjPlacement*)sub)->color[3];
    ((ObjPlacement*)setup)->posX = obj->anim.localPosX;
    ((ObjPlacement*)setup)->posY = obj->anim.localPosY;
    ((ObjPlacement*)setup)->posZ = obj->anim.localPosZ;
    ((Seq11EChildSetup*)setup)->unk19 = 0;
    ((Seq11EChildSetup*)setup)->unk20 = 149;
    return Obj_SetupObject((ObjPlacement*)setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
}

void gcRobotPatrol_init(GameObject* obj, int state)
{
    f32 fz;

    ((BaddieState*)state)->speedScale = 60.0f;
    *(u32*)&((BaddieState*)state)->unk2E4 = 41;
    *(u32*)&((BaddieState*)state)->unk2E4 |= 0x7000;
    *(u32*)&((BaddieState*)state)->unk2E4 |= 0x20000LL;
    ((BaddieState*)state)->unk308 = 0.005f;
    ((BaddieState*)state)->animDeltaScale = 0.006f;
    ((BaddieState*)state)->unk304 = 0.99f;
    ((BaddieState*)state)->unk320 = 0;
    fz = 1.0f;
    *(f32*)&((BaddieState*)state)->eventFlags = fz;
    ((BaddieState*)state)->unk321 = 0;
    ((BaddieState*)state)->unk318 = fz;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fz;
    *(f32*)(state + 0x32c) = 0.0f;
    obj->anim.hitboxScale = 100.0f;
    Sfx_AddLoopedObjectSound((u32)obj, SFXTRIG_tr_bcrek1_c);
}

f32 lbl_803E2868 = 0.0f;
f32 lbl_803E286C = 60.0f;

void mikaladon_updateWhileFrozen(int obj, int state, int unused, int msg, int wpad0, int wpad1, void* wpad2, int wpad3)
{
    if (msg == 16 || msg == 17)
    {
        return;
    }
    Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_248);
    *(s16*)&((BaddieState*)state)->hitCounter = 0;
    *(u32*)&((BaddieState*)state)->unk2E4 |= 0x20;
    ((BaddieState*)state)->reactionFlags |= 0x8;
}

Seq11ERow gSeq11EStateTable[6] = {
    {3.0f, 0x1, 0, 1, 4, 1}, {2.0f, 0x0, 1, 2, 2, 1}, {3.0f, 0x1, 2, 3, 3, 1},
    {2.0f, 0x0, 7, 0, 4, 1}, {2.0f, 0x0, 3, 5, 5, 0}, {3.5f, 0x1, 4, 5, 5, 0},
};
