/*
 * gcRobotPatrol (GreatFox patrol robot) and mikaladon freeze-event behaviour,
 * split out of the seqobj11e DLL's guardClaw/gcRobotLight translation unit.
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

#define SEQOBJ11E_GCROBOT_DROP_OBJ 0x6b5

typedef void (*SeqObj11ESetMovePointerStateFn)(GameObject* obj, void* state, int moveId, f32 speed, int p5,
                                               int flags);

extern int lbl_803DBCA8[2];
extern f32 lbl_803DBCB0;
extern f32 lbl_803DBCB4;

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

/* gcRobotPatrol_update: main update: child-zap timer, curve follow, heading steps,
 * landing sfx, light-pulse fx, child spark spawn. */


typedef struct
{
    u8 pad[8];
    f32 a;
    f32 b;
    f32 c;
    f32 d;
} SeqFxParams;

void gcRobotPatrol_update(int* obj, u8* state)
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
        objfx_spawnLightPulse((GameObject*)obj, 0.5f, 2, 0, 6, 0.25f, &fx);
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

const f32 gGcRobotPatrolZero = 0.0f;
const f32 gMikaladonZero = 0.0f;
const f32 gMikaladonDefaultPeriod = 60.0f;

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
