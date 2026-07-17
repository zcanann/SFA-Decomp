/*
 * grimble (DLL 0x00D0) - the path-following SharpClaw "grimble" baddie
 * (object type id 0x59), built on the shared ground-baddie / player-aware
 * control framework (gBaddieControlInterface, gPlayerInterface).
 *
 * Each grimble locks onto a nearby path object (one of the type-0x17 group
 * scanned in fn_801627F4) and walks its GrimbleControl sub-state (at
 * GrimbleState+0x40C): it tracks progress along the path (unk48), derives
 * facing from the sampled path tangent (getAngle), and clamps progress to
 * the path's [lbl_803E2EF4, lbl_803E2EF8] bounds. State handlers A00-A02
 * (registered in gGrimbleStateHandlersA/B and driven by the player
 * interface) implement patrol, edge-turn and pursuit moves; reaching a path
 * edge or losing line-of-sight to the target flips the reversed flag and
 * picks a new randomized targetProgress. The render pass spawns bone/object
 * particle effects from the unk400 fx-flag bits. When the object is asleep
 * (unkF4 != 0) update wakes it from the saved map-event time slot.
 */
#include "main/game_object.h"
#include "main/dll/objfx_api.h"
#include "main/obj_group.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/grimble_state.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/baddie_state.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/dll_00CF_cannonclaw.h"
#include "main/dll/dll_00D0_grimble.h"
#include "main/mapEventTypes.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "main/object_render_legacy.h"
#include "main/audio/sfx.h"
#include "main/player_control_interface.h"
#include "main/dll/baddie_control_interface.h"

typedef struct GrimblePlacement
{
    u8 pad0[0x14 - 0x0];
    s32 mapId;
} GrimblePlacement;

/* object group this object belongs to */
#define GRIMBLE_OBJGROUP    3
#define DFROPENODE_OBJGROUP 0x17 /* DLL 0x175 dfropenode (path nodes) */

extern int lbl_803200E0[];
extern int lbl_80320158[];
extern void* gGrimbleStateHandlersA[11];
extern void* gGrimbleStateHandlersB[6];
extern f32 lbl_803E2EB8;
extern f32 lbl_803E2EBC;
extern f32 lbl_803E2EF0;
extern f32 lbl_803E2EF4;
extern f32 lbl_803E2EF8;
extern f32 lbl_803E2EFC;
int grimble_animEventCallback(void);
void fn_801627F4(GameObject* obj);

int grimble_stateHandlerA02(GameObject* obj, char* state, f32 arg)
{
    u16 zone;
    u16 pad;
    u16 dist;
    f32 z2, y2, x2, z, y, x;
    f32 spd;
    f32 vel;
    s16 angle;
    double d;
    f32 r;
    char* sub;

    sub = *(char**)(*(int*)&obj->extra + 0x40c);
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 3, lbl_803E2EB8, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2EF0;
    (*(void (**)(void*, char*, f32, int))(*(int*)gPlayerInterface + 0x20))(obj, state, arg, 9);
    (*(void (**)(int, char*, f32))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x28))(
        ((GrimbleControl*)sub)->pathObj, sub + 0x48,
        ((GroundBaddieState*)state)->baddie.animSpeedA * (f32)(1 - (((GrimbleControl*)sub)->reversed << 1)));
    if (((GrimbleControl*)sub)->pathProgress < lbl_803E2EF4)
    {
        ((GrimbleControl*)sub)->pathProgress = lbl_803E2EF4;
    }
    else if (((GrimbleControl*)sub)->pathProgress > lbl_803E2EF8)
    {
        ((GrimbleControl*)sub)->pathProgress = lbl_803E2EF8;
    }
    (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
        ((GrimbleControl*)sub)->pathObj, ((GrimbleControl*)sub)->pathProgress - lbl_803E2EFC, &x, &y, &z);
    (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
        ((GrimbleControl*)sub)->pathObj, lbl_803E2EFC + ((GrimbleControl*)sub)->pathProgress, &x2, &y2, &z2);
    x = x - x2;
    y = y - y2;
    z = z - z2;
    r = sqrtf(x * x + z * z);
    d = r;
    x = r;
    angle = getAngle(y, d);
    obj->anim.rotY = (lbl_803E2EBC - 2.0f * obj->anim.currentMoveProgress) *
                     (f32)(s16)(angle * ((((GrimbleControl*)sub)->reversed << 1) - 1));
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        (*(void (**)(void*, int, int, u16*, u16*, u16*))(*(int*)gBaddieControlInterface + 0x14))(
            obj, *(int*)&((GroundBaddieState*)state)->baddie.targetObj, 0x10, &zone, &pad, &dist);
        ((GrimbleControl*)sub)->reversed = 1 - *(u8*)&((GrimbleControl*)sub)->reversed;
        obj->anim.rotX = ((GrimbleControl*)sub)->baseRotX + (!((GrimbleControl*)sub)->reversed << 15);
        spd = (f32)(int)randomGetRange(0x32, 0x64) / 100.0f;
        vel = (f32)((((GrimbleControl*)sub)->reversed << 1) - 1) * spd;
        if (zone < 4 || zone > 0xb)
        {
            if (dist > 0x1f4)
            {
                vel *= lbl_803E2EBC + dist / 100.0f;
            }
            else
            {
                vel *= lbl_803E2EBC + dist / 300.0f;
            }
        }
        ((GrimbleControl*)sub)->targetProgress = ((GrimbleControl*)sub)->pathProgress - vel;
        spd = ((GrimbleControl*)sub)->targetProgress;
        spd = (spd > lbl_803E2EBC) ? spd : lbl_803E2EBC;
        ((GrimbleControl*)sub)->targetProgress = spd;
        spd = ((GrimbleControl*)sub)->targetProgress;
        spd = (spd < 6.0f) ? spd : 6.0f;
        ((GrimbleControl*)sub)->targetProgress = spd;
        return 4;
    }
    return 0;
}

int grimble_stateHandlerA01(GameObject* obj, char* state, f32 arg)
{
    f32 z2, y2, x2, z, y, x;
    u8 hitEdge;
    s16 angle;
    double d;
    f32 r;
    char* sub;

    sub = *(char**)(*(int*)&(obj)->extra + 0x40c);
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2EB8, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    (*(void (**)(int, char*, f32, int))(*(int*)gPlayerInterface + 0x20))((int)obj, state, arg, 0);
    if ((*(int*)&((GroundBaddieState*)state)->baddie.eventFlags & 1) != 0)
    {
        *(int*)&((GroundBaddieState*)state)->baddie.eventFlags =
            *(int*)&((GroundBaddieState*)state)->baddie.eventFlags & ~1;
        Sfx_PlayFromObject((int)obj, SFXTRIG_mv_persquk1);
    }
    (*(void (**)(int, char*, f32))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x28))(
        ((GrimbleControl*)sub)->pathObj, sub + 0x48,
        50.4f *
            (((GroundBaddieState*)state)->baddie.moveSpeed * (f32)(1 - (((GrimbleControl*)sub)->reversed << 1))));
    if (((GrimbleControl*)sub)->pathProgress < lbl_803E2EF4)
    {
        ((GrimbleControl*)sub)->pathProgress = lbl_803E2EF4;
        hitEdge = 1;
    }
    else if (((GrimbleControl*)sub)->pathProgress > lbl_803E2EF8)
    {
        ((GrimbleControl*)sub)->pathProgress = lbl_803E2EF8;
        hitEdge = 1;
    }
    else
    {
        hitEdge = 0;
    }
    if (hitEdge != 0)
    {
        return 7;
    }
    (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
        ((GrimbleControl*)sub)->pathObj, ((GrimbleControl*)sub)->pathProgress - lbl_803E2EFC, &x, &y, &z);
    (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
        ((GrimbleControl*)sub)->pathObj, lbl_803E2EFC + ((GrimbleControl*)sub)->pathProgress, &x2, &y2, &z2);
    x = x - x2;
    y = y - y2;
    z = z - z2;
    r = sqrtf(x * x + z * z);
    d = r;
    x = r;
    angle = getAngle(y, d);
    (obj)->anim.rotY = angle * ((((GrimbleControl*)sub)->reversed << 1) - 1);
    return 0;
}

#pragma opt_common_subs off
#pragma fp_contract off
int grimble_stateHandlerA00(GameObject* obj, char* state, f32 arg)
{
    u16 zone;
    u16 pad;
    u16 dist;
    f32 z2, y2, x2, z, y, x;
    s16 angle;
    double d;
    f32 r;
    char* sub;

    sub = *(char**)(*(int*)&obj->extra + 0x40c);
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2EB8, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2EF0;
    (*(void (**)(int, char*, f32, int))(*(int*)gPlayerInterface + 0x20))((int)obj, state, arg, 1);
    (*(void (**)(int, char*, f32))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x28))(
        ((GrimbleControl*)sub)->pathObj, sub + 0x48,
        ((GroundBaddieState*)state)->baddie.animSpeedA * (f32)(1 - (((GrimbleControl*)sub)->reversed << 1)));
    if (((GrimbleControl*)sub)->pathProgress < lbl_803E2EF4)
    {
        ((GrimbleControl*)sub)->pathProgress = lbl_803E2EF4;
    }
    else if (((GrimbleControl*)sub)->pathProgress > lbl_803E2EF8)
    {
        ((GrimbleControl*)sub)->pathProgress = lbl_803E2EF8;
    }
    (*(void (**)(int, int, int, u16*, u16*, u16*))(*(int*)gBaddieControlInterface + 0x14))(
        (int)obj, *(int*)&((GroundBaddieState*)state)->baddie.targetObj, 0x10, &zone, &pad, &dist);
    if (zone > 3 && zone < 0xc && dist > 0x190 && ((GrimbleControl*)sub)->pathProgress > 2.0f &&
        ((GrimbleControl*)sub)->pathProgress < 5.0f)
    {
        return 3;
    }
    if ((((GrimbleControl*)sub)->reversed ^
         (((GrimbleControl*)sub)->pathProgress >= ((GrimbleControl*)sub)->targetProgress)) != 0 &&
        *(s8*)&((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        return 3;
    }
    if ((*(int*)&((GroundBaddieState*)state)->baddie.eventFlags & 1) != 0)
    {
        *(int*)&((GroundBaddieState*)state)->baddie.eventFlags =
            *(int*)&((GroundBaddieState*)state)->baddie.eventFlags & ~1;
        Sfx_PlayFromObject((int)obj, SFXTRIG_mv_persquk1);
    }
    (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
        ((GrimbleControl*)sub)->pathObj, ((GrimbleControl*)sub)->pathProgress - lbl_803E2EFC, &x, &y, &z);
    (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
        ((GrimbleControl*)sub)->pathObj, lbl_803E2EFC + ((GrimbleControl*)sub)->pathProgress, &x2, &y2, &z2);
    x = x - x2;
    y = y - y2;
    z = z - z2;
    r = sqrtf(x * x + z * z);
    d = r;
    x = r;
    angle = getAngle(y, d);
    obj->anim.rotY = angle * ((((GrimbleControl*)sub)->reversed << 1) - 1);
    return 0;
}
#pragma opt_common_subs reset
#pragma fp_contract reset

int grimble_animEventCallback(void)
{
    return 0x0;
}

__declspec(section ".sdata2") f32 gGrimblePathSearchMaxDist = 200.0f;

void fn_801627F4(GameObject* obj)
{
    int count;
    f32 dist;
    f32 hitY;
    f32 unk;
    f32 progress;
    int* ptr;
    char* state;
    int i;
    int diff;
    int facing;
    char* sub;

    state = obj->extra;
    ptr = (void*)ObjGroup_GetObjects(DFROPENODE_OBJGROUP, &count);
    if (count != 0)
    {
        sub = (char*)((GroundBaddieState*)state)->control;
        ((GrimbleControl*)sub)->candidatePathObj = 0;
        ((GrimbleControl*)sub)->nearestDist = gGrimblePathSearchMaxDist;
        for (i = 0; i < count; i++)
        {
            if ((*(int (**)(int, f32, f32, f32, f32*, f32*, f32*))(*(int*)(*(int*)(ptr[i] + 0x68)) + 0x30))(
                    ptr[i], obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &dist, &hitY, &unk) != 0 &&
                dist < ((GrimbleControl*)sub)->nearestDist)
            {
                ((GrimbleControl*)sub)->candidatePathObj = ptr[i];
                ((GrimbleControl*)sub)->nearestDist = dist;
                ((GrimbleControl*)sub)->candidateProgress = hitY;
            }
        }
        if (*(void**)&((GrimbleControl*)sub)->candidatePathObj != NULL)
        {
            ((GrimbleControl*)sub)->pathObj = ((GrimbleControl*)sub)->candidatePathObj;
            ((GrimbleControl*)sub)->pathProgress = ((GrimbleControl*)sub)->candidateProgress;
            (*(void (**)(int, char*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x20))(
                ((GrimbleControl*)sub)->pathObj, sub + 0xc);
            (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
                ((GrimbleControl*)sub)->pathObj, ((GrimbleControl*)sub)->pathProgress, (f32*)(sub + 0x1c),
                (f32*)(sub + 0x20), (f32*)(sub + 0x24));
            ((GrimbleControl*)sub)->baseRotX = (*(s16(**)(int))(
                *(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x34))(((GrimbleControl*)sub)->pathObj);
            ((GrimbleControl*)sub)->savedPathProgress = ((GrimbleControl*)sub)->pathProgress;
            ((GrimbleControl*)sub)->unk46 = 0;
            ((GrimbleControl*)sub)->anchorPosY = ((GrimbleControl*)sub)->homePosY;
            ((GrimbleControl*)sub)->currentPosY = obj->anim.localPosY;
            ((GrimbleControl*)sub)->posYDelta =
                ((GrimbleControl*)sub)->anchorPosY - ((GrimbleControl*)sub)->currentPosY;
            diff = obj->anim.rotX - (u16)((GrimbleControl*)sub)->baseRotX;
            if (diff > 0x8000)
            {
                diff -= 0xffff;
            }
            if (diff < -0x8000)
            {
                diff += 0xffff;
            }
            facing = 0;
            if (diff <= 0x3ffc && diff >= -0x3ffc)
            {
                facing = 1;
            }
            ((GrimbleControl*)sub)->reversed = facing;
            obj->anim.rotX = ((GrimbleControl*)sub)->baseRotX + (!((GrimbleControl*)sub)->reversed << 15);
            progress = ((GrimbleControl*)sub)->pathProgress - (f32)((((GrimbleControl*)sub)->reversed << 1) - 1) *
                                                                  ((f32)(int)randomGetRange(0xa, 0x3c) / 10.0f);
            ((GrimbleControl*)sub)->targetProgress = progress;
            progress = ((GrimbleControl*)sub)->targetProgress;
            progress = (progress > lbl_803E2EBC) ? progress : lbl_803E2EBC;
            ((GrimbleControl*)sub)->targetProgress = progress;
            progress = ((GrimbleControl*)sub)->targetProgress;
            progress = (progress < 6.0f) ? progress : 6.0f;
            ((GrimbleControl*)sub)->targetProgress = progress;
        }
    }
}

int grimble_getExtraSize(void)
{
    return 0x46c;
}
int grimble_getObjectTypeId(void)
{
    return 0x59;
}

void grimble_free(GameObject* obj)
{
    int* state = obj->extra;
    ObjGroup_RemoveObject((u32)obj, GRIMBLE_OBJGROUP);
    (*(void (**)(int, int*, int))(*(int*)gBaddieControlInterface + 0x40))((int)obj, state, 0);
}

#pragma opt_common_subs off
void grimble_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    char* state = obj->extra;
    char* sub = *(char**)&((GroundBaddieState*)state)->control;

    if (visible == 0 || obj->unkF4 != 0)
    {
        return;
    }
    objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E2EBC);
    if (((GrimbleControl*)sub)->unk50 > lbl_803E2EB8)
    {
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x52a, NULL, 0x64, NULL);
    }
    if ((((GroundBaddieState*)state)->flags400 & 0x60) != 0)
    {
        objParticleFn_80099d84((GameObject*)obj, lbl_803E2EBC, 3, ((GroundBaddieState*)state)->glowAlpha, 0);
    }
    if ((((GroundBaddieState*)state)->flags400 & 0x100) != 0)
    {
        objParticleFn_80099d84((GameObject*)obj, lbl_803E2EBC, 4, ((GroundBaddieState*)state)->glowAlpha, 0);
        ((GroundBaddieState*)state)->flags400 = ((GroundBaddieState*)state)->flags400 & ~0x100;
    }
}
#pragma opt_common_subs reset

void grimble_hitDetect(int obj)
{
    (*(void (**)(int, int*, void*))(*(int*)gPlayerInterface + 0xC))(obj, ((GameObject*)obj)->extra,
                                                                    gGrimbleStateHandlersA);
}

#pragma opt_common_subs off
void grimble_update(GameObject* obj)
{
    char* state;
    char* sub;
    int def;

    state = obj->extra;
    sub = *(char**)&((GroundBaddieState*)state)->control;
    def = *(int*)&obj->anim.placementData;
    if (obj->unkF4 != 0)
    {
        if ((*gMapEventInterface)->shouldNotSaveTime(((GrimblePlacement*)def)->mapId) != 0)
        {
            (*(void (**)(int, int, char*, int, int, int, int, f32))(*(int*)gBaddieControlInterface + 0x58))(
                (int)obj, def, state, 0xa, 6, 0x10e, 0x36, 20.0f);
            ((GroundBaddieState*)state)->baddie.substate = 1;
            ((GroundBaddieState*)state)->baddie.moveJustStartedB = 1;
            obj->anim.alpha = 0;
        }
    }
    else
    {
        if (*(void**)&((GrimbleControl*)sub)->candidatePathObj != NULL)
        {
            void* target;
            int r;
            (*(void (**)(int, char*, f32, f32, void*, void*))(*(int*)gPlayerInterface + 0x8))(
                (int)obj, state, lbl_803E2EBC, *(f32*)&lbl_803E2EBC, gGrimbleStateHandlersA, gGrimbleStateHandlersB);
            (*(void (**)(int, f32, int, int, int))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
                ((GrimbleControl*)sub)->pathObj, ((GrimbleControl*)sub)->pathProgress, (int)obj + 0xc, (int)obj + 0x10,
                (int)obj + 0x14);
            (*(void (**)(int, char*, char*, int, char*, int, int, int))(*(int*)gBaddieControlInterface + 0x54))(
                (int)obj, state, state + 0x35c, ((GroundBaddieState*)state)->gameBitB, state + 0x405, 0, 0, 0);
            r = (*(int (**)(int, char*, char*, int, int*, int*, int, int))(*(int*)gBaddieControlInterface + 0x50))(
                (int)obj, state, state + 0x35c, ((GroundBaddieState*)state)->gameBitB, lbl_803200E0, lbl_80320158, 3, 0);
            if (r == 0xe)
            {
                ((GroundBaddieState*)state)->subMode = 2;
                ((GroundBaddieState*)state)->baddie.targetObj = Obj_GetPlayerObject();
            }
            if (((GroundBaddieState*)state)->baddie.targetObj != NULL ||
                *(s8*)&((GroundBaddieState*)state)->baddie.hitPoints == 0)
            {
                ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags |= 1;
                if ((*(int (**)(int, char*, f32, int))(*(int*)gBaddieControlInterface + 0x44))(
                        (int)obj, state, (f32)((GroundBaddieState*)state)->aggroRange, 1) != 0)
                {
                    *(int*)&((GroundBaddieState*)state)->baddie.targetObj = 0;
                }
            }
            else
            {
                ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~1;
                target = (*(void* (**)(int, char*, f32, int))(*(int*)gBaddieControlInterface + 0x48))(
                    (int)obj, state, (f32)((GroundBaddieState*)state)->aggroRange, 0x8000);
                if (target != NULL)
                {
                    ((GroundBaddieState*)state)->baddie.targetObj = target;
                    ((GroundBaddieState*)state)->baddie.hasTarget = 0;
                }
            }
        }
        else
        {
            fn_801627F4(obj);
        }
    }
}
#pragma opt_common_subs reset

void grimble_init(int obj, int def, int flag)
{
    char* state = ((GameObject*)obj)->extra;
    u8 flags = 2;

    if (flag != 0)
    {
        flags |= 1;
    }
    (*(void (**)(int, int, char*, int, int, int, u8, f32))(*(int*)gBaddieControlInterface + 0x58))(
        obj, def, state, 0, 0, 0, flags, 20.0f);
    ((GameObject*)obj)->animEventCallback = grimble_animEventCallback;
    (*(void (**)(int, char*, int))(*(int*)gPlayerInterface + 0x14))(obj, state, 0);
    ((GroundBaddieState*)state)->baddie.substate = 0;
    ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2EB8;
    *(int*)((char*)((GroundBaddieState*)state)->control + 0x34) = 0;
}

void grimble_release(void)
{
}

void grimble_initialise(void)
{
    grimble_initialiseStateHandlerTables();
}

ObjectDescriptor gGrimbleObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)grimble_initialise,
    (ObjectDescriptorCallback)grimble_release,
    0,
    (ObjectDescriptorCallback)grimble_init,
    (ObjectDescriptorCallback)grimble_update,
    (ObjectDescriptorCallback)grimble_hitDetect,
    (ObjectDescriptorCallback)grimble_render,
    (ObjectDescriptorCallback)grimble_free,
    (ObjectDescriptorCallback)grimble_getObjectTypeId,
    grimble_getExtraSize,
};

/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* gCannonClawObjDescriptor[14] = {(void*)0x00000000,          (void*)0x00000000,      (void*)0x00000000,
                                      (void*)0x00090000,          cannonclaw_initialise,  cannonclaw_release,
                                      (void*)0x00000000,          cannonclaw_init,        cannonclaw_update,
                                      cannonclaw_hitDetect,       cannonclaw_render,      cannonclaw_free,
                                      cannonclaw_getObjectTypeId, cannonclaw_getExtraSize};
