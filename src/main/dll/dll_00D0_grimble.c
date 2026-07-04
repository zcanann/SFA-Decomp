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
 *
 * This TU also carries the tumbleweedbush object descriptor (a separate
 * sibling object whose handlers live in another TU).
 */
#include "main/game_object.h"
#include "main/dll/grimble_state.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/scarab.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/gameplay_runtime.h"
#include "main/audio/sfx.h"

/* object group this object belongs to */
#define GRIMBLE_OBJGROUP 3

typedef struct GrimblePlacement
{
    u8 pad0[0x14 - 0x0];
    s32 mapId;
} GrimblePlacement;

extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void* ObjGroup_GetObjects(int type, int* outCount);
extern int getAngle(float y, float x);
extern void objParticleFn_80099d84(int obj, f32 a, int b, f32 c, int d);
extern void* gPlayerInterface;
extern void* gBaddieControlInterface;
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
extern f32 lbl_803E2F00;
extern f32 lbl_803E2F08;
extern f32 lbl_803E2F0C;
extern f32 lbl_803E2F18;
extern f32 lbl_803E2F1C;
extern f32 gGrimblePathSearchMaxDist;
extern f32 lbl_803E2F24;
extern f32 lbl_803E2F28;

int grimble_animEventCallback(void);
void fn_801627F4(int obj);

int grimble_stateHandlerA02(int obj, char* state, f32 arg)
{
    extern f32 sqrtf(f32); /* #57 */
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

    sub = *(char**)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 3, lbl_803E2EB8, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2EF0;
    (*(void (**)(int, char*, f32, int))(*(int*)gPlayerInterface + 0x20))(obj, state, arg, 9);
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
    ((GameObject*)obj)->anim.rotY = (lbl_803E2EBC - lbl_803E2F00 * ((GameObject*)obj)->anim.currentMoveProgress) *
        (f32)(s16)(angle * ((((GrimbleControl*)sub)->reversed << 1) - 1));
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        (*(void (**)(int, int, int, u16*, u16*, u16*))(*(int*)gBaddieControlInterface + 0x14))(
            obj, *(int*)&((GroundBaddieState*)state)->baddie.targetObj, 0x10, &zone, &pad, &dist);
        ((GrimbleControl*)sub)->reversed = 1 - *(u8*)&((GrimbleControl*)sub)->reversed;
        ((GameObject*)obj)->anim.rotX = ((GrimbleControl*)sub)->baseRotX + (!((GrimbleControl*)sub)->reversed << 15);
        spd = (f32)(int)
        randomGetRange(0x32, 0x64) / 100.0f;
        vel = (f32)((((GrimbleControl*)sub)->reversed << 1) - 1) * spd;
        if (zone < 4 || zone > 0xb)
        {
            if (dist > 0x1f4)
            {
                vel *= lbl_803E2EBC + dist / 100.0f;
            }
            else
            {
                vel *= lbl_803E2EBC + dist / lbl_803E2F08;
            }
        }
        ((GrimbleControl*)sub)->targetProgress = ((GrimbleControl*)sub)->pathProgress - vel;
        spd = ((GrimbleControl*)sub)->targetProgress;
        spd = (spd > lbl_803E2EBC) ? spd : lbl_803E2EBC;
        ((GrimbleControl*)sub)->targetProgress = spd;
        spd = ((GrimbleControl*)sub)->targetProgress;
        spd = (spd < lbl_803E2F0C) ? spd : lbl_803E2F0C;
        ((GrimbleControl*)sub)->targetProgress = spd;
        return 4;
    }
    return 0;
}

int grimble_stateHandlerA01(int obj, char* state, f32 arg)
{
    extern f32 sqrtf(f32); /* #57 */
 /* #57 */
    f32 z2, y2, x2, z, y, x;
    u8 hitEdge;
    s16 angle;
    double d;
    f32 r;
    char* sub;

    sub = *(char**)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E2EB8, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    (*(void (**)(int, char*, f32, int))(*(int*)gPlayerInterface + 0x20))(obj, state, arg, 0);
    if ((*(int*)&((GroundBaddieState*)state)->baddie.eventFlags & 1) != 0)
    {
        *(int*)&((GroundBaddieState*)state)->baddie.eventFlags = *(int*)&((GroundBaddieState*)state)->baddie.eventFlags
            & ~1;
        Sfx_PlayFromObject(obj, SFXsc_death01);
    }
    (*(void (**)(int, char*, f32))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x28))(
        ((GrimbleControl*)sub)->pathObj, sub + 0x48,
        lbl_803E2F18 * (((GroundBaddieState*)state)->baddie.moveSpeed * (f32)(1 - (((GrimbleControl*)sub)->reversed << 1))));
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
    ((GameObject*)obj)->anim.rotY = angle * ((((GrimbleControl*)sub)->reversed << 1) - 1);
    return 0;
}

int grimble_stateHandlerA00(int obj, char* state, f32 arg)
{
    extern f32 sqrtf(f32); /* #57 */
 /* #57 */
    u16 zone;
    u16 pad;
    u16 dist;
    f32 z2, y2, x2, z, y, x;
    s16 angle;
    double d;
    f32 r;
    char* sub;

    sub = *(char**)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E2EB8, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2EF0;
    (*(void (**)(int, char*, f32, int))(*(int*)gPlayerInterface + 0x20))(obj, state, arg, 1);
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
        obj, *(int*)&((GroundBaddieState*)state)->baddie.targetObj, 0x10, &zone, &pad, &dist);
    if (zone > 3 && zone < 0xc && dist > 0x190 && ((GrimbleControl*)sub)->pathProgress > lbl_803E2F00 &&
        ((GrimbleControl*)sub)->pathProgress < lbl_803E2F1C)
    {
        return 3;
    }
    if ((((GrimbleControl*)sub)->reversed ^ (((GrimbleControl*)sub)->pathProgress >= ((GrimbleControl*)sub)->targetProgress))
        != 0 &&
        *(s8*)&((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        return 3;
    }
    if ((*(int*)&((GroundBaddieState*)state)->baddie.eventFlags & 1) != 0)
    {
        *(int*)&((GroundBaddieState*)state)->baddie.eventFlags = *(int*)&((GroundBaddieState*)state)->baddie.eventFlags
            & ~1;
        Sfx_PlayFromObject(obj, SFXsc_death01);
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
    ((GameObject*)obj)->anim.rotY = angle * ((((GrimbleControl*)sub)->reversed << 1) - 1);
    return 0;
}

void fn_801627F4(int obj)
{
    int count;
    f32 dist;
    f32 hitY;
    f32 unk;
    f32 f;
    int* ptr;
    char* state;
    int i;
    int diff;
    int facing;
    char* sub;

    state = ((GameObject*)obj)->extra;
    ptr = ObjGroup_GetObjects(0x17, &count);
    if (count != 0)
    {
        sub = (char*)((GroundBaddieState*)state)->control;
        ((GrimbleControl*)sub)->candidatePathObj = 0;
        ((GrimbleControl*)sub)->nearestDist = gGrimblePathSearchMaxDist;
        for (i = 0; i < count; i++)
        {
            if ((*(int (**)(int, f32, f32, f32, f32*, f32*, f32*))(*(int*)(*(int*)(ptr[i] + 0x68)) + 0x30))(
                    ptr[i], ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ, &dist,
                    &hitY, &unk) != 0 &&
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
                ((GrimbleControl*)sub)->pathObj, ((GrimbleControl*)sub)->pathProgress, (f32*)(sub + 0x1c), (f32*)(sub + 0x20),
                (f32*)(sub + 0x24));
            ((GrimbleControl*)sub)->baseRotX =
                (*(s16 (**)(int))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x34))(
                    ((GrimbleControl*)sub)->pathObj);
            ((GrimbleControl*)sub)->savedPathProgress = ((GrimbleControl*)sub)->pathProgress;
            ((GrimbleControl*)sub)->unk46 = 0;
            ((GrimbleControl*)sub)->anchorPosY = ((GrimbleControl*)sub)->homePosY;
            ((GrimbleControl*)sub)->currentPosY = ((GameObject*)obj)->anim.localPosY;
            ((GrimbleControl*)sub)->posYDelta = ((GrimbleControl*)sub)->anchorPosY - ((GrimbleControl*)sub)->currentPosY;
            diff = ((GameObject*)obj)->anim.rotX - (u16)((GrimbleControl*)sub)->baseRotX;
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
            ((GameObject*)obj)->anim.rotX = ((GrimbleControl*)sub)->baseRotX + (!((GrimbleControl*)sub)->reversed <<
                15);
            f = ((GrimbleControl*)sub)->pathProgress -
                (f32)((((GrimbleControl*)sub)->reversed << 1) - 1) *
                ((f32)(int)
            randomGetRange(0xa, 0x3c) / lbl_803E2F24
            )
            ;
            ((GrimbleControl*)sub)->targetProgress = f;
            f = ((GrimbleControl*)sub)->targetProgress;
            f = (f > lbl_803E2EBC) ? f : lbl_803E2EBC;
            ((GrimbleControl*)sub)->targetProgress = f;
            f = ((GrimbleControl*)sub)->targetProgress;
            f = (f < lbl_803E2F0C) ? f : lbl_803E2F0C;
            ((GrimbleControl*)sub)->targetProgress = f;
        }
    }
}

void grimble_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    char* state = ((GameObject*)obj)->extra;
    char* sub = *(char**)&((GroundBaddieState*)state)->control;

    if (visible == 0 || ((GameObject*)obj)->unkF4 != 0)
    {
        return;
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E2EBC);
    if (((GrimbleControl*)sub)->unk50 > lbl_803E2EB8)
    {
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x52a, NULL, 0x64, NULL);
    }
    if ((((GroundBaddieState*)state)->flags400 & 0x60) != 0)
    {
        objParticleFn_80099d84(obj, lbl_803E2EBC, 3, ((GroundBaddieState*)state)->glowAlpha, 0);
    }
    if ((((GroundBaddieState*)state)->flags400 & 0x100) != 0)
    {
        objParticleFn_80099d84(obj, lbl_803E2EBC, 4, ((GroundBaddieState*)state)->glowAlpha, 0);
        ((GroundBaddieState*)state)->flags400 = ((GroundBaddieState*)state)->flags400 & ~0x100;
    }
}

void grimble_update(int obj)
{
    char* state;
    char* sub;
    int def;

    state = ((GameObject*)obj)->extra;
    sub = *(char**)&((GroundBaddieState*)state)->control;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if ((*gMapEventInterface)->shouldNotSaveTime(((GrimblePlacement*)def)->mapId) != 0)
        {
            (*(void (**)(int, int, char*, int, int, int, int, f32))(*(int*)gBaddieControlInterface +
                0x58))(obj, def, state, 0xa, 6,
                       0x10e, 0x36, lbl_803E2F28);
            ((GroundBaddieState*)state)->baddie.substate = 1;
            ((GroundBaddieState*)state)->baddie.moveJustStartedB = 1;
            ((GameObject*)obj)->anim.alpha = 0;
        }
    }
    else
    {
        if (*(void**)&((GrimbleControl*)sub)->candidatePathObj != NULL)
        {
            void* target;
            int r;
            (*(void (**)(int, char*, f32, f32, void*, void*))(*(int*)gPlayerInterface + 0x8))(
                obj, state, lbl_803E2EBC, *(f32*)&lbl_803E2EBC, gGrimbleStateHandlersA, gGrimbleStateHandlersB);
            (*(void (**)(int, f32, int, int, int))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) +
                0x24))(((GrimbleControl*)sub)->pathObj, ((GrimbleControl*)sub)->pathProgress,
                       obj + 0xc, obj + 0x10, obj + 0x14);
            (*(void (**)(int, char*, char*, int, char*, int, int, int))(*(int*)gBaddieControlInterface +
                0x54))(
                obj, state, state + 0x35c, ((GroundBaddieState*)state)->gameBitB, state + 0x405, 0, 0, 0);
            r = (*(int (**)(int, char*, char*, int, int*, int*, int, int))(*(int*)gBaddieControlInterface +
                0x50))(
                obj, state, state + 0x35c, ((GroundBaddieState*)state)->gameBitB, lbl_803200E0, lbl_80320158, 3, 0);
            if (r == 0xe)
            {
                ((GroundBaddieState*)state)->unk405 = 2;
                ((GroundBaddieState*)state)->baddie.targetObj = Obj_GetPlayerObject();
            }
            if (((GroundBaddieState*)state)->baddie.targetObj != NULL || *(s8*)&((GroundBaddieState*)state)->baddie.
                hitPoints == 0)
            {
                ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags |= 1;
                if ((*(int (**)(int, char*, f32, int))(*(int*)gBaddieControlInterface + 0x44))(
                    obj, state, (f32)((GroundBaddieState*)state)->aggroRange, 1) != 0)
                {
                    *(int*)&((GroundBaddieState*)state)->baddie.targetObj = 0;
                }
            }
            else
            {
                ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
                target = (*(void *(**)(int, char*, f32, int))(*(int*)gBaddieControlInterface + 0x48))(
                    obj, state, (f32)((GroundBaddieState*)state)->aggroRange, 0x8000);
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

void grimble_init(int obj, int p2, int p3)
{
    char* state = ((GameObject*)obj)->extra;
    u8 flags = 2;

    if (p3 != 0)
    {
        flags |= 1;
    }
    (*(void (**)(int, int, char*, int, int, int, u8, f32))(*(int*)gBaddieControlInterface + 0x58))(
        obj, p2, state, 0, 0, 0, flags, lbl_803E2F28);
    ((GameObject*)obj)->animEventCallback = grimble_animEventCallback;
    (*(void (**)(int, char*, int))(*(int*)gPlayerInterface + 0x14))(obj, state, 0);
    ((GroundBaddieState*)state)->baddie.substate = 0;
    ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2EB8;
    *(int*)((char*)((GroundBaddieState*)state)->control + 0x34) = 0;
}

void grimble_release(void)
{
}

int grimble_animEventCallback(void) { return 0x0; }
int grimble_getExtraSize(void) { return 0x46c; }
int grimble_getObjectTypeId(void) { return 0x59; }

#pragma dont_inline on
void grimble_initialiseStateHandlerTables(void);
#pragma dont_inline reset
void grimble_initialise(void) { grimble_initialiseStateHandlerTables(); }

void grimble_free(int obj)
{
    int* state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, GRIMBLE_OBJGROUP);
    (*(void (**)(int, int*, int))(*(int*)gBaddieControlInterface + 0x40))(obj, state, 0);
}

void grimble_hitDetect(int obj)
{
    (*(void (**)(int, int*, void*))(*(int*)gPlayerInterface + 0xC))(
        obj, ((GameObject*)obj)->extra, gGrimbleStateHandlersA);
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

void tumbleweedbush_free(void);

void tumbleweedbush_hitDetect(void);

void tumbleweedbush_release(void);

void tumbleweedbush_initialise(void);

void tumbleweedbush_init(u8* obj, u8* params, int param3);

int tumbleweedbush_getExtraSize(void);
int tumbleweedbush_getObjectTypeId(void);

void tumbleweedbush_update(int* obj);

void tumbleweedbush_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* tumbleweedbush_setScale: scan the sub-array at obj->_b8 (sub[0x50] entries
 * of 4 bytes each), zeroing every slot whose +0xc word matches `match`. */
void tumbleweedbush_setScale(u8* obj, void* match);

ObjectDescriptor11WithPadding gTumbleWeedBushObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)tumbleweedbush_initialise,
        (ObjectDescriptorCallback)tumbleweedbush_release,
        0,
        (ObjectDescriptorCallback)tumbleweedbush_init,
        (ObjectDescriptorCallback)tumbleweedbush_update,
        (ObjectDescriptorCallback)tumbleweedbush_hitDetect,
        (ObjectDescriptorCallback)tumbleweedbush_render,
        (ObjectDescriptorCallback)tumbleweedbush_free,
        (ObjectDescriptorCallback)tumbleweedbush_getObjectTypeId,
        tumbleweedbush_getExtraSize,
        (ObjectDescriptorCallback)tumbleweedbush_setScale,
    },
    0,
};
