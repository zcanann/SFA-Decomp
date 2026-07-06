/*
 * DLL 0x00CB - a ground-baddie object (object type id 0x14b, extra size
 * 0x410). Its AI runs through gBaddieControlInterface and gPlayerInterface:
 * dll_CB_init sets up the control state and registers dll_CB_seqFn as the
 * anim-event callback; dll_CB_update advances movement and, while the
 * sub-state's flags400 bit 8 is set, walks a ROM curve path
 * (gRomCurveInterface / Curve_AdvanceAlongPath) copying the curve's
 * position/orientation onto the object. dll_CB_seqFn drives an objseq
 * sub-state machine (subMode 0/1/2) handling player tracking, route paths
 * (route35C) and game-bit gating (gameBitC / DllCBPlacement.gameBitId yield).
 * dll_CB_initialise installs the two callback tables gDllCBMoveHandlers /
 * gDllCBStateHandlers used by the player-interface update.
 *
 * This TU also defines the co-located ChukChuk (gChukChukObjDescriptor) and
 * IceBall (gIceBallObjDescriptor) object descriptors, whose bodies live in
 * their own DLL TUs.
 */
#include "main/dll/chukchukstate_struct.h"
#include "main/dll/scarab.h"
#include "main/game_object.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/curve_walker.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/gamebits.h"

/* object group this object belongs to */
#define DLLCB_OBJGROUP 3

typedef struct DllCBPlacement
{
    u8 pad0[0x4 - 0x0];
    s8 unk4;
    s8 unk5;
    u8 unk6;
    u8 unk7;
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[0x24 - 0x14];
    s16 trackYieldId;
    u8 pad26[0x2C - 0x26];
    s16 gameBitId;
    s8 trackYieldEnable;
    u8 pad2F[0x30 - 0x2F];
} DllCBPlacement;

extern u64 ObjGroup_RemoveObject();

#pragma scheduling off
#pragma peephole off

extern void Obj_FreeObject(int* obj);
extern f32 timeDelta;

int fn_801601C4(int obj, GroundBaddieState* p)
{
    extern void*memcpy(void* dst, const void* src, int n);
    extern void voxmaps_updateRoutePath(char* a, char* b);
    extern f32 lbl_803E2E68;
    extern f32 lbl_803E2E6C;
    extern f32 lbl_803E2E70;
    extern f32 lbl_803E2E74;
    extern f32 lbl_803E2E78;
    GroundBaddieState* sub;
    char* wp;
    f32 z;

    sub = ((GameObject*)obj)->extra;
    if (*(void**)&p->baddie.targetObj != NULL)
    {
        (*gPlayerInterface)->setState((void*)obj, p, 1);
        wp = (char*)sub->route35C;
        z = lbl_803E2E68;
        p->baddie.moveInputX = z;
        p->baddie.moveInputZ = z;
        memcpy(wp, &((GameObject*)obj)->anim.localPosX, 12);
        memcpy((void*)(sub->route35C + 0xc), (void*)&((GameObject*)p->baddie.targetObj)->anim.localPosX, 12);
        voxmaps_updateRoutePath(wp, (char*)(sub->route35C + 0x28));
        if (p->baddie.targetDistance < lbl_803E2E6C && sub->subMode == 2)
        {
            return 5;
        }
        if (*(u8*)(wp + 0x25) == 0)
        {
            (*gPlayerInterface)->moveTowardPoint((void*)obj, p, *(f32*)(wp + 0x18), *(f32*)(wp + 0x20),
                                                 lbl_803E2E68, *(f32*)&lbl_803E2E68, lbl_803E2E70);
        }
        else
        {
            (*gPlayerInterface)->moveTowardPoint((void*)obj, p, *(f32*)(wp + 0x18), *(f32*)(wp + 0x20),
                                                 lbl_803E2E74, lbl_803E2E78, lbl_803E2E70);
        }
    }
    else
    {
        (*gPlayerInterface)->setState((void*)obj, p, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    return 0;
}

int fn_8016043C(int obj, GroundBaddieState* p)
{
    extern int Obj_GetPlayerObject(void);
    extern void ObjMsg_SendToObject(int target, int msg, int from, int a);
    extern void Obj_FreeObject(int* obj);
    ObjHitsPriorityState* hitState;

    if (*(char*)&p->baddie.moveJustStartedB != '\0')
    {
        (*gPlayerInterface)->setState((void*)obj, p, 3);
        *(int*)&p->baddie.targetObj = 0;
        *(s8*)&p->baddie.physicsActive = 0;
        *(s8*)&p->baddie.hasTarget = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    else
    {
        ObjMsg_SendToObject(Obj_GetPlayerObject(), 0xe0000, obj, 0);
        if (((GameObject*)obj)->anim.placementData == NULL)
        {
            Obj_FreeObject((int*)obj);
            return 0;
        }
        return 4;
    }
    return 0;
}

#pragma dont_inline on
void fn_801606F0(int obj, void* p2, int sub, GroundBaddieState* p)
{
    extern int* gBaddieControlInterface;
    extern void* gDllCBStateHandlers[];
    extern void* gDllCBMoveHandlers[];
    extern f32 lbl_803E2E9C;
    int setup;

    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    *(s8*)&p->baddie.moveDone = 1;
    if ((*(int (**)(int, u8*, f32, int))(*(int*)gBaddieControlInterface + 0x44))(
        obj, (u8*)p, (f32)(u32)((GroundBaddieState*)sub)->aggroRange, 1) != 0)
    {
        *(int*)&p->baddie.targetObj = ((GroundBaddieState*)sub)->savedObjC0;
        *(s8*)&p->baddie.hasTarget = 0;
        if (((DllCBPlacement*)setup)->trackYieldEnable != -1)
        {
            if (p2 != NULL)
            {
                (*gObjectTriggerInterface)->yield((ObjSeqState*)p2, ((DllCBPlacement*)setup)->trackYieldId);
            }
            *(s8*)&((GroundBaddieState*)sub)->subMode = 1;
        }
        else
        {
            *(int*)&p->baddie.targetObj = 0;
        }
    }
    (*(void (**)(int, u8*, f32, int))(*(int*)gBaddieControlInterface + 0x2c))(obj, (u8*)p,
                                                                              lbl_803E2E9C, 1);
    ((GroundBaddieState*)sub)->savedObjC0 = *(int*)&((GameObject*)obj)->pendingParentObj;
    *(int*)&((GameObject*)obj)->pendingParentObj = 0;
    (*gPlayerInterface)->update((void*)obj, p, timeDelta, timeDelta, gDllCBMoveHandlers, gDllCBStateHandlers);
    *(int*)&((GameObject*)obj)->pendingParentObj = ((GroundBaddieState*)sub)->savedObjC0;
}
#pragma dont_inline reset

#pragma dont_inline on
void fn_8016083C(int* obj, GroundBaddieState* sub, GroundBaddieState* p)
{
    extern void characterDoEyeAnims(int* obj, u8* a);
    extern f32 sqrtf(f32);
    extern int Obj_GetPlayerObject(void);
    extern int* gBaddieControlInterface;
    extern u8 lbl_80320008[];
    extern u8 lbl_80320080[];
    char* o;
    int t;
    struct
    {
        f32 x, y, z;
    } d;
    f32* dp = &d.x;

    if (((GameObject*)obj)->childObjs[0] != NULL)
    {
        *(int*)(*(int*)&((GameObject*)obj)->childObjs[0] + 0x30) = *(int*)&((GameObject*)obj)->anim.parent;
    }
    o = *(char**)&p->baddie.targetObj;
    if (o != NULL)
    {
        d.x = ((GameObject*)o)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        d.y = ((GameObject*)o)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        d.z = ((GameObject*)o)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        p->baddie.targetDistance = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
    }
    characterDoEyeAnims(obj, sub->route35C + 0x50);
    if ((sub->configFlags & 1) == 0)
    {
        (*(void (**)(int*, u8*, u8*, int, int, int, int))(*(int*)gBaddieControlInterface + 0x3c))(
            obj, (u8*)p, (u8*)&sub->flags400, 2, 3, sub->unk3FC, sub->unk3FA);
    }
    (*(void (**)(int*, u8*, u8*, int, u8*, int, int, int))(*(int*)gBaddieControlInterface +
        0x54))(
        obj, (u8*)p, sub->route35C, sub->gameBitB, &sub->subMode, 0, 0, 0);
    t = (*(int (**)(int*, u8*, u8*, int, u8*, u8*, int, int))(*(int*)gBaddieControlInterface +
        0x50))(
        obj, (u8*)p, sub->route35C, sub->gameBitB, lbl_80320008, lbl_80320080, 1, 0);
    if (t >= 4)
    {
        *(s8*)&sub->subMode = 2;
        *(int*)&p->baddie.targetObj = Obj_GetPlayerObject();
    }
}
#pragma dont_inline reset

int dll_CB_seqFn(short* obj, int p2, u8* e)
{

    extern int Curve_AdvanceAlongPath(int* p, f32 t);
    extern int getAngle(float y, float x);
    extern int* gBaddieControlInterface;
    extern void* gDllCBStateHandlers[];
    extern void* gDllCBMoveHandlers[];
    extern f32 lbl_803E2E8C;
    extern f32 lbl_803E2E98;
    extern f32 lbl_803E2E9C;
    int setup;
    RomCurveWalker* path;
    int sub;

    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    sub = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        return 0;
    }
    if (((GameObject*)obj)->seqIndex != -1)
    {
        if ((*(int (**)(short*, int, int))(*(int*)gBaddieControlInterface + 0x30))(obj, sub, 1) ==
            0)
        {
            return 1;
        }
        fn_8016083C((int*)obj, (GroundBaddieState*)sub, (GroundBaddieState*)sub);
        if (((GroundBaddieState*)sub)->gameBitC != -1 && GameBit_Get(((GroundBaddieState*)sub)->gameBitC) != 0)
        {
            (*gObjectTriggerInterface)->yield((ObjSeqState*)e, ((DllCBPlacement*)setup)->gameBitId);
            ((GroundBaddieState*)sub)->gameBitC = -1;
        }
        switch (((GroundBaddieState*)sub)->subMode)
        {
        case 2:
            ((ObjSeqState*)e)->flags = 0;
            fn_801606F0((int)obj, e, sub, (GroundBaddieState*)sub);
            if (((GroundBaddieState*)sub)->subMode == 1)
            {
                ((GroundBaddieState*)sub)->baddie.substate = 5;
                (*gPlayerInterface)->update(obj, (void*)sub, lbl_803E2E8C, *(f32*)&lbl_803E2E8C,
                                            gDllCBMoveHandlers, gDllCBStateHandlers);
                ((ObjSeqState*)e)->movementState = 0;
            }
            break;
        case 1:
            if ((*(int (**)(short*, u8*, int, void*, void*, int))(*(int*)gBaddieControlInterface +
                0x34))(
                obj, e, sub, gDllCBMoveHandlers, gDllCBStateHandlers, 0) != 0)
            {
                (*(void (**)(short*, int, f32, int))(*(int*)gBaddieControlInterface + 0x2c))(obj, sub, lbl_803E2E9C, 1);
            }
            break;
        case 0:
        default:
            ((ObjSeqState*)e)->flags = -1;
            ((ObjSeqState*)e)->flags &= ~0x40;
            path = (RomCurveWalker*)((GroundBaddieState*)sub)->path;
            if ((((GroundBaddieState*)sub)->flags400 & BADDIE_FLAG400_PATH_ACTIVE) != 0)
            {
                if ((Curve_AdvanceAlongPath((int*)path, ((GroundBaddieState*)sub)->baddie.animSpeedA) != 0 || path->atSegmentEnd != 0) &&
                    (*gRomCurveInterface)->goNextPoint(path) != 0)
                {
                    ((GroundBaddieState*)sub)->flags400 &= ~BADDIE_FLAG400_PATH_ACTIVE;
                }
                ((GroundBaddieState*)sub)->baddie.animSpeedA = lbl_803E2E98;
                ((GameObject*)obj)->anim.rotX = getAngle(path->tangentX, path->tangentZ) +
                    0x8000;
                ((GameObject*)obj)->anim.rotY = getAngle(path->tangentZ, path->tangentY) +
                    0x4000;
                ((GameObject*)obj)->anim.rotZ = getAngle(path->tangentY, path->tangentX) +
                    0x4000;
                ((GameObject*)obj)->anim.localPosX = path->posX;
                ((GameObject*)obj)->anim.localPosY = path->posY;
                ((GameObject*)obj)->anim.localPosZ = path->posZ;
            }
            break;
        }
    }
    if (((GameObject*)obj)->seqIndex == -1)
    {
        ((GroundBaddieState*)sub)->flags400 |= 2;
        return 0;
    }
    return ((GroundBaddieState*)sub)->subMode != 0;
}

#pragma scheduling on
#pragma peephole on

void chukchuk_free(void);
void chukchuk_hitDetect(void);
void chukchuk_release(void);
void chukchuk_initialise(void);

/*
 * Per-object extra state for the ChukChuk ice-spitter
 * (chukchuk_getExtraSize == 0x18).
 */

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

void chukchuk_init(u8* obj, u8* params);
void iceball_hitDetect(void);
void iceball_release(void);
void iceball_initialise(void);

void dll_CB_func0B_nop(void)
{
}

void dll_CB_release_nop(void)
{
}

extern f32 lbl_803E2EA8;

#pragma scheduling off
#pragma peephole off
void dll_CB_init(int* obj, u8* params, int extra)
{
    extern int* gBaddieControlInterface;
    GroundBaddieState* sub;
    u8 flags;

    sub = ((GameObject*)obj)->extra;
    flags = 0x16;
    if (extra != 0) flags |= 1;
    if ((params[0x2b] & 1) == 0) flags |= 8;
    ((GameObject*)obj)->anim.rotY = (s16)((s8)params[0x28] << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((s8)params[0x27] << 8);
    ((void(*)(int*, u8*, u8*, int, int, int, u8, f32))((void**)*(int*)gBaddieControlInterface)[22])(
        obj, params, (u8*)sub, 4, 6, 0x82, flags, lbl_803E2EA8);
    ((GameObject*)obj)->animEventCallback = dll_CB_seqFn;
    (*gPlayerInterface)->setState(obj, sub, 0);
    sub->baddie.substate = 0;
    if (sub->aggroRange < 0x32)
    {
        sub->aggroRange = 0x32;
    }
}

extern int Curve_AdvanceAlongPath(int* p, f32 t);
extern int getAngle(float y, float x);
extern f32 lbl_803E2E98;

void dll_CB_update(int* obj)
{
    extern int* gBaddieControlInterface;
    RomCurveWalker* path;
    GroundBaddieState* sub;
    u8* def;

    sub = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->unkF4 != 0) return;
    if (((GameObject*)obj)->unkF8 == 0)
    {
        ((GameObject*)obj)->anim.localPosX = ((DllCBPlacement*)def)->posX;
        ((GameObject*)obj)->anim.localPosY = ((DllCBPlacement*)def)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((DllCBPlacement*)def)->posZ;
        ((GameObject*)obj)->unkF8 = 1;
        return;
    }
    if ((sub->flags400 & 2) != 0)
    {
        ((void(*)(int*, u8*, u8*, s16, u8*, int, int, int, int))((int**)*(int**)gBaddieControlInterface)[10])(
            obj, (u8*)sub, sub->route35C, sub->gameBitB, &sub->subMode, 0, 0, 0, 1);
        sub->flags400 = (u16)(sub->flags400 & ~2);
    }
    if (((int(*)(int*, u8*, int))((int**)*(int**)gBaddieControlInterface)[12])(obj, (u8*)sub, 1) == 0) return;
    fn_8016083C(obj, sub, sub);
    path = (RomCurveWalker*)sub->path;
    if ((sub->flags400 & BADDIE_FLAG400_PATH_ACTIVE) == 0) return;
    if (Curve_AdvanceAlongPath((int*)path, sub->baddie.animSpeedA) != 0 || path->atSegmentEnd != 0)
    {
        if ((*gRomCurveInterface)->goNextPoint(path) != 0)
        {
            sub->flags400 = (u16)(sub->flags400 & ~BADDIE_FLAG400_PATH_ACTIVE);
        }
    }
    sub->baddie.animSpeedA = lbl_803E2E98;
    ((GameObject*)obj)->anim.rotX = (s16)(getAngle(path->tangentX, path->tangentZ) + 0x8000);
    ((GameObject*)obj)->anim.rotY = (s16)(getAngle(path->tangentZ, path->tangentY) + 0x4000);
    ((GameObject*)obj)->anim.rotZ = (s16)(getAngle(path->tangentY, path->tangentX) + 0x4000);
    ((GameObject*)obj)->anim.localPosX = path->posX;
    ((GameObject*)obj)->anim.localPosY = path->posY;
    ((GameObject*)obj)->anim.localPosZ = path->posZ;
}

int chukchuk_getExtraSize(void);
int chukchuk_getObjectTypeId(void);
int iceball_getExtraSize(void);
int iceball_getObjectTypeId(void);
int fn_8016052C(void) { return 0x6; }
int dll_CB_getExtraSize_ret_1040(void) { return 0x410; }
int dll_CB_getObjectTypeId(void) { return 0x14b; }

s16 dll_CB_setScale(int* obj) { return ((BaddieState*)((GameObject*)obj)->extra)->controlMode; }

extern void objRenderModelAndHitVolumes(int* obj, int p2, int p3, int p4, int p5, f32 scale);

void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void iceball_free(void);
void chukchuk_update(short* obj);
void chukchuk_setScale(int obj, int v);
void iceball_init(void* obj);

#pragma scheduling on
int fn_8016050C(int p1, u8* obj)
{
    if ((s8)obj[0x354] < 1) return 3;
    return 6;
}

extern int* gBaddieControlInterface;

#pragma scheduling off
int fn_801603E8(int* obj, u8* obj2)
{
    GroundBaddieState* x = ((GameObject*)obj)->extra;
    if ((s8)obj2[0x27b] != 0)
    {
        (*(VtableFn*)((char*)(*gBaddieControlInterface) + 0x4c))(obj, x->triggerId, -1, 0);
    }
    return 0;
}

extern u8 gDllCBMoveHandlers[];
#pragma peephole on
void dll_CB_hitDetect(int* obj)
{
    void* a = ((GameObject*)obj)->extra;
    (*gPlayerInterface)->updateVelocityState(obj, a, gDllCBMoveHandlers);
}

extern f32 lbl_803E2E8C;
#pragma scheduling on
#pragma peephole off
void dll_CB_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E2E8C);
            break;
        }
    }
}

extern f32 lbl_803E2E68;
#pragma scheduling off
#pragma peephole on
int fn_801605A8(short* out, u8* obj)
{
    f32 f = lbl_803E2E68;
    ((BaddieState*)obj)->animSpeedA = f;
    ((BaddieState*)obj)->animSpeedB = f;
    ((BaddieState*)obj)->physicsActive = 1;
    out[2] = ((BaddieState*)obj)->spawnRotZ;
    out[1] = ((BaddieState*)obj)->spawnRotY;
    return 0;
}

int fn_80160690(short* out, u8* obj)
{
    f32 f = lbl_803E2E68;
    ((BaddieState*)obj)->animSpeedA = f;
    ((BaddieState*)obj)->animSpeedB = f;
    ((BaddieState*)obj)->moveSpeed = f;
    ((BaddieState*)obj)->physicsActive = 1;
    out[2] = ((BaddieState*)obj)->spawnRotZ;
    out[1] = ((BaddieState*)obj)->spawnRotY;
    (*gPlayerInterface)->rotateTowardTarget(out, obj, 5);
    return 0;
}

extern u8 framesThisStep;
extern f32 lbl_803E2E7C;
extern f64 lbl_803E2E80;
extern f32 lbl_803E2E88;

#pragma peephole off
int fn_8016032C(int* obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        f32 fz;
        (*gPlayerInterface)->setState(obj, state, 0);
        fz = lbl_803E2E7C;
        ((GameObject*)obj)->anim.velocityY = fz;
        state->baddie.animSpeedA = fz;
        state->baddie.animSpeedC = fz;
    }
    if (((GameObject*)obj)->anim.velocityY < lbl_803E2E80)
    {
        f32 fz = lbl_803E2E68;
        ((GameObject*)obj)->anim.velocityY = fz;
        state->baddie.animSpeedA = fz;
        state->baddie.animSpeedC = fz;
        return 6;
    }
    {
        f32 d = lbl_803E2E88;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY / d;
        state->baddie.animSpeedA = state->baddie.animSpeedA / d;
        state->baddie.animSpeedC = state->baddie.animSpeedC / d;
    }
    return 0;
}

extern void* gDllCBStateHandlers[];
int fn_80160534(int* obj);

extern f32 lbl_803E2E90;
extern f32 lbl_803E2E94;

int fn_801605D4(int* obj, GroundBaddieState* def)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    if ((s8)def->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2E68, 0);
        *(s8*)&def->baddie.moveDone = 0;
    }
    *(s8*)&def->baddie.physicsActive = 1;
    ((GameObject*)obj)->anim.rotZ = def->baddie.spawnRotZ;
    ((GameObject*)obj)->anim.rotY = def->baddie.spawnRotY;
    ((void(*)(int*, u8*, int*, f32, f32))((void**)*gBaddieControlInterface)[4])(
        obj, (u8*)def, (int*)state, lbl_803E2E8C, lbl_803E2E90);
    def->baddie.moveSpeed = lbl_803E2E94 * def->baddie.animSpeedA;
    return 0;
}

void dll_CB_initialise(void)
{
    ((void**)gDllCBMoveHandlers)[0] = fn_80160690;
    ((void**)gDllCBMoveHandlers)[1] = fn_801605D4;
    ((void**)gDllCBMoveHandlers)[2] = fn_801605A8;
    ((void**)gDllCBMoveHandlers)[3] = fn_80160534;
    gDllCBStateHandlers[0] = fn_8016052C;
    gDllCBStateHandlers[1] = fn_8016050C;
    gDllCBStateHandlers[2] = fn_8016043C;
    gDllCBStateHandlers[3] = fn_801603E8;
    gDllCBStateHandlers[4] = fn_8016032C;
    gDllCBStateHandlers[5] = fn_801601C4;
}

#pragma peephole on
int fn_80160534(int* obj)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    u8 step;
    if (((GameObject*)obj)->anim.alpha >= (step = framesThisStep))
    {
        ((GameObject*)obj)->anim.alpha = ((GameObject*)obj)->anim.alpha - step;
    }
    else
    {
        ((GameObject*)obj)->anim.alpha = 0;
    }
    if (((GameObject*)obj)->anim.alpha == 0)
    {
        GameBit_Set(sub->gameBitB, 0);
        GameBit_Set(sub->gameBitA, 1);
    }
    return 0;
}

#pragma peephole off
void dll_CB_free(int* obj)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, DLLCB_OBJGROUP);
    {
        int* sub = ((GameObject*)obj)->childObjs[0];
        if (sub != NULL)
        {
            Obj_FreeObject(sub);
            ((GameObject*)obj)->childObjs[0] = NULL;
        }
    }
    ((void(*)(int*, int*, int))((void**)*gBaddieControlInterface)[16])(obj, (int*)state, 1);
}

ObjectDescriptor11WithPadding gChukChukObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)chukchuk_initialise,
        (ObjectDescriptorCallback)chukchuk_release,
        0,
        (ObjectDescriptorCallback)chukchuk_init,
        (ObjectDescriptorCallback)chukchuk_update,
        (ObjectDescriptorCallback)chukchuk_hitDetect,
        (ObjectDescriptorCallback)chukchuk_render,
        (ObjectDescriptorCallback)chukchuk_free,
        (ObjectDescriptorCallback)chukchuk_getObjectTypeId,
        chukchuk_getExtraSize,
        (ObjectDescriptorCallback)chukchuk_setScale,
    },
    0,
};

ObjectDescriptor gIceBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)iceball_initialise,
    (ObjectDescriptorCallback)iceball_release,
    0,
    (ObjectDescriptorCallback)iceball_init,
    (ObjectDescriptorCallback)iceball_update,
    (ObjectDescriptorCallback)iceball_hitDetect,
    (ObjectDescriptorCallback)iceball_render,
    (ObjectDescriptorCallback)iceball_free,
    (ObjectDescriptorCallback)iceball_getObjectTypeId,
    iceball_getExtraSize,
};
