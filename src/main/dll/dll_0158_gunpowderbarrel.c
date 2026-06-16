/*
 * GunPowderBarrel (DLL 0x158) - carryable gunpowder barrel (+ MetalBarrel).
 * TU = 0x801A0B14..0x801A27B8 (helper group at the head, then the barrel
 * descriptor fns).
 */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/gunpowderbarrel_state.h"
#include "main/dll/player_motion.h"
#include "main/objlib.h"

typedef struct GunpowderbarrelTriggerExplosionPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} GunpowderbarrelTriggerExplosionPlacement;

typedef struct GunpowderbarrelTriggerExplosionState
{
    u8 pad0[0x10 - 0x0];
    void* unk10;
    u8 pad14[0x34 - 0x14];
    f32 unk34;
} GunpowderbarrelTriggerExplosionState;

typedef struct GunpowderbarrelState
{
    u8 pad0[0x10 - 0x0];
    s32 unk10;
    u8 pad14[0x34 - 0x14];
    f32 unk34;
} GunpowderbarrelState;

typedef struct GunpowderbarrelUpdatePhysicsState
{
    u8 pad0[0xC - 0x0];
    void* unkC;
    void* unk10;
    u8 pad14[0x20 - 0x14];
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    u8 pad2C[0x34 - 0x2C];
    f32 unk34;
    f32 slideTimer;
    u8 pad3C[0x44 - 0x3C];
    s16 unk44;
    s16 unk46;
} GunpowderbarrelUpdatePhysicsState;

extern undefined4 FUN_80006824();
extern int FUN_80017a90();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_8013651c();
extern int FUN_8020a468();
extern undefined4 FUN_8020a90c();
extern uint FUN_80286838();
extern undefined4 FUN_80286884();

extern undefined4* DAT_803dd740;
extern f32 lbl_803E4F58;
extern f32 lbl_803E4F5C;
extern f32 lbl_803E4FA0;

extern undefined4* gCarryableInterface;
extern f32 lbl_803E42DC;
extern void objRenderFn_8003b8f4(int* obj, int a, int b, int c, int d, f32 e);
extern int barrelgener_getLinkId();
extern void saveGame_saveObjectPos(int* obj);
extern void spawnExplosion(int* obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern u8* getTrickyObject(void);
extern void trickyImpress(u8 * tricky);
extern void timer_clearManualFlags();
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern void objMove(int* obj, f32 x, f32 y, f32 z);
extern int fn_80062D60(int* obj, f32 x, f32 top, f32 z, f32 bottom, f32* outY, int** outObj);
extern void gunpowderbarrel_setPlayerHeldState(int* obj, u8 heldByPlayer);
extern void fn_801A0F58(int* obj, s16 a, s16 b);
extern f32 timeDelta;
extern f32 lbl_803E42C0;
extern f32 lbl_803E42C4;
extern f32 lbl_803E4308;
extern f32 lbl_803E430C;
extern f32 lbl_803E4310;
extern f32 lbl_803E4314;
extern f32 lbl_803E4318;
extern f32 lbl_803E431C;
extern f32 lbl_803E4320;
extern f32 lbl_803DBE88;
extern int fn_80080150(void* p1);
extern int objHitDetectFn_80062e84(int p1, int p2, int p3);
extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, int p5, int obj, int p7, int p8, int p9, int p10);
extern void Vec3_ReflectAgainstNormal(void* normal, void* velocity, void* out);
extern f32 PSVECMag(f32 * v);
extern f32 oneOverTimeDelta;
extern f32 lbl_803DBE84;
extern f32 lbl_803E4324;
extern f32 lbl_803E4328;
extern f32 lbl_803E432C;
extern f32 lbl_803E4330;
extern f32 lbl_803E4334;
extern void storeZeroToFloatParam(void* p);
extern int timerCountDown(void* p);
extern void s16toFloat(void* p, int v);
extern void memset(void* p, int c, int n);
extern int playerIsDisguised(u8 * player);
extern int timer_isEffectMode(int obj);
extern void timer_forceStart(int obj);
extern int timer_hasExpired(int obj);
extern void barrelgener_queueObjectRelease(int gen, int obj, int code);
extern void Obj_RemoveFromUpdateList(int obj);
extern u32 playerGetStateFlag310(u8 * player);
extern void setAButtonIcon(int kind);
extern int fn_802966B4(u8 * player);
extern int fn_8029669C(u8 * player);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern void fn_801A1230(int obj);
extern void* Obj_GetPlayerObject(void);
extern u8 framesThisStep;
extern f32 lbl_803E4338;
extern f32 lbl_803E433C;
extern f32 lbl_803E4340;
extern f32 lbl_803DBE80;
extern void gunpowderbarrel_launchAtTarget(int obj, u8 flag);
extern void vecRotateZXY(s16 * rotIn, f32 * outVec);
extern f32 lbl_803E42C8;
extern f32 lbl_803E42CC;
extern f32 lbl_803E42D0;
extern f32 lbl_803E42D4;
extern f32 lbl_803E42D8;
extern f32 lbl_803E42E0;
extern f32 lbl_803E42E4;
extern const f32 lbl_803E42E8;
extern f32 lbl_803E42EC;
extern f32 lbl_803E42F0;

void FUN_801a1230(int param_1, char param_2)
{
    int extra;
    ObjHitsPriorityState* hitState;

    extra = *(int*)&((GameObject*)param_1)->extra;
    hitState = (ObjHitsPriorityState*)((GameObject*)param_1)->anim.hitReactState;
    if (param_2 == '\0')
    {
        hitState->lateralResponseWeight = ((GameObject*)param_1)->anim.modelInstance->lateralResponseWeight;
        hitState->axialResponseWeight = ((GameObject*)param_1)->anim.modelInstance->axialResponseWeight;
        *(byte*)(extra + 0x4a) = *(byte*)(extra + 0x4a) & 0x7f;
        *(byte*)&((GameObject*)param_1)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_1)->anim.resetHitboxMode &
            0xf7;
        ObjHits_ClearFlags(param_1, 0x400);
        *(byte*)(extra + 0x49) = *(byte*)(extra + 0x49) | 1;
    }
    else
    {
        hitState->lateralResponseWeight = 1;
        hitState->axialResponseWeight = 1;
        *(byte*)&((GameObject*)param_1)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_1)->anim.resetHitboxMode |
            8;
        *(byte*)(extra + 0x4a) = *(byte*)(extra + 0x4a) & 0x7f | 0x80;
        *(byte*)(extra + 0x49) = *(byte*)(extra + 0x49) & 0xfd;
        ObjHits_SetFlags(param_1, 0x480);
        ObjHits_ClearSourceMask(param_1, 1);
        ObjHits_EnableObject(param_1);
        ObjHits_SyncObjectPositionIfDirty(param_1);
    }
    return;
}

void FUN_801a1654(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    uint obj;
    ObjHitsPriorityState* hitState;
    int result;
    uint* objs;
    int linkId;
    uint* p;
    int def;
    int i;
    int extra;
    double in_f29;
    double savedZ;
    double in_f30;
    double savedY;
    double in_f31;
    double savedX;
    double in_ps29_1;
    double in_ps30_1;
    double in_ps31_1;
    int local_58;
    int hitObject;
    float local_28;
    float fStack_24;
    float local_18;
    float fStack_14;
    float local_8;
    float fStack_4;

    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
    local_18 = (float)in_f30;
    fStack_14 = (float)in_ps30_1;
    local_28 = (float)in_f29;
    fStack_24 = (float)in_ps29_1;
    obj = FUN_80286838();
    extra = *(int*)(obj + 0xb8);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    result = ObjHits_GetPriorityHit(obj, &hitObject, (int*)0x0, (uint*)0x0);
    if ((result != 0) || ((hitState->contactFlags != 0 && ((*(byte*)(extra + 0x49) & 2) != 0))))
    {
        *(char*)(extra + 0x16) = *(char*)(extra + 0x16) + '\x01';
        *(byte*)(extra + 0x49) = *(byte*)(extra + 0x49) | 1;
    }
    if (*(char*)(extra + 0x16) != '\0')
    {
        if ((*(byte*)(extra + 0x48) >> 6 & 1) != 0)
        {
            def = *(int*)(obj + 0x4c);
            result = 0;
            if (*(short*)(def + 0x1a) == 0)
            {
                result = ObjGroup_FindNearestObject(0x3a, obj, (float*)0x0);
            }
            else
            {
                objs = ObjGroup_GetObjects(0x3a, &local_58);
                p = objs;
                for (i = 0; i < local_58; i = i + 1)
                {
                    linkId = FUN_8020a468(*p);
                    if (*(short*)(def + 0x1a) == linkId)
                    {
                        result = objs[i];
                        break;
                    }
                    p = p + 1;
                }
            }
            if (result != 0)
            {
                savedX = (double)*(float*)(obj + 0xc);
                savedY = (double)*(float*)(obj + 0x10);
                savedZ = (double)*(float*)(obj + 0x14);
                *(undefined4*)(obj + 0xc) = *(undefined4*)(result + 0xc);
                *(undefined4*)(obj + 0x10) = *(undefined4*)(result + 0x10);
                *(undefined4*)(obj + 0x14) = *(undefined4*)(result + 0x14);
                FUN_800e8630(obj);
                *(float*)(obj + 0xc) = (float)savedX;
                *(float*)(obj + 0x10) = (float)savedY;
                *(float*)(obj + 0x14) = (float)savedZ;
            }
        }
        ObjHits_ClearFlags(obj, 0x80);
        ObjHits_SetSourceMask(obj, 1);
        ObjHitbox_SetCapsuleBounds(obj, 0x14, -5, 0x14);
        ObjHits_EnableObject(obj);
        ObjHits_MarkObjectPositionDirty(obj);
        ObjHits_SetHitVolumeSlot(obj, 5, 4, 0);
        FUN_80006824(obj, SFXsk_bapt11_c);
        *(float*)(obj + 0x10) = *(float*)(obj + 0x10) + lbl_803E4FA0;
        FUN_8008112c((double)lbl_803E4F58, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 1, 1, 0, 0, 0, 1, 0);
        if (*(char*)(extra + 0x15) != '\0')
        {
            (**(code**)(*DAT_803dd740 + 0x30))(obj, extra);
            *(undefined*)(extra + 0x15) = 0;
        }
        *(undefined*)(extra + 0x17) = 1;
        *(byte*)(extra + 0x4a) = *(byte*)(extra + 0x4a) & 0xdf;
        ObjGroup_RemoveObject(obj, 0x19);
        if (*(int*)(obj + 0x30) == 0)
        {
            *(float*)(extra + 0x34) = lbl_803E4F5C;
        }
        else
        {
            *(float*)(extra + 0x34) = lbl_803E4F5C;
        }
        result = FUN_80017a90();
        if (result != 0)
        {
            FUN_8013651c(result);
        }
        *(byte*)(extra + 0x49) = *(byte*)(extra + 0x49) & 0xfd;
        if (*(int*)(extra + 0x10) != 0)
        {
            FUN_8020a90c(*(int*)(extra + 0x10));
        }
    }
    FUN_80286884();
    return;
}

int gunpowderbarrel_getExtraSize(void)
{
    return 0x58;
}

void gunpowderbarrel_free(int obj, int param_2)
{
    extern int Obj_IsObjectAlive(int obj); /* #57 */
    int extra;
    void* child;
    extra = *(int*)&((GameObject*)obj)->extra;
    (*(code*)(*(int*)gCarryableInterface + 0x10))(obj);
    child = (void*)((GunpowderbarrelState*)extra)->unk10;
    if (child != NULL && param_2 == 0)
    {
        if (Obj_IsObjectAlive((int)child) != 0)
        {
            ObjLink_DetachChild(obj, ((GunpowderbarrelState*)extra)->unk10);
            ((GunpowderbarrelState*)extra)->unk10 = 0;
        }
    }
    ObjGroup_RemoveObject(obj, 0x19);
    ObjGroup_RemoveObject(obj, 0x16);
    if (*(unsigned char*)(extra + 0x17) != 0)
    {
        (*gExpgfxInterface)->freeSource2((u32)obj);
    }
}

typedef struct
{
    u8 playerHeld_ : 1;
    u8 unk40_ : 1;
    u8 held_ : 1;
    u8 rest_ : 5;
} GpbHeld4A;

void gunpowderbarrel_render(int* obj, int param_2, int param_3, int param_4, int param_5,
                            s8 visFlag)
{
    u8* sub;
    int result;
    int* child;

    sub = ((GameObject*)obj)->extra;
    if (sub[0x17] != 0 || ((GpbHeld4A*)(sub + 0x4a))->held_)
    {
        return;
    }
    if (sub[0x15] != 0)
    {
        ((GameObject*)obj)->anim.rotZ = 0;
        ((GameObject*)obj)->anim.rotY = 0;
    }
    result = (*(int (**)(int*, int))(*(int*)gCarryableInterface + 0xc))(obj, visFlag);
    if (result != 0 || visFlag == -1)
    {
        objRenderFn_8003b8f4(obj, param_2, param_3, param_4, param_5, lbl_803E42DC);
    }
    child = *(int**)&((GunpowderbarrelState*)sub)->unk10;
    if (child != 0)
    {
        (*(void (**)(int*, int, int, int, int, s8))(*(int*)(*(int*)((char*)child + 0x68)) + 0x10))(
            child, param_2, param_3, param_4, param_5, visFlag);
    }
}

/* Drift-recovery: v1.0 function set (the FUN_801a1xxx above are v1.1-shaped). */

typedef struct
{
    u8 playerHeld : 1; /* 0x80 */
    u8 unk40 : 1; /* 0x40 */
    u8 held : 1; /* 0x20 */
    u8 onGround : 1; /* 0x10 */
    u8 wasOnGround : 1; /* 0x08 */
    u8 landed : 1; /* 0x04 */
    u8 unk02 : 1; /* 0x02 */
    u8 unk01 : 1; /* 0x01 */
} GpbFlags4A;

typedef struct
{
    u8 unk80 : 1; /* 0x80 */
    u8 returnHome : 1; /* 0x40 */
    u8 unkRest : 6;
} GpbFlags48;

/* EN v1.0 0x801A1230  size: 708b  gunpowderbarrel_triggerExplosion: when hit
 * (or touched while resting on a damage source) blow the barrel up, optionally
 * re-saving its position at the owning generator first. */
void gunpowderbarrel_triggerExplosion(int* obj)
{
    u8* sub;
    int hitObj;
    int count;
    u8* tricky;
    int* timer;

    sub = ((GameObject*)obj)->extra;
    if (ObjHits_GetPriorityHit((int)obj, &hitObj, 0, 0) != 0 ||
        (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags != 0 && (sub[0x49] & 2) != 0))
    {
        sub[0x16] += 1;
        sub[0x49] = (u8)(sub[0x49] | 1);
    }
    if (sub[0x16] != 0)
    {
        if (((GpbFlags48*)(sub + 0x48))->returnHome)
        {
            int* def = *(int**)&((GameObject*)obj)->anim.placementData;
            int* best = 0;
            int** objs;
            int i;
            int** p;
            if (((GunpowderbarrelTriggerExplosionPlacement*)def)->unk1A != 0)
            {
                objs = (int**)ObjGroup_GetObjects(0x3a, &count);
                for (i = 0; i < count; i++)
                {
                    int id = barrelgener_getLinkId(objs[i]);
                    if (((GunpowderbarrelTriggerExplosionPlacement*)def)->unk1A == id)
                    {
                        best = objs[i];
                        break;
                    }
                }
            }
            else
            {
                best = (int*)ObjGroup_FindNearestObject(0x3a, (u32)obj, 0);
            }
            if (best != 0)
            {
                f32 x, y, z;
                x = ((GameObject*)obj)->anim.localPosX;
                y = ((GameObject*)obj)->anim.localPosY;
                z = ((GameObject*)obj)->anim.localPosZ;
                ((GameObject*)obj)->anim.localPosX = ((GameObject*)best)->anim.localPosX;
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)best)->anim.localPosY;
                ((GameObject*)obj)->anim.localPosZ = ((GameObject*)best)->anim.localPosZ;
                saveGame_saveObjectPos(obj);
                ((GameObject*)obj)->anim.localPosX = x;
                ((GameObject*)obj)->anim.localPosY = y;
                ((GameObject*)obj)->anim.localPosZ = z;
            }
        }
        ObjHits_ClearFlags((int)obj, 0x80);
        ObjHits_SetSourceMask((int)obj, 1);
        ObjHitbox_SetCapsuleBounds((int)obj, 0x14, -5, 0x14);
        ObjHits_EnableObject((int)obj);
        ObjHits_SetHitVolumeSlot((int)obj, 5, 4, 0);
        Sfx_PlayFromObject((u32)obj, SFXsk_bapt11_c);
        ((GameObject*)obj)->anim.localPosY += lbl_803E4308;
        spawnExplosion(obj, lbl_803E42C0, 1, 1, 0, 0, 0, 1, 0);
        if (sub[0x15] != 0)
        {
            (*(void (**)(int*, u8*))(*(int*)gCarryableInterface + 0x30))(obj, sub);
            sub[0x15] = 0;
        }
        sub[0x17] = 1;
        ((GpbFlags4A*)(sub + 0x4a))->held = 0;
        ObjGroup_RemoveObject((u32)obj, 0x19);
        if (((GameObject*)obj)->anim.parent != 0)
        {
            ((GunpowderbarrelTriggerExplosionState*)sub)->unk34 = lbl_803E42C4;
        }
        else
        {
            ((GunpowderbarrelTriggerExplosionState*)sub)->unk34 = lbl_803E42C4;
        }
        tricky = getTrickyObject();
        if (tricky != 0)
        {
            trickyImpress(tricky);
        }
        sub[0x49] = (u8)(sub[0x49] & ~2);
        timer = *(int**)&((GunpowderbarrelTriggerExplosionState*)sub)->unk10;
        if (timer != 0)
        {
            timer_clearManualFlags(timer);
        }
    }
}

/* EN v1.0 0x801A14F4  size: 928b  gunpowderbarrel_updatePhysics: gravity,
 * velocity clamps, ground probe + landing sfx, contact handling. */
void gunpowderbarrel_updatePhysics(int* obj)
{
    u8* sub;
    int* contact;
    f32 outY;
    int block;
    f32 dt;

    sub = ((GameObject*)obj)->extra;
    if (((GpbFlags4A*)(sub + 0x4a))->held)
    {
        return;
    }
    block = objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                ((GameObject*)obj)->anim.localPosZ);
    if (block == -1)
    {
        if (sub[0x49] & 2)
        {
            sub[0x16] = 4;
        }
        return;
    }
    if (sub[0x16] == 0 && ((sub[0x49] & 2) || ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityY > lbl_803E430C))
    {
        ObjHits_SetHitVolumeSlot((u32)obj, 0xe, 1, 0);
        ObjHits_EnableObject((u32)obj);
    }
    if (!((GpbFlags4A*)(sub + 0x4a))->playerHeld)
    {
        ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityY -= lbl_803E4310 * timeDelta;
    }
    {
        f32 v = ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityX;
        ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityX = (v < lbl_803E4314)
                                                                   ? lbl_803E4314
                                                                   : ((v > lbl_803E4318) ? lbl_803E4318 : v);
    }
    {
        f32 v = ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityY;
        ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityY = (v < lbl_803E4314)
                                                                   ? lbl_803E4314
                                                                   : ((v > lbl_803E4318) ? lbl_803E4318 : v);
    }
    {
        f32 v = ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityZ;
        ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityZ = (v < lbl_803E4314)
                                                                   ? lbl_803E4314
                                                                   : ((v > lbl_803E4318) ? lbl_803E4318 : v);
    }
    ((GameObject*)obj)->anim.velocityX = ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityX;
    ((GameObject*)obj)->anim.velocityY = ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityY;
    ((GameObject*)obj)->anim.velocityZ = ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityZ;
    dt = timeDelta;
    objMove(obj, ((GameObject*)obj)->anim.velocityX * dt, ((GameObject*)obj)->anim.velocityY * dt,
            ((GameObject*)obj)->anim.velocityZ * dt);
    ((GpbFlags4A*)(sub + 0x4a))->onGround = 0;
    if (!(sub[0x49] & 2))
    {
        f32 top;
        f32 bottom;
        int below;
        int result;

        top = ((GameObject*)obj)->anim.previousLocalPosY;
        bottom = ((GameObject*)obj)->anim.localPosY;
        below = top < bottom;
        if (below)
        {
            bottom += lbl_803E4318;
        }
        if (!below)
        {
            top += lbl_803E4318;
        }
        result = fn_80062D60(obj, ((GameObject*)obj)->anim.localPosX, top, ((GameObject*)obj)->anim.localPosZ,
                             bottom, &outY, &contact);
        if (result != 0)
        {
            if (result == 2)
            {
                sub[0x16] = 4;
            }
            else
            {
                if (!((GpbFlags4A*)(sub + 0x4a))->wasOnGround)
                {
                    if (((GpbFlags4A*)(sub + 0x4a))->landed)
                    {
                        Sfx_PlayFromObject((u32)obj, SFXsk_baptr1_c);
                    }
                    else
                    {
                        ((GpbFlags4A*)(sub + 0x4a))->landed = 1;
                    }
                }
                ((GpbFlags4A*)(sub + 0x4a))->onGround = 1;
                ((GameObject*)obj)->anim.localPosY = outY;
            }
        }
    }
    if (((GpbFlags4A*)(sub + 0x4a))->onGround)
    {
        f32 z = lbl_803E42C0;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityY = z;
        ((GameObject*)obj)->anim.velocityZ = z;
        ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityX = z;
        ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityY = z;
        ((GunpowderbarrelUpdatePhysicsState*)sub)->velocityZ = z;
        if (contact != 0)
        {
            u32 flags;
            ObjHits_AddContactObject((int)contact, (int)obj);
            flags = ((ObjAnimComponent*)contact)->modelInstance->flags;
            if ((flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE) && !(flags & 0x8000))
            {
                *(int**)&((GunpowderbarrelUpdatePhysicsState*)sub)->unkC = contact;
            }
            else if (((GunpowderbarrelUpdatePhysicsState*)sub)->slideTimer < lbl_803E431C)
            {
                sub[0x16] = 4;
            }
        }
        if (((GpbFlags4A*)(sub + 0x4a))->playerHeld)
        {
            gunpowderbarrel_setPlayerHeldState(obj, 0);
        }
        ((GunpowderbarrelUpdatePhysicsState*)sub)->slideTimer = lbl_803E42C0;
    }
    else
    {
        if (((GunpowderbarrelUpdatePhysicsState*)sub)->velocityY < lbl_803E4320)
        {
            fn_801A0F58(obj, ((GunpowderbarrelUpdatePhysicsState*)sub)->unk44,
                        ((GunpowderbarrelUpdatePhysicsState*)sub)->unk46);
        }
        if (!((GpbFlags4A*)(sub + 0x4a))->held && !((GpbFlags4A*)(sub + 0x4a))->playerHeld)
        {
            ((GunpowderbarrelUpdatePhysicsState*)sub)->slideTimer += ((GameObject*)obj)->anim.velocityY;
            if (((GunpowderbarrelUpdatePhysicsState*)sub)->slideTimer < -lbl_803DBE88)
            {
                sub[0x16] = 4;
            }
        }
    }
    ((GpbFlags4A*)(sub + 0x4a))->wasOnGround = ((GpbFlags4A*)(sub + 0x4a))->onGround;
}

/* Tail of the TU (0x801A1A60..0x801A27B8) - formerly the head of
 * cannontargetControl.c (now dll_0159_blasted.c). */

typedef struct GunpowderbarrelPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} GunpowderbarrelPlacement;

void gunpowderbarrel_hitDetect(int param_1)
{
    extern int Obj_IsObjectAlive(int obj); /* #57 */
    GameObject* barrel;
    GunpowderBarrelState* state;
    f32 sp1c[3];
    f32 sp10[3];
    f32 collision_buf[24];

    barrel = (GameObject*)param_1;
    state = barrel->extra;

    if ((int)Obj_IsObjectAlive(state->linkedTimerObject) == 0)
    {
        if ((void*)state->linkedTimerObject != NULL)
        {
            ObjLink_DetachChild(param_1, state->linkedTimerObject);
            state->linkedTimerObject = 0;
        }
    }

    if (state->fuseFrames != 0u)
    {
        return;
    }

    if (fn_80080150(&state->respawnTimer) != 0)
    {
        return;
    }
    if (fn_80080150(&state->releaseTimer) != 0)
    {
        return;
    }

    if ((void*)state->queuedHitObject != NULL)
    {
        objHitDetectFn_80062e84(param_1, state->queuedHitObject, 1);
        state->queuedHitObject = 0;
    }

    if (((state->heldFlags >> 7) & 1) != 0u)
    {
        sp1c[0] = barrel->anim.localPosX - barrel->anim.previousLocalPosX;
        sp1c[1] = barrel->anim.localPosY - barrel->anim.previousLocalPosY;
        sp1c[2] = barrel->anim.localPosZ - barrel->anim.previousLocalPosZ;
        {
            f32 inv = lbl_803E4324 * oneOverTimeDelta;
            sp1c[0] = sp1c[0] * inv;
            sp1c[1] = sp1c[1] * inv;
            sp1c[2] = sp1c[2] * inv;
        }
        state->throwVelX = ((f32*)sp1c)[0] + state->throwVelX;
        state->throwVelY = ((f32*)sp1c)[1] + state->throwVelY;
        state->throwVelZ = ((f32*)sp1c)[2] + state->throwVelZ;
        sp1c[1] = lbl_803E42C0;
        state->throwVelX = lbl_803E4328 * state->throwVelX;
        state->throwVelY = lbl_803E4328 * state->throwVelY;
        state->throwVelZ = lbl_803E4328 * state->throwVelZ;
        state->throwVelY = sp1c[1];
        state->motionFlags = (u8)(state->motionFlags | 1);
    }

    if (state->heldByCarryInterface != 0)
    {
        goto copy_end;
    }

    if (objBboxFn_800640cc(param_1 + 0x80, param_1 + 0xc, lbl_803E432C, 1,
                           (int)&collision_buf[0], param_1, 8, -1, 0xff, 0) == 0)
    {
        goto copy_end;
    }

    if ((s8) * ((u8*)&collision_buf[0] + 0x51) == 0x14)
    {
        state->unk16 = 4;
    }

    if (((state->heldFlags >> 7) & 1) != 0u &&
        (s8) * ((u8*)&collision_buf[0] + 0x51) == 3)
    {
        gunpowderbarrel_setPlayerHeldState((int*)param_1, 0);
        ObjGroup_RemoveObject(param_1, 0x16);
        goto copy_end;
    }

    sp10[0] = *((f32*)&collision_buf[0] + 7);
    sp10[1] = *((f32*)&collision_buf[0] + 8);
    sp10[2] = *((f32*)&collision_buf[0] + 9);
    Vec3_ReflectAgainstNormal(sp10, (void*)(param_1 + 0x24), (void*)(param_1 + 0x24));
    Vec3_ReflectAgainstNormal(sp10, &state->throwVelX, &state->throwVelX);

    {
        f32 damp = lbl_803E4330;
        barrel->anim.velocityX = damp * barrel->anim.velocityX;
        barrel->anim.velocityY = damp * barrel->anim.velocityY;
        barrel->anim.velocityZ = damp * barrel->anim.velocityZ;
        state->throwVelX = damp * state->throwVelX;
        state->throwVelY = damp * state->throwVelY;
        state->throwVelZ = damp * state->throwVelZ;
    }
    (void)sp1c;

    if (state->impactSoundCooldown > lbl_803E4334)
    {
        if (PSVECMag(&state->throwVelX) > lbl_803DBE84)
        {
            Sfx_PlayFromObject((u32)param_1, 0x446);
        }
        state->impactSoundCooldown = lbl_803E42C0;
    }

copy_end:
    barrel->anim.previousLocalPosX = barrel->anim.localPosX;
    barrel->anim.previousLocalPosY = barrel->anim.localPosY;
    barrel->anim.previousLocalPosZ = barrel->anim.localPosZ;
    return;
}

typedef struct
{
    u8 b7 : 1;
    u8 b6 : 1;
    u8 b5 : 1;
    u8 b4 : 1;
    u8 b3 : 1;
    u8 b2 : 1;
    u8 b1 : 1;
    u8 b0 : 1;
} BarrelBits;

/* EN v1.0 0x801A25E8  size: 464b  Gunpowder-barrel setup: registers with the
 * carryable interface and obj groups, zeroes the roll/contact state, seeds
 * the hit radius from the model's bound halfword, and latches the
 * indestructible bit for the cannon-range variant (type 0x754). */
void gunpowderbarrel_init(int obj, u8* def)
{
    GunpowderBarrelState* state = ((GameObject*)obj)->extra;

    ((GunpowderBarrelState*)((GameObject*)obj)->extra)->unk07 |= 2;
    (*(void (**)(int, GunpowderBarrelState*, int))((char*)*gCarryableInterface + 0x4))(obj, state, 5);
    ObjGroup_AddObject(obj, 0x19);
    ObjGroup_AddObject(obj, 0x16);
    ObjMsg_AllocQueue((void*)obj, 8);
    ((GameObject*)obj)->unkF8 = 0;
    state->unk44 = 0;
    state->unk46 = 0;
    state->heldByCarryInterface = 0;
    state->unk3C = 0;
    state->unk16 = 0;
    state->fuseFrames = 0;
    state->unk3E = 0;
    state->unk40 = 0;
    state->unk30 = lbl_803E42C0;
    state->motionFlags = 0;
    storeZeroToFloatParam(&state->respawnTimer);
    storeZeroToFloatParam(&state->releaseTimer);
    state->motionFlags |= 1;
    {
        u8 v;
        v = ((s8)def[0x19] >= 1) ? 0 : 1;
        ((BarrelBits*)&state->configFlags)->b7 = v;
        v = (*(s16*)(def + 0x1c) == 0) ? 0 : 1;
        ((BarrelBits*)&state->configFlags)->b6 = v;
    }
    ObjHits_EnableObject(obj);
    state->hitRadius = (f32)((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->primaryRadius;
    ((BarrelBits*)&state->heldFlags)->b5 = 0;
    state->unk38 = lbl_803E42C0;
    state->linkedTimerObject = 0;
    (*(void (**)(GunpowderBarrelState*, int))((char*)*gCarryableInterface + 0x2c))(state, 1);
    if ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState != NULL)
    {
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->trackContactMask = 1;
    }
    if (((GameObject*)obj)->anim.seqId == 0x754)
    {
        ((BarrelBits*)&state->heldFlags)->b1 = 1;
    }
}

/* EN v1.0 0x801A1D48  size: 2208b  Gunpowder-barrel per-frame driver: runs
 * the fuse/respawn timers, manages the cannon attach link, drains the
 * held/released message queue, grows the hitbox while the fuse burns and
 * hands the barrel back to its generator, and handles the pickup/steal/toss
 * transitions against the player's carry state. */
void gunpowderbarrel_update(int obj)
{
    GunpowderBarrelState* state = ((GameObject*)obj)->extra;
    extern void ObjHitbox_SetCapsuleBounds(int obj, int radius, int a, int b); /* #57 */
    u8* player = Obj_GetPlayerObject();
    int def = *(int*)&((GameObject*)obj)->anim.placementData;

    if (state->impactSoundCooldown <= lbl_803E4334)
    {
        state->impactSoundCooldown += timeDelta;
    }
    if (fn_80080150(&state->respawnTimer) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        if (timerCountDown(&state->respawnTimer) != 0)
        {
            state->fuseFrames = 0;
            state->unk16 = 0;
            state->motionFlags |= 1;
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ObjHits_ClearHitVolumes(obj);
            ObjHitbox_SetCapsuleBounds(obj, 8, -2, 0x19);
            ObjHits_EnableObject(obj);
            ObjHits_SyncObjectPositionIfDirty(obj);
            gunpowderbarrel_updatePhysics((int*)obj);
            gunpowderbarrel_setPlayerHeldState((int*)obj, 0);
        }
        return;
    }
    if (fn_80080150(&state->releaseTimer) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        timerCountDown(&state->releaseTimer);
        memset(&state->throwVelX, 0, 0xc);
        memset((void*)&((GameObject*)obj)->anim.velocityX, 0, 0xc);
        return;
    }
    if (((BarrelBits*)&state->heldFlags)->b5 == 0)
    {
        if (((BarrelBits*)&state->heldFlags)->b1 != 0 && playerIsDisguised(player) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
        }
    }
    if (((GameObject*)obj)->childObjs[0] == NULL)
    {
        f32 range = lbl_803E4338;
        if ((u32)(state->linkedTimerObject = ObjGroup_FindNearestObject(0x4c, obj, &range)) != 0 &&
            timer_isEffectMode(state->linkedTimerObject) != 0 &&
            *(void**)(state->linkedTimerObject + 0xc4) == NULL)
        {
            ObjLink_AttachChild(obj, state->linkedTimerObject, 0);
        }
    }
    else
    {
        if ((int)Obj_IsObjectAlive(state->linkedTimerObject) == 0 && *(void* *)&state->linkedTimerObject != NULL)
        {
            ObjLink_DetachChild(obj, state->linkedTimerObject);
            state->linkedTimerObject = 0;
        }
    }
    {
        u32 arg;
        uint msg;
        msg = 0;
        arg = 0;
        while ((int)ObjMsg_Pop((void*)obj, &msg, 0, &arg) != 0)
        {
            switch (msg)
            {
            case 0xf:
                gunpowderbarrel_setPlayerHeldState((int*)obj, 1);
                break;
            case 0x10:
                gunpowderbarrel_setPlayerHeldState((int*)obj, 0);
                if (arg != 0)
                {
                    ObjGroup_AddObject(obj, 0x16);
                }
                break;
            }
        }
    }
    if (((BarrelBits*)&state->heldFlags)->b5 != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
    }
    if (state->fuseFrames != 0)
    {
        state->fuseFrames += framesThisStep;
        state->hitRadius = state->radiusGrowthPerFrame * (f32)(u32)
        state->fuseFrames + lbl_803E42DC;
        ObjHitbox_SetCapsuleBounds(obj, (s32)state->hitRadius,
                                   (s32)(-state->hitRadius * lbl_803E4328),
                                   (s32)(state->hitRadius * lbl_803E4328));
        if (*(void* *)&state->linkedTimerObject != NULL)
        {
            timer_clearManualFlags(state->linkedTimerObject);
        }
        if (state->fuseFrames > 0x14)
        {
            int i;
            u32 gen;
            if (((BarrelBits*)&state->heldFlags)->b7 != 0)
            {
                gunpowderbarrel_setPlayerHeldState((int*)obj, 0);
            }
            gen = 0;
            if (((GunpowderbarrelPlacement*)def)->unk1A != 0)
            {
                int cnt;
                uint* objs = ObjGroup_GetObjects(0x3a, &cnt);
                uint* p;
                i = 0;
                p = objs;
                for (; i < cnt; i++)
                {
                    if (((GunpowderbarrelPlacement*)def)->unk1A == barrelgener_getLinkId(*p))
                    {
                        gen = objs[i];
                        break;
                    }
                    p++;
                }
            }
            else
            {
                gen = ObjGroup_FindNearestObject(0x3a, obj, 0);
            }
            if (gen == 0)
            {
                Obj_RemoveFromUpdateList(obj);
                ObjHits_DisableObject(obj);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                s16toFloat(&state->respawnTimer, 0x3c);
                return;
            }
            memset(&state->throwVelX, 0, 0xc);
            memset((void*)&((GameObject*)obj)->anim.velocityX, 0, 0xc);
            state->motionFlags &= ~2;
            ObjHits_RefreshObjectState(obj);
            if (((BarrelBits*)&state->configFlags)->b7 != 0)
            {
                s16toFloat(&state->respawnTimer, 0x3c);
                storeZeroToFloatParam(&state->releaseTimer);
                s16toFloat(&state->releaseTimer, 0x5a);
                barrelgener_queueObjectRelease(gen, obj, 0x46);
                ObjHits_ClearHitVolumes(obj);
                ObjHits_DisableObject(obj);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                return;
            }
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            return;
        }
        return;
    }
    if (state->heldByCarryInterface != 0)
    {
        if ((playerGetStateFlag310(player) & 0x4000) != 0)
        {
            setAButtonIcon(5);
        }
        else
        {
            setAButtonIcon(4);
        }
    }
    else
    {
        if (((BarrelBits*)&state->configFlags)->b6 != 0 && ((BarrelBits*)&state->heldFlags)->b4 != 0 &&
            (state->motionFlags & 2) == 0)
        {
            saveGame_saveObjectPos((int*)obj);
        }
    }
    if ((state->motionFlags & 2) != 0 || ((BarrelBits*)&state->heldFlags)->b5 != 0 ||
        (*(int (**)(int, GunpowderBarrelState*))((char*)*gCarryableInterface + 0x8))(obj, state) == 0 ||
        (((BarrelBits*)&state->heldFlags)->b1 != 0 && playerIsDisguised(player) == 0))
    {
        ObjHits_EnableObject(obj);
        fn_801A1230(obj);
        ((GameObject*)obj)->anim.alpha = 0xff;
        if (state->heldByCarryInterface != 0)
        {
            state->heldByCarryInterface = 0;
            if (fn_802966B4(player) != 0)
            {
                ObjHits_SyncObjectPositionIfDirty(obj);
            }
            else if (fn_8029669C(player) != 0)
            {
                ObjHits_MarkObjectPositionDirty(obj);
                gunpowderbarrel_launchAtTarget(obj, 1);
            }
            else if (lbl_803E42C0 == Player_GetLiftVelocityY((int)player))
            {
                ObjHits_SyncObjectPositionIfDirty(obj);
                gunpowderbarrel_launchAtTarget(obj, 0);
            }
            else if (state->fuseFrames == 0)
            {
                ((GameObject*)obj)->anim.velocityX = state->throwVelX =
                    mathSinf(lbl_803E433C * (f32) * (s16*)player / lbl_803E4340);
                ((GameObject*)obj)->anim.velocityY = state->throwVelY = lbl_803E42C0;
                ((GameObject*)obj)->anim.velocityZ = state->throwVelZ =
                    mathCosf(lbl_803E433C * (f32) * (s16*)player / lbl_803E4340);
                ((GameObject*)obj)->anim.localPosX =
                    lbl_803DBE80 * -mathSinf(lbl_803E433C * (f32) * (s16*)player /
                        lbl_803E4340) +
                    ((GameObject*)obj)->anim.localPosX;
                ((GameObject*)obj)->anim.localPosZ =
                    lbl_803DBE80 * -mathCosf(lbl_803E433C * (f32) * (s16*)player / lbl_803E4340) +
                    ((GameObject*)obj)->anim.localPosZ;
                ObjGroup_AddObject(obj, 0x16);
            }
            ObjGroup_AddObject(obj, 0x16);
        }
        gunpowderbarrel_updatePhysics((int*)obj);
    }
    else
    {
        state->motionFlags |= 1;
        if (state->heldByCarryInterface == 0)
        {
            if (*(void* *)&state->linkedTimerObject != NULL)
            {
                timer_forceStart(state->linkedTimerObject);
            }
            ObjGroup_RemoveObject(obj, 0x16);
        }
        state->heldByCarryInterface = 1;
        ((BarrelBits*)&state->heldFlags)->b6 = 1;
        state->launchYaw = *(s16*)player;
        fn_801A1230(obj);
    }
    if (((BarrelBits*)&state->heldFlags)->b5 != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        if (((BarrelBits*)&state->heldFlags)->b6 != 0 && ((BarrelBits*)&state->heldFlags)->b7 != 0)
        {
            state->throwVelX = ((GameObject*)obj)->anim.velocityX;
            state->throwVelY = ((GameObject*)obj)->anim.velocityY;
            state->throwVelZ = ((GameObject*)obj)->anim.velocityZ;
            state->throwVelY = lbl_803E42C0;
            ((BarrelBits*)&state->heldFlags)->b6 = 0;
        }
    }
    if (*(void* *)&state->linkedTimerObject != NULL)
    {
        if (timer_hasExpired(state->linkedTimerObject) != 0)
        {
            state->unk16 = 0xa;
        }
    }
}

/* Head of the TU (0x801A0B14..0x801A1230) - formerly the
 * gunpowder-barrel helper group inside sandwormBoss.c. Placed LAST in
 * this file so none of the small helpers can be auto-inlined into the
 * update/hitDetect callers above (they were extern bls before the
 * re-split, and the retail unit keeps the bls). */

u32 gunpowderbarrel_isHeld(int* obj) { return (((GunpowderBarrelState*)((int**)obj)[0xb8 / 4])->heldFlags >> 5) & 1; }

typedef struct
{
    u8 playerHeld : 1;
    u8 _pad0 : 1;
    u8 held : 1;
    u8 _pad1 : 5;
} GpbHeldByte;

/* EN v1.0 0x801A0BDC  size: 56b  gunpowderbarrel_setHeldState: flag the
 * barrel as held, mark obj active, and clear its physics-sleep bit. */
void gunpowderbarrel_setHeldState(int* obj)
{
    GunpowderBarrelState* sub = ((GameObject*)obj)->extra;
    ((GpbHeldByte*)&sub->heldFlags)->held = 1;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
    sub->motionFlags = (u8)(sub->motionFlags & ~2);
}

/* EN v1.0 0x801A0B90  size: 76b  gunpowderbarrel_clearHeldState: zero the
 * barrel's velocity/throw vectors, mark it sleeping, clear obj-active and
 * the held flag. */
void gunpowderbarrel_clearHeldState(int* obj)
{
    GunpowderBarrelState* sub = ((GameObject*)obj)->extra;
    f32 z = lbl_803E42C0;
    sub->throwVelY = z;
    sub->throwVelX = z;
    sub->throwVelZ = z;
    sub->motionFlags = (u8)(sub->motionFlags | 1);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~8);
    sub->unk38 = z;
    ((GpbHeldByte*)&sub->heldFlags)->held = 0;
}

/* EN v1.0 0x801A0E04  size: 244b  gunpowderbarrel_setPlayerHeldState: when
 * grabbed by the player, copy the held-pose and enable hit reactions; when
 * released, restore the default pose and clear them. */
void gunpowderbarrel_setPlayerHeldState(int* obj, u8 heldByPlayer)
{
    GunpowderBarrelState* sub;
    int o = (int)obj;
    u8* h;
    sub = ((GameObject*)o)->extra;
    h = *(u8**)&((GameObject*)o)->anim.hitReactState;
    if (heldByPlayer != 0)
    {
        h[0x6a] = 1;
        h[0x6b] = 1;
        *(u8*)&((GameObject*)o)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)o)->anim.resetHitboxMode | 8);
        ((GpbHeldByte*)&sub->heldFlags)->playerHeld = 1;
        sub->motionFlags = (u8)(sub->motionFlags & ~2);
        ObjHits_SetFlags(o, 0x480);
        ObjHits_ClearSourceMask(o, 1);
        ObjHits_EnableObject(o);
        ObjHits_SyncObjectPositionIfDirty(o);
    }
    else
    {
        h[0x6a] = (*(u8**)&((GameObject*)o)->anim.modelInstance)[0x63];
        h[0x6b] = (*(u8**)&((GameObject*)o)->anim.modelInstance)[0x64];
        ((GpbHeldByte*)&sub->heldFlags)->playerHeld = 0;
        *(u8*)&((GameObject*)o)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)o)->anim.resetHitboxMode & ~8);
        ObjHits_ClearFlags(o, 0x400);
        sub->motionFlags = (u8)(sub->motionFlags | 1);
    }
}

void gunpowderbarrel_setScale(int* obj, f32* params)
{
    int* state = ((GameObject*)obj)->extra;
    if (((GunpowderBarrelState*)state)->heldByCarryInterface != 0) return;
    if (((GunpowderBarrelState*)state)->fuseFrames != 0) return;
    ((GunpowderBarrelState*)state)->throwVelY = ((GunpowderBarrelState*)state)->throwVelY + params[1];
    ((GunpowderBarrelState*)state)->throwVelX = ((GunpowderBarrelState*)state)->throwVelX + params[0];
    ((GunpowderBarrelState*)state)->throwVelZ = ((GunpowderBarrelState*)state)->throwVelZ + params[2];
    ((GunpowderBarrelState*)state)->motionFlags = (u8)(((GunpowderBarrelState*)state)->motionFlags | 1);
}

int gunpowderbarrel_canBeGrabbed(int* obj)
{
    GunpowderBarrelState* state = ((GameObject*)obj)->extra;
    int result = 0;
    if (state->heldByCarryInterface == 0 &&
        state->respawnTimer == lbl_803E42C0 &&
        ((int(*)(GunpowderBarrelState*))(*(*(void****)&gCarryableInterface))[5])(state) == 0)
    {
        result = 1;
    }
    return result;
}

typedef struct GunpowderbarrelLaunchAtTargetPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
} GunpowderbarrelLaunchAtTargetPlacement;

/* gunpowderbarrel_launchAtTarget: gunpowder-barrel "throw at target" launch. Seeds state's
 * launch velocity (state+0x20..28) from a per-axis pair scaled by the
 * player's strength (player_state[0x298]), or a fixed pair when the flag
 * is clear. Builds a rotation-vec from state[0x50], runs the 3-vec rotor
 * via vecRotateZXY, sets thrown/inflight flags, plays sfx 0xd3. When
 * state[0x48] bit 0x40 is set, looks up the linked barrel by data[0x1a]
 * (or the nearest one if 0), temporarily moves obj to that barrel's
 * position so saveGame_saveObjectPos latches the target slot, then
 * restores. */
void gunpowderbarrel_launchAtTarget(int obj, u8 flag)
{
    GunpowderBarrelState* state = ((GameObject*)obj)->extra;
    u8* playerState;
    s16 stk[8];
    f32 fz;
    int target;
    f32 sx, sy, sz;

    playerState = *(u8**)((u8*)Obj_GetPlayerObject() + 0xb8);
    state->throwVelX = lbl_803E42C0;
    if (flag != 0)
    {
        state->throwVelY = lbl_803E42C8 * *(f32*)(playerState + 0x298) + lbl_803E42C4;
        state->throwVelZ = lbl_803E42D0 * *(f32*)(playerState + 0x298) + lbl_803E42CC;
    }
    else
    {
        state->throwVelY = lbl_803E42D4;
        state->throwVelZ = lbl_803E42D8;
    }
    fz = lbl_803E42C0;
    *(f32*)((u8*)stk + 0xc) = fz;
    *(f32*)((u8*)stk + 0x10) = fz;
    *(f32*)((u8*)stk + 0x14) = fz;
    *(f32*)((u8*)stk + 0x8) = lbl_803E42DC;
    stk[2] = 0;
    stk[1] = 0;
    stk[0] = state->launchYaw;
    vecRotateZXY(stk, &state->throwVelX);
    state->motionFlags = (u8)(state->motionFlags | 1);
    Sfx_PlayFromObject((u32)obj, SFXsk_baptr6_c);
    state->motionFlags = (u8)(state->motionFlags | 2);
    if (((BarrelBits*)&state->configFlags)->b6 != 0)
    {
        u8* params = *(u8**)&((GameObject*)obj)->anim.placementData;
        target = 0;
        if (*(s16*)(params + 0x1a) != 0)
        {
            int count;
            uint* barrels = ObjGroup_GetObjects(0x3a, &count);
            int i;
            uint* p = barrels;
            for (i = 0; i < count; i++)
            {
                if (((GunpowderbarrelLaunchAtTargetPlacement*)params)->unk1A == barrelgener_getLinkId(*p))
                {
                    target = barrels[i];
                    break;
                }
                p++;
            }
        }
        else
        {
            target = ObjGroup_FindNearestObject(0x3a, obj, (f32*)0);
        }
        if ((void*)target != NULL)
        {
            sx = ((GameObject*)obj)->anim.localPosX;
            sy = ((GameObject*)obj)->anim.localPosY;
            sz = ((GameObject*)obj)->anim.localPosZ;
            ((GameObject*)obj)->anim.localPosX = ((GameObject*)target)->anim.localPosX;
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)target)->anim.localPosY;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)target)->anim.localPosZ;
            saveGame_saveObjectPos((int*)obj);
            ((GameObject*)obj)->anim.localPosX = sx;
            ((GameObject*)obj)->anim.localPosY = sy;
            ((GameObject*)obj)->anim.localPosZ = sz;
        }
    }
}

/* EN v1.0 0x801A0F58  size: 728b  fn_801A0F58: home the object on the nearest
 * group-0x1e object above it, scaling velocity and the two heading words by
 * approach rate; on a steep approach play the dive cue and bump the target's
 * cycle phase. */
void fn_801A0F58(int* obj, s16 a, s16 b)
{
    f32 dx;
    f32 dz;
    f32 dy2;
    f32 scale;
    f32 rate;
    f32 dy;
    int v;
    int w;
    char* player;
    char* near;
    f32 radius = lbl_803E42E0;
    player = (char*)Obj_GetPlayerObject();
    near = (char*)ObjGroup_FindNearestObject(0x1e, (u32)obj, &radius);
    if (near == NULL)
    {
        return;
    }
    dy = *(f32*)(near + 0x10) - *(f32*)(player + 0x10);
    dy = (dy >= 0.0f) ? dy : -dy;
    if (dy < lbl_803E42E4)
    {
        return;
    }
    dx = *(f32*)(near + 0xc) - ((GameObject*)obj)->anim.localPosX;
    dy2 = *(f32*)(near + 0x10) - ((GameObject*)obj)->anim.localPosY;
    scale = 0.0f;
    if (dy2 > scale)
    {
        return;
    }
    dz = *(f32*)(near + 0x14) - ((GameObject*)obj)->anim.localPosZ;
    rate = (dy2 != scale) ? ((GameObject*)obj)->anim.velocityY / dy2 : scale;
    if (rate >= lbl_803E42DC)
    {
        Sfx_PlayFromObject((u32)obj, 0xd2);
        rate = lbl_803E42DC;
        ((GameObject*)obj)->anim.velocityY = dy2;
        *(f32*)(near + 0xc) += lbl_803E42E8;
        *(f32*)(near + 0x2c) += lbl_803E42E8;
        if (*(f32*)(near + 0x2c) > lbl_803E42EC)
        {
            *(f32*)(near + 0xc) -= *(f32*)(near + 0x2c);
            *(f32*)(near + 0x2c) = 0.0f;
        }
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotZ = 0;
        a = 0;
        b = 0;
    }
    ((GameObject*)obj)->anim.velocityX = dx * rate;
    ((GameObject*)obj)->anim.velocityZ = dz * rate;
    v = a;
    if (v != 0)
    {
        f32 t;
        if (v == 1)
        {
            t = (lbl_803E42F0 - (f32)(u16)((GameObject*)obj)->anim.rotY) * rate;
        }
        else
        {
            t = (f32)(u16)((GameObject*)obj)->anim.rotY * (rate * (f32)v);
        }
        ((GameObject*)obj)->anim.rotY = (f32)((GameObject*)obj)->anim.rotY + t;
    }
    w = b;
    if (w != 0)
    {
        f32 t;
        if (w == 1)
        {
            t = 0.0f;
        }
        else
        {
            t = (f32)(u16)((GameObject*)obj)->anim.rotZ * (rate * (f32)w);
        }
        ((GameObject*)obj)->anim.rotZ = (f32)((GameObject*)obj)->anim.rotZ + t;
    }
}
