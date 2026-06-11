#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/mapEvent.h"
#include "main/dll/IM/IMicicle.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"

typedef struct CfmagicwallPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} CfmagicwallPlacement;


typedef struct CfforcefieldPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} CfforcefieldPlacement;


typedef struct CflevelcontrolState
{
    u8 pad0[0x8 - 0x0];
    s32 unk8;
    u8 padC[0xD - 0xC];
    s8 unkD;
    u8 padE[0x10 - 0xE];
} CflevelcontrolState;


typedef struct SlidingdoorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} SlidingdoorPlacement;


extern undefined8 FUN_80017698();
extern u32 randomGetRange(int min, int max);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern undefined4 SH_LevelControl_runBloopEvent();
extern uint countLeadingZeros();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern MapEventInterface** gMapEventInterface;
extern f64 DOUBLE_803e5020;
extern f64 DOUBLE_803e5048;
extern f64 DOUBLE_803e5060;
extern f64 DOUBLE_803e5078;
extern f64 DOUBLE_803e5090;
extern f64 DOUBLE_803e50a8;
extern f32 lbl_803DC074;
extern f32 lbl_803DCAF8;
extern f32 lbl_803E4FF4;
extern f32 lbl_803E5028;
extern f32 lbl_803E502C;
extern f32 lbl_803E5030;
extern f32 lbl_803E5034;
extern f32 lbl_803E5038;
extern f32 lbl_803E5040;
extern f32 lbl_803E5050;
extern f32 lbl_803E5058;
extern f32 lbl_803E5074;
extern f32 lbl_803E5080;
extern f32 lbl_803E5084;
extern f32 lbl_803E5088;
extern f32 lbl_803E508C;
extern f32 lbl_803E5098;
extern f32 lbl_803E509C;
extern f32 lbl_803E50A0;
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void Obj_BuildWorldTransformMatrix(void* obj, f32* mtx, int flags);
extern void PSMTXMultVecSR(f32 * mtx, f32 * src, f32 * dst);
extern f32 mathCosf(f32 angle);
extern f32 mathSinf(f32 angle);
extern int fn_80080150(void* timer);
extern void s16toFloat(void* p, int duration);
extern int timerCountDown(void* timer);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern EffectInterface** gPartfxInterface;
extern f32 timeDelta;
extern f32 lbl_803DBE90;
extern int lbl_803DBE94;
extern int lbl_803DBE98;
extern int lbl_80322ED8[];
extern f32 lbl_803E4390;
extern f32 lbl_803E4394;
extern f32 lbl_803E4398;
extern f32 lbl_803E439C;
extern f32 lbl_803E43A0;
extern f32 lbl_803E43A4;
extern f32 lbl_803E43A8;
extern f32 lbl_803E43AC;

/*
 * --INFO--
 *
 * Function: cfforcefield_update
 * EN v1.0 Address: 0x801A39D0
 * EN v1.0 Size: 1128b
 * EN v1.1 Address: 0x801A3B20
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cfforcefield_update(u8* obj)
{
    typedef struct ForceFieldEmitter
    {
        int effectId;
        int pad04;
        int angleStep;
        int pad0c;
        int pad10;
        f32 waveScale;
    } ForceFieldEmitter;
    typedef struct ForceFieldFlags
    {
        u8 disabled : 1;
        u8 rest : 7;
    } ForceFieldFlags;
    f32* wavePtr;
    int* stepPtr;
    ForceFieldEmitter* emitter;
    int angle;
    u8* data;
    u8* state;
    int style;
    f32 val;
    int isZero;
    f32 kA4;
    f32 kA8;
    f32 kAC;
    f32 kA0;
    f32 strength;
    f32 kZero;
    f32 z;
    f32 mtx[3][4];
    f32 world[6];
    f32 local[3];

    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    z = lbl_803E4390;
    ((GameObject*)obj)->anim.velocityZ = z;
    ((GameObject*)obj)->anim.velocityY = z;
    ((GameObject*)obj)->anim.velocityX = z;

    if (GameBit_Get(((CfforcefieldPlacement*)data)->unk1E) != 0)
    {
        if (!((ForceFieldFlags*)state)->disabled)
        {
            style = (s8)data[0x19] % 3;
            val = *(f32*)(state + 4);
            isZero = (val != lbl_803E4390);
            isZero = !isZero;
            if (isZero)
            {
                strength = lbl_803E4394;
            }
            else
            {
                strength = lbl_803E4398 * val;
            }

            {
                Obj_BuildWorldTransformMatrix(obj, (f32*)mtx, 0);
                ((GameObject*)obj)->anim.rotZ = (s16)(
                    lbl_803E439C * timeDelta + (f32)(s32)((GameObject*)obj)->anim.rotZ);

                angle = -0x7fff;
                emitter = (ForceFieldEmitter*)((u8*)lbl_80322ED8 + style * 0x18);
                wavePtr = &emitter->waveScale;
                stepPtr = &emitter->angleStep;
                kA4 = lbl_803E43A4;
                kA8 = lbl_803E43A8;
                kAC = lbl_803E43AC;
                kA0 = lbl_803E43A0;
                kZero = lbl_803E4390;
                for (; angle < 0x7fff; angle += *stepPtr)
                {
                    local[0] = (f32)(int)
                    randomGetRange(-lbl_803DBE94, lbl_803DBE94) +
                        kA0 * (strength * lbl_803DBE90) *
                        mathCosf(kA4 * (f32)(angle + (s32)(kA8 * *wavePtr)) / kAC);
                    local[1] = (f32)(int)
                    randomGetRange(-lbl_803DBE94, lbl_803DBE94) +
                        kA0 * (strength * lbl_803DBE90) *
                        mathSinf(kA4 * (f32)(angle + (s32)(kA8 * *wavePtr)) / kAC);
                    local[2] = kZero;
                    PSMTXMultVecSR((f32*)mtx, local, local);
                    world[3] = local[0] + ((GameObject*)obj)->anim.localPosX;
                    world[4] = local[1] + ((GameObject*)obj)->anim.localPosY;
                    world[5] = local[2] + ((GameObject*)obj)->anim.localPosZ;
                    (*gPartfxInterface)->spawnObject(obj, emitter->effectId, world, 0x200001, -1, obj + 0x24);
                    (*gPartfxInterface)->spawnObject(obj, emitter->effectId, world, 0x200001, -1, obj + 0x24);
                    (*gPartfxInterface)->spawnObject(obj, emitter->effectId, world, 0x200001, -1, obj + 0x24);
                }
            }

            if (fn_80080150(state + 4) != 0)
            {
                ((GameObject*)obj)->anim.rotY = (s16)(
                    (f32)(s32)lbl_803DBE98 * timeDelta + (f32)(s32)((GameObject*)obj)->anim.rotY);
                if (timerCountDown(state + 4) != 0)
                {
                    ((ForceFieldFlags*)state)->disabled = 1;
                    ((GameObject*)obj)->anim.rotY = 0;
                }
            }
            else if (GameBit_Get(((CfforcefieldPlacement*)data)->unk20) != 0)
            {
                s16toFloat(state + 4, 0x3c);
                Sfx_PlayFromObject((int)obj, 0x366);
                if (*(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) != 0x47f5e)
                {
                    Sfx_PlayFromObject((int)obj, 0x409);
                }
            }
        }
        else
        {
            ((ForceFieldFlags*)state)->disabled = (u8)GameBit_Get(((CfforcefieldPlacement*)data)->unk20);
        }
    }
}


/*
 * --INFO--
 *
 * Function: FUN_801a4520
 * EN v1.0 Address: 0x801A4520
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x801A4660
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a4520(int param_1)
{
    int iVar1;

    if (((GameObject*)param_1)->unkF4 == 0)
    {
        iVar1 = *(int*)&((GameObject*)param_1)->anim.placementData;
        if ((*(short*)(iVar1 + 0x1c) != 0) && (**(byte**)&((GameObject*)param_1)->extra >> 5 != 0))
        {
            (*gObjectTriggerInterface)->preempt(param_1, *(s16*)(iVar1 + 0x1c));
        }
        iVar1 = (int)*(char*)(iVar1 + 0x1e);
        if (iVar1 != -1)
        {
            (*gObjectTriggerInterface)->runSequence(iVar1, (void*)param_1, -1);
        }
        ((GameObject*)param_1)->unkF4 = 1;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a45cc
 * EN v1.0 Address: 0x801A45CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A4708
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a45cc(short* param_1, int param_2)
{
}


/*
 * --INFO--
 *
 * Function: cflevelcontrol_free
 * EN v1.0 Address: 0x801A45D4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801A4880
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cflevelcontrol_free(int param_1)
{
}


/*
 * --INFO--
 *
 * Function: FUN_801a4810
 * EN v1.0 Address: 0x801A4810
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801A4AD8
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801a4810(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             undefined4 param_9, undefined4 param_10, int param_11)
{
    undefined4 uVar1;
    int iVar2;
    undefined8 uVar3;

    for (iVar2 = 0; iVar2 < (int)(uint) * (byte*)(param_11 + 0x8b); iVar2 = iVar2 + 1)
    {
        if (*(char*)(param_11 + iVar2 + 0x81) == '\x01')
        {
            FUN_80017698(0xdcb, 1);
            uVar3 = FUN_80017698(0x4a3, 0);
            FUN_80041ff8(uVar3, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x2b);
            FUN_80042b9c(0, 0, 1);
            uVar1 = FUN_80044404(0x2b);
            FUN_80042bec(uVar1, 0);
        }
    }
    return 0;
}


/* Trivial 4b 0-arg blr leaves. */
void cfforcefield_release(void)
{
}

void cfforcefield_initialise(void)
{
}

void slidingdoor_free(void)
{
}

void slidingdoor_hitDetect(void)
{
}

void slidingdoor_release(void)
{
}

void slidingdoor_initialise(void)
{
}

void attractor_hitDetect(void)
{
}

void attractor_update(void)
{
}

void attractor_release(void)
{
}

void attractor_initialise(void)
{
}

void cfmagicwall_free(void)
{
}

void cfmagicwall_hitDetect(void)
{
}

void cfmagicwall_release(void)
{
}

void cfmagicwall_initialise(void)
{
}

void cflevelcontrol_hitDetect(void)
{
}

void cflevelcontrol_release(void)
{
}

void cflevelcontrol_initialise(void)
{
}

extern void storeZeroToFloatParam(void* p);
extern void objSetSlot(void* obj, int resourceId);
extern s16 lbl_80323008[];

void cflevelcontrol_init(u8* obj, u8* params)
{
    typedef struct LevelControlFlags
    {
        u8 b7 : 1;
        u8 b6 : 1;
        u8 b5 : 1;
        u8 b4 : 1;
        u8 b3 : 1;
        u8 rest : 3;
    } LevelControlFlags;
    u8* sub;
    int i;

    sub = ((GameObject*)obj)->extra;
    ((CflevelcontrolState*)sub)->unk8 = 0;
    ((CflevelcontrolState*)sub)->unkD = -1;
    storeZeroToFloatParam(sub);
    s16toFloat(sub, 0x1e0);
    ((LevelControlFlags*)(sub + 0xc))->b6 = 0;
    ((GameObject*)obj)->animEventCallback = (void*)CFLevelControl_SeqFn;
    GameBit_Set(0x983, *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) != 0x2cef);
    if (GameBit_Get(0x2fe) == 0)
    {
        for (i = 0; i < 0x17; i++)
        {
            GameBit_Set(lbl_80323008[i], 0);
        }
    }
    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 4, 0);
    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 0x11, 0);
    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 0x15, 0);
    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 0x16, 0);
    ((LevelControlFlags*)(sub + 0xc))->b5 = (u8)GameBit_Get(0x974);
    ((LevelControlFlags*)(sub + 0xc))->b4 = (u8)GameBit_Get(0x975);
    objSetSlot(obj, 0x51);
    ((LevelControlFlags*)(sub + 0xc))->b3 = 1;
}

void exploded_free(void)
{
}

void exploded_hitDetect(void)
{
}

void exploded_release(void)
{
}

void exploded_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int slidingdoor_getExtraSize(void) { return 0x1; }
int slidingdoor_getObjectTypeId(void) { return 0x0; }
int attractor_getExtraSize(void) { return 0x0; }
int attractor_getObjectTypeId(void) { return 0x0; }
int cfmagicwall_getExtraSize(void) { return 0x0; }
int cfmagicwall_getObjectTypeId(void) { return 0x0; }
int cflevelcontrol_getExtraSize(void) { return 0x10; }
int cflevelcontrol_getObjectTypeId(void) { return 0x0; }
int exploded_getExtraSize(void) { return 0x6c; }

/* Pattern wrappers. */
u8 exploded_setScale(int* obj) { return ((ExplodedObjectState*)((int**)obj)[0xb8 / 4])->explodePhase; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E43BC;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E43D0;
extern f32 lbl_803E43D8;
extern f32 lbl_803E43DC;
extern void* Obj_GetPlayerObject(void);
extern f32 Vec_distance(void* a, void* b);
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern f32 lbl_803E43E8;
extern f32 lbl_803E43F4;

void slidingdoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E43BC);
}

void attractor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E43D0);
}

void cfmagicwall_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E43D8);
}

void cflevelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E43E8);
}

void exploded_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E43F4);
}

void cfmagicwall_update(int obj)
{
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int player = (int)Obj_GetPlayerObject();
    int alpha = 0xff;

    if (GameBit_Get(((CfmagicwallPlacement*)data)->unk20) != 0)
    {
        int yaw = (s16)Obj_GetYawDeltaToObject(obj, player, NULL);

        if (yaw < 0)
        {
            yaw = -yaw;
        }

        if (yaw > 0x4000)
        {
            ((GameObject*)obj)->anim.alpha = 0;
            return;
        }

        {
            f32 playerDistance;
            f32 range;
            f32 fadeDistance;
            range = (f32)(s32)((CfmagicwallPlacement*)data)->unk1A;
            playerDistance = Vec_distance((void*)&((GameObject*)obj)->anim.worldPosX, (void*)(player + 0x18));
            fadeDistance = Camera_DistanceToCurrentViewPosition(
                ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ);

            if (fadeDistance < playerDistance)
            {
                fadeDistance = Camera_DistanceToCurrentViewPosition(
                    ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ);
            }
            else
            {
                fadeDistance = playerDistance;
            }

            if (fadeDistance < range)
            {
                alpha = (s32)(lbl_803E43DC * (fadeDistance / range));
            }

            ((GameObject*)obj)->anim.alpha = alpha;
        }
    }
}

extern int ObjList_FindObjectById(int objectId);
extern void fn_8017C294(int obj);
extern void getEnvfxActImmediately(void* obj, void* target, int animId, int flags);
extern void skyFn_80088e54(int mode, f32 brightness);
extern void unlockLevel(int a, int b, int c);
extern int playerIsDisguised(int player);
extern void fn_80295CF4(int player, int mode);
extern int getCurMapLayer(void);
extern int lbl_802C22E8[];
extern f32 lbl_803E43EC;
extern void SCGameBitLatch_Update(void* latch, int mask, int clearIfSetBit, int clearIfClearBit,
                                  int latchBit, int musicId);
extern void SCGameBitLatch_UpdateInverted(void* latch, int mask, int clearIfSetBit,
                                          int clearIfClearBit, int latchBit, int musicId);

void cflevelcontrol_update(int obj)
{
    u8* state = ((GameObject*)obj)->extra;
    int player = (int)Obj_GetPlayerObject();
    int triggerPos[3];
    u32 bit974;
    u32 bit975;
    u32 old974;
    u32 bit94e;
    int cameraMode;

    triggerPos[0] = lbl_802C22E8[0];
    triggerPos[1] = lbl_802C22E8[1];
    triggerPos[2] = lbl_802C22E8[2];

    if (((u32)state[0xc] >> 3 & 1) != 0)
    {
        fn_8017C294(ObjList_FindObjectById(0x47fae));
        fn_8017C294(ObjList_FindObjectById(0x47f83));
        fn_8017C294(ObjList_FindObjectById(0x47f8f));
        fn_8017C294(ObjList_FindObjectById(0x47fa2));
        fn_8017C294(ObjList_FindObjectById(0x29f2));
        fn_8017C294(ObjList_FindObjectById(0x29f3));
        fn_8017C294(ObjList_FindObjectById(0x29ef));
        fn_8017C294(ObjList_FindObjectById(0x29ee));
        state[0xc] = (u8)(state[0xc] & ~0x08);
    }

    if ((*gMapEventInterface)->getMode(0x1d) == 1 &&
        GameBit_Get(0x40) != 0)
    {
        (*gMapEventInterface)->setMode(0x1d, 2);
    }

    bit974 = (u8)GameBit_Get(0x974);
    bit975 = (u8)GameBit_Get(0x975);
    old974 = ((u32)state[0xc] >> 5) & 1;

    if (old974 == 0 || (((u32)state[0xc] >> 4) & 1) == 0)
    {
        if (old974 == 0 && (((u32)state[0xc] >> 4) & 1) == 0)
        {
            if (bit974 != 0 || bit975 != 0)
            {
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            }
        }
        else if (bit974 != 0 && bit975 != 0)
        {
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
        }
    }

    state[0xc] = (u8)((state[0xc] & ~0x20) | ((bit974 & 1) << 5));
    state[0xc] = (u8)((state[0xc] & ~0x10) | ((bit975 & 1) << 4));

    if (((GameObject*)obj)->unkF4 == 0)
    {
        getEnvfxActImmediately((void*)obj, (void*)obj, 0x56, 0);
        if (GameBit_Get(0xd73) == 0)
        {
            getEnvfxActImmediately((void*)obj, (void*)obj, 0xd, 0);
            getEnvfxActImmediately((void*)obj, (void*)obj, 0x11, 0);
            getEnvfxActImmediately((void*)obj, (void*)obj, 0xe, 0);
            skyFn_80088e54(0, lbl_803E43EC);
            GameBit_Set(0xd73, 1);
        }

        if (GameBit_Get(0xdca) != 0)
        {
            getEnvfxActImmediately((void*)obj, (void*)obj, 0xd, 0);
            getEnvfxActImmediately((void*)obj, (void*)obj, 0x7e, 0);
            getEnvfxActImmediately((void*)obj, (void*)obj, 0x7d, 0);
            skyFn_80088e54(1, lbl_803E43EC);
            GameBit_Set(0xdca, 0);
            unlockLevel(0, 0, 1);
        }

        ((GameObject*)obj)->unkF4 = 1;
    }

    if (GameBit_Get(0x94f) != 0 && (((GameObject*)player)->objectFlags & 0x1000) == 0)
    {
        GameBit_Set(0x94e, 0);
    }

    bit94e = GameBit_Get(0x94e);
    if (bit94e != 0)
    {
        if (playerIsDisguised(player) == 0)
        {
            fn_80295CF4((int)Obj_GetPlayerObject(), 0);
        }
    }
    else if (playerIsDisguised(player) == 0)
    {
        fn_80295CF4((int)Obj_GetPlayerObject(), 1);
    }

    if (GameBit_Get(0xd3d) != 0)
    {
        ((void (*)(int*, int, int, int))(*(int*)((u8*)*gMapEventInterface + 0x24)))(
            triggerPos, 0, getCurMapLayer(), 1);
        GameBit_Set(0xd3d, 0);
        getEnvfxActImmediately((void*)obj, (void*)obj, 0xd, 0);
        getEnvfxActImmediately((void*)obj, (void*)obj, 0x11, 0);
        skyFn_80088e54(1, lbl_803E43E8);
    }

    cameraMode = (*gCameraInterface)->getMode();
    if (cameraMode == 0x47)
    {
        if ((s8)state[0xd] != 0x47)
        {
            GameBit_Set(0xc0, 1);
        }
    }
    else if ((s8)state[0xd] == 0x47)
    {
        GameBit_Set(0x1a8, 1);
    }
    state[0xd] = (s8)(*gCameraInterface)->getMode();

    SCGameBitLatch_Update(state + 8, 4, -1, -1, 0x983, 0xb0);
    SCGameBitLatch_Update(state + 8, 8, -1, -1, 0x983, 0x38);
    SCGameBitLatch_UpdateInverted(state + 8, 0x100, -1, -1, 0x983, 0x16);
    SCGameBitLatch_UpdateInverted(state + 8, 0x80, -1, -1, 0x983, 0x39);

    if (GameBit_Get(0x983) == 0)
    {
        if (GameBit_Get(0xe23) == 0)
        {
            SCGameBitLatch_UpdateInverted(state + 8, 0x200, -1, -1, 0x984, 0xad);
            SCGameBitLatch_Update(state + 8, 0x40, -1, -1, 0x984, 0x16);
        }
        if (GameBit_Get(0x984) != 0)
        {
            SCGameBitLatch_Update(state + 8, 0x20, -1, -1, 0xe23, 0x17);
            SCGameBitLatch_UpdateInverted(state + 8, 0x400, -1, -1, 0xe23, 0x16);
        }
    }

    SCGameBitLatch_Update(state + 8, 1, 0x1a8, 0xc0, 0xdb8, 0xae);
    SCGameBitLatch_Update(state + 8, 0x10, -1, -1, 0xe1d, 0x36);
    SCGameBitLatch_Update(state + 8, 0x1000, -1, -1, 0xe1d, 0xf1);
    SCGameBitLatch_Update(state + 8, 2, -1, -1, 0xb46, 0xaf);
    SCGameBitLatch_Update(state + 8, 0x800, -1, -1, 0xcbb, 0xc4);
}

/* ObjGroup_RemoveObject(x, N) wrappers. */
void attractor_free(int x) { ObjGroup_RemoveObject(x, 0x1e); }

/* state encode: ((obj->_X)->_Y << shift) | const. */
u32 exploded_getObjectTypeId(ExplodedObject* obj) { return (obj->mapData->objectTypeTag << 11) | 0x400; }

/* byte-to-short shift8 pattern. */
void cfmagicwall_init(s16* dst, void* src)
{
    s8 v = *((s8*)src + 0x18);
    s16 t = v << 8;
    *dst = t;
}

/* attractor_setScale: branch on s8 flag at +0x19 of obj->_4C; if set return s16 at +0x1a, else 0. */
int attractor_setScale(int* obj)
{
    int* p = (int*)((int**)obj)[0x4c / 4];
    if ((s8) * ((u8*)p + 0x19) != 0)
    {
        return *(s16*)((char*)p + 0x1a);
    }
    return 0;
}

/* attractor_init: ObjGroup_AddObject(obj, 0x1e); byte<<8 -> sth at obj. */
void attractor_init(s16* obj, void* data)
{
    ObjGroup_AddObject(obj, 0x1e);
    {
        s8 v = *((s8*)data + 0x18);
        s16 t = v << 8;
        *obj = t;
    }
}

extern u8 framesThisStep;

void exploded_update(int* obj)
{
    ExplodedObject* o = (ExplodedObject*)obj;
    ExplodedObjectState* state = o->state;
    u8 stateVal = state->explodePhase;
    int flag;
    switch (stateVal)
    {
    case 0:
        break;
    case 1:
        if (exploded_stepDebrisPhysics(o, state) != 0)
        {
            state->explodePhase = 0;
        }
        break;
    case 2:
        break;
    }
    if (state->durationFrames != -1)
    {
        s32 elapsedFrames = state->elapsedFrames + framesThisStep;
        s32 durationFrames;
        state->elapsedFrames = elapsedFrames;
        durationFrames = state->durationFrames;
        if (elapsedFrames >= durationFrames)
        {
            state->durationFrames = -1;
            o->alpha = 0;
            o->flags06 = (s16)(o->flags06 | 0x4000);
            flag = 1;
        }
        else
        {
            s32 remainingFrames = durationFrames - state->elapsedFrames;
            if (remainingFrames < 0xff)
            {
                o->alpha = (u8)remainingFrames;
            }
            flag = 0;
        }
        if (flag != 0)
        {
            state->explodePhase = 2;
        }
    }
}

extern f32 lbl_803E43B8;
extern f32 lbl_803E43C0;
extern f32 lbl_803E4428;
extern void* getTrickyObject(void);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern int atan2i(int y, int x);

/* slidingdoor_SeqFn: slidingdoor "think" routine. Tracks whether the player or
 * tricky is within lbl_803E43B8 xz-distance and steps a 3-bit state field
 * (state[0] bits 5..7) through the door's open/close machine. Returns 1
 * while in the static states (0/1) and 0 while in transition (2/3). */
int slidingdoor_SeqFn(u8* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    typedef struct DoorFlags
    {
        u8 mode : 3;
        u8 rest : 5;
    } DoorFlags;
    register int playerNear;
    register int trickyNear;
    register u8* state;
    u8* params;
    u32 mode;
    int result;
    void* player;
    void* tricky;

    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();

    if (player != NULL)
    {
        playerNear = Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            lbl_803E43B8;
    }
    else
    {
        playerNear = 0;
    }

    if (tricky != NULL)
    {
        trickyNear = Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)((u8*)tricky + 0x18)) < lbl_803E43B8;
    }
    else
    {
        trickyNear = 0;
    }

    state = ((GameObject*)obj)->extra;
    params = *(u8**)&((GameObject*)obj)->anim.placementData;
    mode = ((u32)state[0] >> 5) & 7;

    if (mode == 0)
    {
        if (GameBit_Get(((SlidingdoorPlacement*)params)->unk18) != 0 &&
            (((SlidingdoorPlacement*)params)->unk22 == -1 ||
                GameBit_Get(((SlidingdoorPlacement*)params)->unk22) != 0))
        {
            GameBit_Set(((SlidingdoorPlacement*)params)->unk1A, 1);
            if (playerNear != 0 || trickyNear != 0)
            {
                ((DoorFlags*)state)->mode = 2;
            }
        }
    }
    else if (mode == 1)
    {
        if ((GameBit_Get(((SlidingdoorPlacement*)params)->unk18) != 0 ||
                (((SlidingdoorPlacement*)params)->unk22 != -1 &&
                    GameBit_Get(((SlidingdoorPlacement*)params)->unk22) != 0)) &&
            playerNear == 0 && trickyNear == 0)
        {
            ((DoorFlags*)state)->mode = 3;
        }
    }

    {
        register DoorFlags* fl = (DoorFlags*)state;
        if (fl->mode == 2)
        {
            if (animUpdate->triggerCommand == 2)
            {
                fl->mode = 1;
            }
        }
        else if (fl->mode == 3)
        {
            if (animUpdate->triggerCommand == 1)
            {
                fl->mode = 0;
            }
        }
    }

    result = 0;
    {
        u32 m3 = ((u32)state[0] >> 5) & 7;
        if (m3 != 2)
        {
            if (m3 != 3) result = 1;
        }
    }
    return result;
}

/* slidingdoor_update: triggered-once handler. If obj->_f4 is already set,
 * skip. Otherwise: if data->_1c (event id) is non-zero AND obj->_b8->_0
 * bits 5..7 are set, preempt the event. Then if (s8)data->_1e is not -1,
 * run that sequence with obj, -1.
 * Finally latch obj->_f4 = 1. */
void slidingdoor_update(u8* obj)
{
    u8* sub;
    u8* data;
    if (((GameObject*)obj)->unkF4 != 0) return;
    sub = ((GameObject*)obj)->extra;
    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((SlidingdoorPlacement*)data)->unk1C != 0)
    {
        u32 mode = (u32)((sub[0] >> 5) & 7);
        if (mode != 0)
        {
            (*gObjectTriggerInterface)->preempt((int)obj, ((SlidingdoorPlacement*)data)->unk1C);
        }
    }
    {
        s8 id = (s8)data[0x1e];
        if (id != -1)
        {
            (*gObjectTriggerInterface)->runSequence(id, obj, -1);
        }
    }
    *(u32*)&((GameObject*)obj)->unkF4 = 1;
}

/* exploded_init: store the map object tag, scale the model using the map
 * byte, then enable physics if any initial velocity/acceleration is present. */
void exploded_init(ExplodedObject* obj, ExplodedObjectMapData* data, int extra)
{
    ExplodedObjectState* state;
    obj->objectTypeTag = data->objectTypeTag;
    state = obj->state;
    obj->modelScale = (*(f32*)((char*)obj->modelData + 4) * (f32)(s32)
    data->scaleByte
    )
    /
    lbl_803E4428;
    exploded_initDebrisState(obj, data, extra, state);
    if (data->initialVelocityX != 0 ||
        data->initialVelocityY != 0 ||
        data->initialVelocityZ != 0 ||
        data->accelerationX != 0 ||
        data->accelerationY != 0 ||
        data->accelerationZ != 0)
    {
        state->explodePhase = 1;
    }
    else
    {
        state->explodePhase = 0;
    }
}

/* attractor_func0B: dispatch on (s8)obj->_4c->_19 - state 0/3+ store NULL,
 * state 1 stores obj, state 2 computes atan2 of (player - obj) deltas
 * (truncated to int), latches angle+0x8000 into obj+0, then stores obj. */
void attractor_func0B(u8* obj, void** out)
{
    void* result = NULL;
    s8 state = *(s8*)((char*)(*(u8**)&((GameObject*)obj)->anim.placementData) + 0x19);
    switch (state)
    {
    case 0:
        break;
    case 1:
        result = obj;
        break;
    case 2:
        {
            u8* player = (u8*)Obj_GetPlayerObject();
            int angle = atan2i(
                (int)(((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX),
                (int)(((GameObject*)player)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ)
            );
            ((GameObject*)obj)->anim.rotX = (s16)(angle + 0x8000);
            result = obj;
            break;
        }
    }
    *out = result;
}

/* slidingdoor_init: clear obj+0xf4, copy data[0x1f]<<8 into obj+0; install
 * slidingdoor_SeqFn as obj->thinkRoutine; convert data[0x21] to f32, scale by
 * lbl_803E43C0 and obj->_50->[4], stash at obj+0x8; then clear bits 5..7 of
 * obj->_b8->_0. */
void slidingdoor_init(u8* obj, u8* data)
{
    typedef struct SlidingDoorSubFlags
    {
        u8 doorState : 3;
        u8 rest : 5;
    } SlidingDoorSubFlags;
    u8* sub;
    f32 v;
    u32 doorState = 0;
    *(u32*)&((GameObject*)obj)->unkF4 = doorState;
    ((GameObject*)obj)->anim.rotX = (s16)(data[0x1f] << 8);
    ((GameObject*)obj)->animEventCallback = (void*)slidingdoor_SeqFn;
    v = (f32)(u32)
    data[0x21] * lbl_803E43C0;
    ((GameObject*)obj)->anim.rootMotionScale = v;
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * *(f32*)((char*)(*(u8**)&((
        GameObject*)obj)->anim.modelInstance) + 4);
    sub = ((GameObject*)obj)->extra;
    ((SlidingDoorSubFlags*)sub)->doorState = doorState;
}

extern void loadMapAndParent(int mapId);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int dirIdx, int b);

int CFLevelControl_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        int v = animUpdate->eventIds[i];
        switch (v)
        {
        case 1:
            GameBit_Set(0xdcb, 1);
            GameBit_Set(0x4a3, 0);
            loadMapAndParent(0x2b);
            unlockLevel(0, 0, 1);
            lockLevel(mapGetDirIdx(0x2b), 0);
            break;
        }
    }
    return 0;
}

/* cfforcefield_init: byte<<8 sth; insert GameBit_Get bit into bit-7 of *(u8*)obj->_B8; storeZeroToFloatParam. */
void cfforcefield_init(s16* obj, void* data)
{
    typedef struct ForceFieldInitFlags
    {
        u8 disabled : 1;
        u8 rest : 7;
    } ForceFieldInitFlags;
    register u8* flagPtr = (u8*)((int**)obj)[0xb8 / 4];
    {
        s8 v = *((s8*)data + 0x18);
        s16 t = v << 8;
        *obj = t;
    }
    ((ForceFieldInitFlags*)flagPtr)->disabled = (u8)GameBit_Get(*(s16*)((char*)data + 0x20));
    storeZeroToFloatParam(flagPtr + 4);
}

extern void Obj_TransformLocalPointByWorldMatrix(void* obj, void* state, f32* out, int flags);
extern void fn_80065684(double x, double y, double z, void* obj, f32* out, int flags);
extern f32 lbl_803E43F0;
extern f32 lbl_803E4400;
extern f32 lbl_803E4404;
extern f32 lbl_803E4408;
extern f64 lbl_803E4410;
extern f32 lbl_803E4418;
extern f32 lbl_803E441C;
extern f32 lbl_803E4420;
extern f32 lbl_803E4424;


void exploded_initDebrisState(ExplodedObject* obj, ExplodedObjectMapData* data,
                              int computeModelCenter, ExplodedObjectState* state)
{
    extern void Model_GetVertexPosition(int, int, f32*);
    extern void vecRotateYXZ(int, int);
    extern f32 lbl_803E43F0;
    extern f32 lbl_803E43F4;

    obj->x = data->positionX;
    obj->y = data->positionY;
    obj->z = data->positionZ;

    if (computeModelCenter == 0)
    {
        register int* mesh;
        register int i;
        f32 v[6];
        f32 z;
        f32 k;

        z = lbl_803E43F0;
        state->localCenterX = z;
        state->localCenterY = z;
        state->localCenterZ = z;
        v[3] = z;
        v[4] = z;
        v[5] = z;

        mesh = *(int**)(*(int*)(*(int*)&((GameObject*)obj)->anim.banks + (u32)data->objectTypeTag * 4));
        for (i = 0; i < *(u16*)((char*)mesh + 0xe4); i++)
        {
            Model_GetVertexPosition((int)mesh, i, v);
            v[3] = v[0] + v[3];
            v[4] = v[1] + v[4];
            v[5] = v[2] + v[5];
        }

        state->localCenterX = v[3] * ((k = lbl_803E43F4) / (f32)(u32) * (u16*)((char*)mesh + 0xe4));
        state->localCenterY = v[4] * (k / (f32)(u32) * (u16*)((char*)mesh + 0xe4));
        state->localCenterZ = v[5] * (k / (f32)(u32) * (u16*)((char*)mesh + 0xe4));
    }

    state->initialLocalCenterX = state->localCenterX;
    state->initialLocalCenterY = state->localCenterY;
    state->initialLocalCenterZ = state->localCenterZ;
    exploded_seedDebrisMotion(obj, state, data);

    {
        f32 tv[3];
        tv[0] = state->localCenterX;
        tv[1] = state->localCenterY;
        tv[2] = state->localCenterZ;
        vecRotateYXZ((int)obj, (int)tv);
        tv[0] = tv[0] * obj->modelScale;
        tv[1] = tv[1] * obj->modelScale;
        tv[2] = tv[2] * obj->modelScale;
    }

    *((u8*)state + 0x67) = 255;
    state->physicsFlags = 0;
}


/* Exploded debris setup: seed object angles, linear velocity, angular velocity,
 * ground clearance, and the randomized lifetime countdown. */
void exploded_seedDebrisMotion(ExplodedObject* obj, ExplodedObjectState* state, ExplodedObjectMapData* data)
{
    f32 floorY[2];
    f32 d1;

    floorY[0] = lbl_803E43F0;
    obj->angleX = data->initialAngleX;
    obj->angleY = data->initialAngleY;
    obj->angleZ = data->initialAngleZ;

    obj->velocityX = (f32)(s32)
    data->initialVelocityX / (d1 = lbl_803E4400);
    obj->velocityY = (f32)(s32)
    data->initialVelocityY / d1;
    obj->velocityZ = (f32)(s32)
    data->initialVelocityZ / d1;
    state->spinX = (f32)(s32)
    data->spinX;
    state->spinY = (f32)(s32)
    data->spinY;
    state->spinZ = (f32)(s32)
    data->spinZ;

    {
        u16 off = *(u16*)&data->floorOffset;
        if (off == 0)
        {
            fn_80065684((double)obj->x, (double)(obj->y - lbl_803E4404), (double)obj->z, obj, floorY, 0);
            state->floorHeight = obj->y - floorY[0];
        }
        else
        {
            state->floorHeight = obj->y + (f32)(s16)
            off;
        }
    }

    state->spinVelocityX = (f32)(s32)
    data->spinVelocityX / (d1 = lbl_803E4404);
    state->spinVelocityY = (f32)(s32)
    data->spinVelocityY / d1;
    state->spinVelocityZ = (f32)(s32)
    data->spinVelocityZ / d1;
    state->accelerationX = (f32)(s32)
    data->accelerationX / (d1 = lbl_803E4408);
    state->accelerationY = (f32)(s32)
    data->accelerationY / d1;
    state->accelerationZ = (f32)(s32)
    data->accelerationZ / d1;

    state->elapsedFrames = 0;
    if (*(u16*)&data->lifetimeFrames != 0)
    {
        state->durationFrames = *(u16*)&data->lifetimeFrames * ((int)randomGetRange(0, 100) + 100) / 200;
    }
    else
    {
        state->durationFrames = -1;
    }
}

/* Exploded debris physics step: integrate local velocity and spin, bounce from
 * the stored floor height, and return nonzero once the shard comes to rest. */
int exploded_stepDebrisPhysics(ExplodedObject* obj, ExplodedObjectState* state)
{
    f32 stopped;
    f32 speed;
    f32 worldAfter[3];
    f32 worldBefore[3];

    stopped = lbl_803E43F0;
    Obj_TransformLocalPointByWorldMatrix(obj, state, worldBefore, 0);
    obj->velocityX = timeDelta * state->accelerationX + obj->velocityX;
    obj->velocityY = timeDelta * state->accelerationY + obj->velocityY;
    obj->velocityZ = timeDelta * state->accelerationZ + obj->velocityZ;
    state->spinX = timeDelta * state->spinVelocityX + state->spinX;
    state->spinY = timeDelta * state->spinVelocityY + state->spinY;
    state->spinZ = timeDelta * state->spinVelocityZ + state->spinZ;

    if (worldBefore[1] < state->floorHeight)
    {
        if (((obj->velocityY < *(f32*)&lbl_803E43F0) && ((state->physicsFlags & 4) != 0)) ||
            (lbl_803E43F0 == obj->velocityY))
        {
            f32 t;
            f32 k;
            t = lbl_803E43F0;
            state->accelerationY = t;
            state->spinVelocityZ = t;
            state->spinZ = t;
            state->spinVelocityY = t;
            state->spinY = t;
            state->spinVelocityX = t;
            state->spinX = t;
            obj->velocityY = t;
            k = lbl_803E4418;
            state->accelerationX = state->accelerationX * k;
            obj->velocityX = obj->velocityX * k;
            state->accelerationZ = state->accelerationZ * k;
            obj->velocityZ = obj->velocityZ * k;
            speed = obj->velocityX;
            speed = (speed >= t) ? speed : -speed;
            if (speed < lbl_803E441C)
            {
                speed = obj->velocityZ;
                speed = (speed >= lbl_803E43F0) ? speed : -speed;
                if (speed < lbl_803E441C)
                {
                    stopped = lbl_803E43F4;
                }
            }
        }
        if (obj->velocityY < lbl_803E43F0)
        {
            f32 k2;
            obj->velocityY = lbl_803E4420 * -obj->velocityY;
            k2 = lbl_803E4418;
            obj->velocityX = obj->velocityX * k2;
            obj->velocityZ = obj->velocityZ * k2;
            state->accelerationY = lbl_803E4424;
            state->spinVelocityZ = -state->spinVelocityZ;
        }
        state->physicsFlags |= 4;
    }
    else
    {
        state->physicsFlags &= ~4;
    }

    obj->angleX = (s32)(state->spinX * timeDelta + (f32)(s32)obj->angleX);
    obj->angleY = (s32)(state->spinY * timeDelta + (f32)(s32)obj->angleY);
    obj->angleZ = (s32)(state->spinZ * timeDelta + (f32)(s32)obj->angleZ);
    Obj_TransformLocalPointByWorldMatrix(obj, state, worldAfter, 0);
    worldAfter[0] = worldBefore[0] - worldAfter[0];
    worldAfter[1] = worldBefore[1] - worldAfter[1];
    worldAfter[2] = worldBefore[2] - worldAfter[2];
    obj->x = obj->x + worldAfter[0];
    obj->y = obj->y + worldAfter[1];
    obj->z = obj->z + worldAfter[2];
    obj->x = obj->velocityX * timeDelta + obj->x;
    obj->y = obj->velocityY * timeDelta + obj->y;
    obj->z = obj->velocityZ * timeDelta + obj->z;
    return (s32)stopped;
}
