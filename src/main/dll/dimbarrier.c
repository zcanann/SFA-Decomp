/* === moved from main/dll/creator1C4.c [801C835C-801C83D0) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling off
#pragma peephole off
#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/creator1C4.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/screen_transition.h"

typedef struct GpshObjcreatorState
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 pad5[0x8 - 0x5];
} GpshObjcreatorState;


typedef struct GpshObjcreatorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s8 unk1E;
    u8 pad1F[0x20 - 0x1F];
} GpshObjcreatorObjectDef;


typedef struct GpshShrineState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    u8 padC[0x12 - 0xC];
    u8 unk12;
    u8 pad13[0x14 - 0x13];
    u8 unk14;
    u8 pad15[0x18 - 0x15];
} GpshShrineState;


extern undefined8 FUN_80006728();
extern undefined4 FUN_80006770();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_80042b9c();
extern int FUN_80044404();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_801c70c4();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801d8480();
extern undefined4 FUN_80286834();
extern undefined4 FUN_80286880();
extern uint FUN_80294cd0();

extern f64 DOUBLE_803e5cc8;
extern f32 lbl_803DC074;
extern f32 lbl_803E5CD4;
extern f32 lbl_803E5CD8;
extern void* objCreateLight(int obj, int kind);

/*
 * --INFO--
 *
 * Function: gpsh_shrine_update
 * EN v1.0 Address: 0x801C7724
 * EN v1.0 Size: 2520b
 * EN v1.1 Address: 0x801C7CD8
 * EN v1.1 Size: 2124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct
{
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
    u8 b08 : 1;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} GpshShrineFlags;

extern void* Obj_GetPlayerObject(void);
extern u32 GameBit_Get(int bit);
extern int GameBit_Set(int bit, int val);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern void skyFn_80088c94(int a, int b);
extern int getEnvfxAct(int obj, int player, int id, int p);
extern void fn_801C70F0(int obj);
extern int mapGetDirIdx(int a);
extern int unlockLevel(int a, int b, int c);
extern void SCGameBitLatch_Update(int state, int a, int b, int c, int d, int e);
extern void SCGameBitLatch_UpdateInverted(int state, int a, int b, int c, int d, int e);
extern void gameTimerInit(int a, int b);
extern void timerSetToCountUp(void);
extern void gameTimerStop(void);
extern int isGameTimerDisabled(void);
extern int Obj_FreeObject(int obj);
extern int objGetAnimStateFlags(int obj, int flag);
extern void audioStopByMask(int mask);
extern int Music_Trigger(int id, int value);
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern ScreenTransitionInterface** gScreenTransitionInterface;
extern MapEventInterface** gMapEventInterface;
extern f32 timeDelta;
extern f32 lbl_803E503C;
extern f32 lbl_803E5040;

void gpsh_shrine_update(int obj);


void gpsh_shrine_init(int* obj, int* def);

/* Trivial 4b 0-arg blr leaves. */
void gpsh_shrine_release(void);

void gpsh_shrine_initialise(void);

void gpsh_objcreator_free(void);

void gpsh_objcreator_hitDetect(void);

void gpsh_objcreator_release(void);

void gpsh_objcreator_initialise(void);

extern u8 Obj_IsLoadingLocked(void);
extern void hitDetectFn_80097070(int* obj, f32 e, int a, int b, int c, int d);
extern void Sfx_PlayFromObjectLimited(int obj, int sfx, int v);
extern void* Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);
extern f32 lbl_803E504C;
extern f32 lbl_803E5050;
extern f32 lbl_803E5054;
extern s16 lbl_803263B8[];

void gpsh_objcreator_update(int* obj);

void gpsh_scene_free(void);

void gpsh_scene_hitDetect(void);

void gpsh_scene_update(void);

void gpsh_scene_release(void);

void gpsh_scene_initialise(void);

void ecsh_cup_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int gpsh_objcreator_getExtraSize(void);
int gpsh_objcreator_getObjectTypeId(void);
int gpsh_scene_getExtraSize(void);
int gpsh_scene_getObjectTypeId(void);
int ecsh_cup_getExtraSize(void) { return 0x30; }
int ecsh_cup_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5048;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5058;
extern f32 lbl_803E5060;

void gpsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void gpsh_scene_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void ecsh_cup_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5060);
}

void ecsh_cup_free(int* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void gpsh_scene_init(int* obj, int* def);

void gpsh_objcreator_init(int* obj, int* def);
#pragma scheduling reset
#pragma peephole reset

#include "main/dll/dimbarrier.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/objseq.h"

typedef struct EcshCupState
{
    f32 unk0;
    f32 unk4;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    f32 unk14;
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    s32 unk24;
    s32 unk28;
    s16 unk2C;
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} EcshCupState;


extern undefined4 FUN_800067e8();
extern void* FUN_80017624();
extern undefined4 FUN_8001771c();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810ec();
extern undefined4 FUN_801c7390();

extern undefined4 DAT_802c2b38;
extern undefined4 DAT_802c2b3c;
extern undefined4 DAT_802c2b40;
extern f32 lbl_803DC074;

extern f32 lbl_803E5064;
extern f32 lbl_803E5068;
extern f32 lbl_803E506C;
extern f32 lbl_803E5070;
extern f32 lbl_803E5074;
extern f32 lbl_803E5078;
extern f32 lbl_803E507C;
extern f32 lbl_803E5080;
extern f32 lbl_803E5084;
extern f32 lbl_803E5088;
extern f64 lbl_803E5090;
extern f64 lbl_803E5098;
extern undefined4 lbl_803DDBC8;

/*
 * --INFO--
 *
 * Function: ecsh_cup_update
 * EN v1.0 Address: 0x801C83D0
 * EN v1.0 Size: 1636b
 * EN v1.1 Address: 0x801C8524
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct
{
    f32 x;
    f32 y;
    f32 z;
} CupVec3;

extern void* Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32 * a, f32 * b);
extern EffectInterface** gPartfxInterface;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f32 timeDelta;
extern f32 lbl_802C23B8[];

#pragma scheduling off
void ecsh_cup_update(short* obj)
{
    f32 dist;
    int mode;
    u8 buf[4];
    CupVec3 v;
    char* player = (char*)Obj_GetPlayerObject();
    char* state = ((GameObject*)obj)->extra;
    f32 a;

    v = *(CupVec3*)lbl_802C23B8;
    dist = lbl_803E5064;
    mode = -1;
    buf[0] = 0;
    if (lbl_803DDBC8 == 0)
    {
        lbl_803DDBC8 = ObjGroup_FindNearestObject(0xb, obj, &dist);
    }
    if (lbl_803DDBC8 != 0 && *(short*)(lbl_803DDBC8 + 0x44) != 0)
    {
        (*(void (*)(int*, u8*))*(int*)(*(int*)(*(int*)(lbl_803DDBC8 + 0x68)) + 0x28))(&mode, buf);
        *obj = *obj + ((EcshCupState*)state)->unk2C;
        if (mode != 6)
        {
            ((EcshCupState*)state)->unk1C -= timeDelta;
            if (((EcshCupState*)state)->unk1C <= lbl_803E5068)
            {
                ((EcshCupState*)state)->unk1C = lbl_803E506C;
                if (mode != 3 && mode != 6 && mode != 7)
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x270, NULL, 0, -1, NULL);
                }
            }
        }
        ((EcshCupState*)state)->unk20 -= timeDelta;
        if (((EcshCupState*)state)->unk20 <= lbl_803E5068)
        {
            ((EcshCupState*)state)->unk2E = *(u8*)&((EcshCupState*)state)->unk2E * -1LL;
            ((EcshCupState*)state)->unk20 = lbl_803E5070;
        }
        ((GameObject*)obj)->anim.localPosY = lbl_803E5074 * (f32)((EcshCupState*)state)->unk2E + ((GameObject*)obj)->
            anim.localPosY;
        if (mode == 1 && ((EcshCupState*)state)->unk24 == 1)
        {
            ((GameObject*)obj)->anim.localPosX = ((EcshCupState*)state)->unkC * timeDelta + ((GameObject*)obj)->anim.
                localPosX;
            ((GameObject*)obj)->anim.localPosZ = ((EcshCupState*)state)->unk14 * timeDelta + ((GameObject*)obj)->anim.
                localPosZ;
            ObjHits_EnableObject((int)obj);
            ObjHits_SetHitVolumeSlot((int)obj, 10, 1, 0);
            ObjHits_SyncObjectPositionIfDirty((int)obj);
        }
        else
        {
            ObjHits_EnableObject((int)obj);
            ObjHits_SetHitVolumeSlot((int)obj, 0, 0, 0);
            ObjHits_SyncObjectPositionIfDirty((int)obj);
        }
        if (mode == 6)
        {
            if (((GameObject*)obj)->anim.localPosY < ((EcshCupState*)state)->unk18)
            {
                ((GameObject*)obj)->anim.localPosY = lbl_803E5078 * timeDelta + ((GameObject*)obj)->anim.localPosY;
            }
            if (*(u8*)((char*)obj + 0x37) != 0xff)
            {
                a = (f32)(u32) * (u8*)((char*)obj + 0x37);
                a = lbl_803E507C * timeDelta + a;
                if (a >= lbl_803E5080)
                {
                    a = lbl_803E5080;
                }
                *(u8*)((char*)obj + 0x37) = (u8)(int)
                a;
            }
            ((EcshCupState*)state)->unk1C -= timeDelta;
            if (((EcshCupState*)state)->unk1C <= lbl_803E5068)
            {
                ((EcshCupState*)state)->unk1C = lbl_803E506C;
                (*gPartfxInterface)->spawnObject(obj, 0x271, NULL, 0, -1, NULL);
            }
        }
        else if (mode == 7)
        {
            if (((GameObject*)obj)->anim.localPosY > ((EcshCupState*)state)->unk18 - lbl_803E5084)
            {
                ((GameObject*)obj)->anim.localPosY = -(lbl_803E5078 * timeDelta - ((GameObject*)obj)->anim.localPosY);
                ((EcshCupState*)state)->unk1C -= timeDelta;
                if (((EcshCupState*)state)->unk1C <= lbl_803E5068)
                {
                    ((EcshCupState*)state)->unk1C = lbl_803E506C;
                    if (mode != 3)
                    {
                        (*gPartfxInterface)->spawnObject(obj, 0x271, NULL, 0, -1, NULL);
                    }
                }
            }
            if (*(u8*)((char*)obj + 0x37) != 0)
            {
                a = (f32)(u32) * (u8*)((char*)obj + 0x37);
                a = -(lbl_803E507C * timeDelta - a);
                if (a <= lbl_803E5068)
                {
                    a = lbl_803E5068;
                }
                *(u8*)((char*)obj + 0x37) = (u8)(int)
                a;
            }
        }
        else if (mode == 8 && mode != ((EcshCupState*)state)->unk24)
        {
            if (((EcshCupState*)state)->unk28 == buf[0])
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            }
            ((EcshCupState*)state)->unk24 = mode;
        }
        else if (mode == 1 && mode != *(int*)(state + 0x24))
        {
            (*(void (*)(int, f32*, f32*))*(int*)(*(int*)(*(int*)(lbl_803DDBC8 + 0x68)) + 0x24))(
                (u8)((EcshCupState*)state)->unk28, &v.x, &v.z);
            ((EcshCupState*)state)->unkC = (v.x - ((GameObject*)obj)->anim.localPosX) / lbl_803E5070;
            ((EcshCupState*)state)->unk14 = (v.z - ((GameObject*)obj)->anim.localPosZ) / lbl_803E5070;
            ((EcshCupState*)state)->unk0 = ((GameObject*)obj)->anim.localPosX;
            ((EcshCupState*)state)->unk8 = ((GameObject*)obj)->anim.localPosZ;
            ((EcshCupState*)state)->unk24 = mode;
        }
        else if (mode == 0 && mode != *(int*)(state + 0x24))
        {
            ((EcshCupState*)state)->unkC = lbl_803E5068;
            ((EcshCupState*)state)->unk14 = lbl_803E5068;
            ((EcshCupState*)state)->unk24 = mode;
        }
        else if (mode == 2 && mode != *(int*)(state + 0x24))
        {
            ((EcshCupState*)state)->unkC = lbl_803E5068;
            ((EcshCupState*)state)->unk14 = lbl_803E5068;
            (*(void (*)(int, f32, f32))*(int*)(*(int*)(*(int*)(lbl_803DDBC8 + 0x68)) + 0x2c))(
                (u8)((EcshCupState*)state)->unk28, ((GameObject*)obj)->anim.localPosX,
                ((GameObject*)obj)->anim.localPosZ);
            ((EcshCupState*)state)->unk24 = mode;
        }
        else if (mode == 3 && mode != *(int*)(state + 0x24))
        {
            ((EcshCupState*)state)->unk24 = mode;
        }
        else if (mode == 4 && mode != *(int*)(state + 0x24))
        {
            (*(void (*)(int, f32*, f32*))*(int*)(*(int*)(*(int*)(lbl_803DDBC8 + 0x68)) + 0x24))(
                (u8)((EcshCupState*)state)->unk28, &v.x, &v.z);
            ((GameObject*)obj)->anim.localPosX = v.x;
            ((GameObject*)obj)->anim.localPosZ = v.z;
            ((EcshCupState*)state)->unk24 = mode;
        }
        else if (mode == 5)
        {
            if (player != NULL)
            {
                if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) < lbl_803E5088)
                {
                    (*(void (*)(int))*(int*)(*(int*)(*(int*)(lbl_803DDBC8 + 0x68)) + 0x30))(
                        (u8)((EcshCupState*)state)->unk28);
                    if (((EcshCupState*)state)->unk28 == buf[0])
                    {
                        (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                    }
                }
            }
        }
    }
}

/*
 * --INFO--
 *
 * Function: FUN_801c83d4
 * EN v1.0 Address: 0x801C83D4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801C864C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on


/*
 * --INFO--
 *
 * Function: ecsh_cup_release
 * EN v1.0 Address: 0x801C8B60
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ecsh_cup_release(void)
{
}

/*
 * --INFO--
 *
 * Function: ecsh_cup_init
 * EN v1.0 Address: 0x801C8A34
 * EN v1.0 Size: 300b
 */
#pragma scheduling off
#pragma peephole off
void ecsh_cup_init(int obj, int p2)
{
    extern int randomGetRange(int min, int max); /* #57 */
    int t;
    f32 ftmp;

    t = *(int*)&((GameObject*)obj)->extra;
    ftmp = lbl_803E5064;
    lbl_803DDBC8 = 0;
    ((EcshCupState*)t)->unk0 = ((GameObject*)obj)->anim.localPosX;
    ((EcshCupState*)t)->unk4 = ((GameObject*)obj)->anim.localPosY;
    ((EcshCupState*)t)->unk8 = ((GameObject*)obj)->anim.localPosZ;
    ((EcshCupState*)t)->unk18 = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E5084;
    {
        f32 fz = lbl_803E5068;
        ((EcshCupState*)t)->unkC = fz;
        ((EcshCupState*)t)->unk10 = fz;
        ((EcshCupState*)t)->unk14 = fz;
    }
    ((EcshCupState*)t)->unk24 = 0;
    ((EcshCupState*)t)->unk28 = *(s16*)(p2 + 0x1a);
    ((EcshCupState*)t)->unk20 = (f32)randomGetRange(0, 0x258);
    ((EcshCupState*)t)->unk2C = (s16)randomGetRange(-0x320, 0x320);
    *(u8*)&((EcshCupState*)t)->unk2E = 1;
    *(u8*)(obj + 0x37) = 0;
    ((EcshCupState*)t)->unk1C = lbl_803E5068;
    if (lbl_803DDBC8 == 0)
    {
        lbl_803DDBC8 = ObjGroup_FindNearestObject(0xb, obj, &ftmp);
    }
    ObjHits_EnableObject(obj);
    ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
    ObjHits_SyncObjectPositionIfDirty(obj);
}

/*
 * --INFO--
 *
 * Function: ecsh_cup_initialise
 * EN v1.0 Address: 0x801C8B64
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void ecsh_cup_initialise(void)
{
}


extern f32 mathSinf(f32 v);
extern int getAngle(f32 dx, f32 dz);
extern f32 Vec_xzDistance(float* a, float* b);
extern f32 lbl_803E50A0;
extern f32 lbl_803E50A4;
extern f32 lbl_803E50A8;
extern f32 lbl_803E50AC;
extern f32 lbl_803E50B0;
extern f32 lbl_803E50B4;
extern f32 lbl_803E50B8;
extern f32 lbl_803E50BC;
extern f32 lbl_803E50C0;
extern f32 lbl_803E50C4;
extern f32 lbl_803E50C8;
extern f64 lbl_803E50D0;

/*
 * --INFO--
 *
 * Function: fn_801C8B68
 * EN v1.0 Address: 0x801C8B68
 * EN v1.0 Size: 852b
 */
#pragma scheduling off
#pragma peephole off
void fn_801C8B68(int obj)
{
    register int self = obj;
    register int state2 = *(int*)&((GameObject*)self)->anim.placementData;
    register int state = *(int*)&((GameObject*)self)->extra;
    void* player = Obj_GetPlayerObject();
    int local_var;
    f32 dist;
    f32 angA, angB;
    int delta;

    if ((((GameObject*)self)->anim.flags & 0x4000) != 0)
    {
        *(short*)self = 0;
        ((GameObject*)self)->anim.localPosY = *(float*)(state2 + 0xc);
        return;
    }

    *(short*)(state + 0xe) = (short)(
        (int)*(short*)(state + 0xe)
        + (int)(lbl_803E50A0 * timeDelta));
    *(short*)(state + 0x10) = (short)(
        (int)*(short*)(state + 0x10)
        + (int)(lbl_803E50A4 * timeDelta));
    *(short*)(state + 0x12) = (short)(
        (int)*(short*)(state + 0x12)
        + (int)(lbl_803E50A8 * timeDelta));

    ((GameObject*)self)->anim.localPosY = lbl_803E50AC + (*(float*)(state2 + 0xc) +
        mathSinf((lbl_803E50B0 * (f32)(s32) * (short*)(state + 0xe)) / lbl_803E50B4));
    angA = mathSinf((lbl_803E50B0 * (f32)(s32) * (short*)(state + 0x10)) / lbl_803E50B4);
    angB = mathSinf((lbl_803E50B0 * (f32)(s32) * (short*)(state + 0xe)) / lbl_803E50B4);
    ((GameObject*)self)->anim.rotZ = (short)(int)(lbl_803E50B8 * (angA + angB));
    angA = mathSinf((lbl_803E50B0 * (f32)(s32) * (short*)(state + 0x12)) / lbl_803E50B4);
    angB = mathSinf((lbl_803E50B0 * (f32)(s32) * (short*)(state + 0xe)) / lbl_803E50B4);
    ((GameObject*)self)->anim.rotY = (short)(int)(lbl_803E50B8 * (angA + angB));

    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(self, lbl_803E50BC, timeDelta,
                                                                 (ObjAnimEventList*)&local_var);

    if (player == NULL) return;

    {
        float dx = ((GameObject*)self)->anim.worldPosX - *(float*)((int)player + 0x18);
        float dz = ((GameObject*)self)->anim.worldPosZ - *(float*)((int)player + 0x20);
        int ang = (int)getAngle(dx, dz);
        delta = (int)(u16)ang - (int)(u16) * (short*)self;
        if (delta > 0x8000) delta -= 0x10000;
        if (delta < -0x8000) delta += 0x10000;
        *(short*)self = (short)(
            (int)*(short*)self
            + (int)((f32)delta * timeDelta / lbl_803E50C0));
    }
    dist = Vec_xzDistance((float*)(self + 0x18), (float*)((int)player + 0x18));
    if (dist <= lbl_803E50C4)
    {
        ((GameObject*)self)->anim.alpha = (u8)(int)(lbl_803E50C8 * (dist / lbl_803E50C4));
    }
    else
    {
        ((GameObject*)self)->anim.alpha = 0xff;
    }
}
