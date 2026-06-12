/* === merged from main/dll/mmshrine/animobj1C0.c [801C5990-801C5ED8) (TU re-split, docs/boundary_audit.md) === */
#include "main/game_object.h"
#include "main/objseq.h"

#include "main/dll/mmshrine/ecsh_shrine_state.h"


extern u32 randomGetRange(int min, int max);
extern void* FUN_80017aa4();
extern uint FUN_80017ae8();
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern f32 mathSinf(f32 x);

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f32 timeDelta;
extern f64 DOUBLE_803e5c08;
extern f32 lbl_803E4F90;
extern f32 lbl_803E4F94;
extern f32 lbl_803E4F98;
extern f32 lbl_803E4F9C;
extern f32 lbl_803E4FA0;
extern f32 lbl_803E4FA4;
extern f32 lbl_803E4FA8;
extern f32 lbl_803E4FAC;
extern f32 lbl_803E4FB0;
extern f32 lbl_803E4FB4;
extern f32 lbl_803E4FB8;
extern f32 lbl_803E4FC8;
extern f32 lbl_803E5C00;
extern f32 lbl_803E5C10;

typedef struct MmShrineAnimObj
{
    s16 yaw;
    s16 pitch;
    s16 roll;
    s16 flags;
    u8 pad08[0x8];
    f32 posY;
    u8 pad14[0x4];
    f32 posX;
    u8 pad1C[0x4];
    f32 posZ;
    u8 pad24[0x12];
    u8 fadeAlpha;
    u8 pad37[0x15];
    u8* config;
    u8 pad50[0x68];
    u8* state;
} MmShrineAnimObj;

typedef struct MmShrineAnimState
{
    int light;
    u8 pad04[0x24];
    s16 orbitA;
    s16 orbitB;
    s16 orbitC;
    u8 pad2E[0x2];
    u8 hasTorchSignal;
} MmShrineAnimState;

typedef struct MmShrineAnimEvents
{
    u8 pad00[0x56];
    u8 eventStatus;
    u8 pad57[0x19];
    s16 eventModel;
    u8 pad72[0xF];
    u8 events[10];
    u8 eventCount;
} MmShrineAnimEvents;

/*
 * --INFO--
 *
 * Function: FUN_801c5990
 * EN v1.0 Address: 0x801C5990
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x801C5B9C
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_801c5990(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9, int param_10)
{
    extern undefined4 FUN_80017ae4(); /* #57 */
    uint uVar1;
    undefined2* puVar2;
    undefined4 uVar3;
    int iVar4;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    int iVar5;
    double dVar6;
    double dVar7;

    iVar5 = *(int*)&((GameObject*)param_9)->extra;
    *(undefined2*)(iVar5 + 0x6a) = *(undefined2*)(param_10 + 0x1a);
    *(undefined2*)(iVar5 + 0x6e) = 0xffff;
    dVar6 = DOUBLE_803e5c08;
    dVar7 = (double)lbl_803E5C00;
    *(float*)(iVar5 + 0x24) =
        (float)(dVar7 / (double)(float)(dVar7 + (double)(float)((double)CONCAT44(0x43300000,
            (uint) * (byte*)(
                param_10 + 0x24)) - DOUBLE_803e5c08)));
    *(undefined4*)(iVar5 + 0x28) = 0xffffffff;
    iVar4 = ((GameObject*)param_9)->unkF4;
    if ((iVar4 == 0) && (*(short*)(param_10 + 0x18) != 1))
    {
        (*gObjectTriggerInterface)->loadAnimData((u8*)iVar5, (u8*)param_10);
        ((GameObject*)param_9)->unkF4 = *(short*)(param_10 + 0x18) + 1;
    }
    else if ((iVar4 != 0) && ((int)*(short*)(param_10 + 0x18) != iVar4 + -1))
    {
        (*gObjectTriggerInterface)->freeState((u8*)iVar5);
        if (*(short*)(param_10 + 0x18) != -1)
        {
            (*gObjectTriggerInterface)->loadAnimData((u8*)iVar5, (u8*)param_10);
        }
        ((GameObject*)param_9)->unkF4 = *(short*)(param_10 + 0x18) + 1;
    }
    uVar1 = FUN_80017ae8();
    if ((uVar1 & 0xff) != 0)
    {
        puVar2 = FUN_80017aa4(0x24, 0x1b8);
        *(undefined4*)(puVar2 + 4) = *(undefined4*)&((GameObject*)param_9)->anim.localPosX;
        *(undefined4*)(puVar2 + 6) = *(undefined4*)&((GameObject*)param_9)->anim.localPosY;
        *(undefined4*)(puVar2 + 8) = *(undefined4*)&((GameObject*)param_9)->anim.localPosZ;
        *(undefined*)(puVar2 + 2) = 0x20;
        *(undefined*)((int)puVar2 + 5) = 4;
        *(undefined*)((int)puVar2 + 7) = 0xff;
        uVar3 = FUN_80017ae4(dVar6, dVar7, param_3, param_4, param_5, param_6, param_7, param_8, puVar2, 5, 0xff,
                             0xffffffff, (uint*)0x0, in_r8, in_r9, in_r10);
        *(undefined4*)&((GameObject*)param_9)->childObjs[0] = uVar3;
        *(float*)(*(int*)&((GameObject*)param_9)->childObjs[0] + 8) =
            *(float*)(*(int*)&((GameObject*)param_9)->childObjs[0] + 8) * lbl_803E5C10;
    }
    return;
}


#pragma scheduling off
#pragma peephole off
void fn_801C5990(MmShrineAnimObj* obj);

int fn_801C5CE4(void* objArg, int unused, void* eventListArg);


void ecsh_shrine_modelMtxFn(int* p1, u8* p2);

void ecsh_shrine_func0E(u8 v);

extern s16 lbl_80326238[];

typedef struct EcshRenderPair
{
    f32 a;
    f32 b;
} EcshRenderPair;


void ecsh_shrine_render2(u8 idx, f32 a, f32 b);

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset

/* === merged from main/dll/mmshrine/torch1C1.c [801C5ED8-801C60B8) (TU re-split, docs/boundary_audit.md) === */
#include "main/game_object.h"
#include "main/objseq.h"

extern undefined4 FUN_800067c0();
extern undefined8 ObjGroup_RemoveObject();



void ecsh_shrine_func0B(u8 idx, f32* out1, f32* out2);

void ecsh_shrine_setScale(s16* out);

/*
 * --INFO--
 *
 * Function: FUN_801c5f28
 * EN v1.0 Address: 0x801C5F28
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801C5F44
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: ecsh_shrine_getExtraSize
 * EN v1.0 Address: 0x801C5F40
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ecsh_shrine_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: ecsh_shrine_getObjectTypeId
 * EN v1.0 Address: 0x801C5F48
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ecsh_shrine_getObjectTypeId(void);

/*
 * --INFO--
 *
 * Function: ecsh_shrine_hitDetect
 * EN v1.0 Address: 0x801C60B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ecsh_shrine_hitDetect(void);

extern void Music_Trigger(int trackId, int restart);
extern void ModelLightStruct_free(void* p);

void ecsh_shrine_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

void ecsh_shrine_free(int* obj);

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset

#include "main/audio/sfx_ids.h"
#include "main/game_ui_interface.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/dll/mmshrine/shrine1C2.h"
#include "main/dll/mmshrine/torch1C1.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/screen_transition.h"

#include "main/dll/mmshrine/ecsh_shrine_state.h"


extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern undefined4 FUN_80017830();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_AllocQueue();

extern undefined4 DAT_803dc070;

/*
 * --INFO--
 *
 * Function: ecsh_shrine_update
 * EN v1.0 Address: 0x801C60B8
 * EN v1.0 Size: 3360b
 * EN v1.1 Address: 0x801C666C
 * EN v1.1 Size: 3104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void skyFn_80088c94(int a, int b);
extern void getEnvfxAct(s16* obj, int* target, int id, int p);
extern int objIsCurModelNotZero(int* player);
extern void fn_80295CF4(int* player, int a);
extern void SCGameBitLatch_Update(u8* latch, int mask, int a, int b, int bit, int c);
extern void SCGameBitLatch_UpdateInverted(u8* latch, int mask, int a, int b, int bit, int c);
extern void audioStopByMask(int mask);
extern int objGetAnimStateFlags(int* player, int flags);
extern void Sfx_KeepAliveLoopedObjectSound(s16* obj, int sfxId);
extern void Sfx_PlayFromObject(s16* obj, int sfxId);
extern void Music_Trigger(int id, int restart);
extern int GameBit_Get(int bit);
extern ScreenTransitionInterface** gScreenTransitionInterface;
extern int lbl_803E8470;
extern f32 lbl_803E4FCC;
extern f32 lbl_803E4FD0;
extern f32 lbl_803E4FD4;
extern f32 lbl_803E4FD8;
extern f32 lbl_803E4FDC;
extern f32 lbl_803E4FE0;
extern f32 lbl_803E4FE4;
extern f32 lbl_803E4FE8;
extern f32 lbl_803E4FEC;
extern f32 lbl_803E4FF0;

typedef struct EcshPuzzleState
{
    f32 f[12]; /* 0x00 */
    s16 cur[6]; /* 0x30 */
    s16 next[7]; /* 0x3c */
} EcshPuzzleState;

typedef struct EcshIntPair
{
    int a;
    int b;
} EcshIntPair;

#pragma opt_strength_reduction off
void ecsh_shrine_update(s16* obj);
#pragma opt_strength_reduction reset


/*
 * --INFO--
 *
 * Function: FUN_801c6e04
 * EN v1.0 Address: 0x801C6E04
 * EN v1.0 Size: 704b
 * EN v1.1 Address: 0x801C7408
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c6e04(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined2* param_9)
{
    extern int FUN_80017ae4(); /* #57 */
    uint uVar1;
    int* piVar2;
    undefined2* puVar3;
    undefined4 in_r8;
    int in_r9;
    undefined4 in_r10;
    short* psVar4;
    int iVar5;

    iVar5 = *(int*)(param_9 + 0x26);
    psVar4 = *(short**)(param_9 + 0x5c);
    if ((*(int*)(param_9 + 0x7c) == '\0') && (uVar1 = FUN_80017690((int)psVar4[2]), uVar1 != 0))
    {
        piVar2 = (int*)FUN_80006b14(0x82);
        (*(code*)(*piVar2 + 4))(param_9, 0, 0, 1, 0xffffffff, 0);
        in_r8 = 0;
        in_r9 = *piVar2;
        (*(code*)(in_r9 + 4))(param_9, 1, 0, 1, 0xffffffff);
        param_1 = FUN_80006824((uint)param_9, SFXwp_mflop7_c);
        FUN_80006b0c((undefined*)piVar2);
        psVar4[1] = 1;
        *(undefined4*)(param_9 + 0x7c) = 1;
    }
    if (psVar4[1] != 0)
    {
        *psVar4 = *psVar4 - psVar4[1] * (ushort)DAT_803dc070;
    }
    uVar1 = FUN_80017ae8();
    if (((uVar1 & 0xff) != 0) && (*psVar4 < 1))
    {
        puVar3 = (undefined2*)FUN_80017830(0x38, 0xe);
        *(undefined4*)(puVar3 + 4) = *(undefined4*)(iVar5 + 8);
        *(undefined4*)(puVar3 + 6) = *(undefined4*)(iVar5 + 0xc);
        *(undefined4*)(puVar3 + 8) = *(undefined4*)(iVar5 + 0x10);
        *puVar3 = 0x11;
        *(undefined4*)(puVar3 + 10) = 0xffffffff;
        *(u8*)(puVar3 + 2) = *(u8*)(iVar5 + 4);
        *(u8*)((int)puVar3 + 5) = *(u8*)(iVar5 + 5);
        *(u8*)(puVar3 + 3) = *(u8*)(iVar5 + 6);
        *(u8*)((int)puVar3 + 7) = *(u8*)(iVar5 + 7);
        *(u8*)((int)puVar3 + 0x27) = 3;
        *(u8*)(puVar3 + 0x14) = 0;
        puVar3[0xc] = psVar4[2] + (short)*(char*)(iVar5 + 0x1f);
        puVar3[0x18] = 0xffff;
        *(char*)(puVar3 + 0x15) = (char)((ushort) * param_9 >> 8);
        *(u8*)((int)puVar3 + 0x2b) = 2;
        puVar3[0x10] = 0;
        puVar3[0xf] = 0;
        puVar3[0x11] = 0xffff;
        *(u8*)((int)puVar3 + 0x29) = 0xff;
        *(u8*)(puVar3 + 0x17) = 0xff;
        puVar3[0x12] = 0;
        puVar3[0x16] = 0;
        puVar3[0x1a] = 0xffff;
        puVar3[0xd] = 0;
        *(char*)(puVar3 + 0x19) = (char)psVar4[4];
        iVar5 = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, puVar3, 5,
                             *(u8*)(param_9 + 0x56), 0xffffffff, *(uint**)(param_9 + 0x18), in_r8,
                             in_r9, in_r10);
        if (iVar5 != 0)
        {
            *(u8*)(*(int*)(iVar5 + 0xb8) + 0x404) = 0x20;
        }
        *psVar4 = 100;
        psVar4[1] = 0;
    }
    return;
}


/* Trivial 4b 0-arg blr leaves. */
void ecsh_shrine_release(void);

void ecsh_shrine_initialise(void);

void ecsh_creator_free(void)
{
}

void ecsh_creator_hitDetect(void)
{
}

void ecsh_creator_release(void)
{
}

void ecsh_creator_initialise(void)
{
}

void gpsh_shrine_hitDetect(void);

/* 8b "li r3, N; blr" returners. */
int ecsh_creator_getExtraSize(void) { return 0xa; }
int ecsh_creator_getObjectTypeId(void) { return 0x0; }
int gpsh_shrine_getExtraSize(void);

extern void ModelLightStruct_free(void* light);



/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4FF8;

void ecsh_creator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32); /* #57 */
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4FF8);
}

void ecsh_creator_init(s16* obj, s8* def)
{
    s16* inner = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x1e] << 8);
    ((GameObject*)obj)->unkF8 = 0;
    inner[0] = 100;
    inner[1] = 0;
    *(u8*)((char*)obj + 0x37) = 0xff;
    ((GameObject*)obj)->anim.alpha = 0xff;
    inner[2] = *(s16*)(def + 0x18);
    inner[4] = 2;
    inner[4] += (u8)def[0x20];
}

extern int objCreateLight(int a, int b);
extern int lbl_803DDBC0;



void ecsh_shrine_init(s16* obj, s8* def);

extern u8* mmAlloc(int size, int tag, int p);
extern int Obj_SetupObject(u8* def, int a, int b, int c, int d);
extern u8 Obj_IsLoadingLocked(void);
extern u8 framesThisStep;

void ecsh_creator_update(s16* obj)
{
    u8* def;
    s16* sub;
    void* res;
    u8* p;
    int ret;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    sub = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->unkF8 == 0 && (u32)GameBit_Get(sub[2]) != 0)
    {
        res = Resource_Acquire(0x82, 1);
        (*(void (**)(s16*, int, int, int, int, int))(*(int*)res + 4))(obj, 0, 0, 1, -1, 0);
        (*(void (**)(s16*, int, int, int, int, int))(*(int*)res + 4))(obj, 1, 0, 1, -1, 0);
        Sfx_PlayFromObject(obj, 0x16d);
        Resource_Release(res);
        sub[1] = 1;
        ((GameObject*)obj)->unkF8 = 1;
    }
    if (sub[1] != 0)
    {
        *sub = *sub - sub[1] * framesThisStep;
    }
    if (Obj_IsLoadingLocked() != 0 && *sub <= 0)
    {
        p = mmAlloc(0x38, 0xe, 0);
        *(f32*)(p + 8) = ((ObjPlacement*)def)->posX;
        *(f32*)(p + 0xc) = ((ObjPlacement*)def)->posY;
        *(f32*)(p + 0x10) = ((ObjPlacement*)def)->posZ;
        *(s16*)p = 0x11;
        *(int*)(p + 0x14) = -1;
        p[4] = def[4];
        p[5] = def[5];
        p[6] = def[6];
        p[7] = def[7];
        p[0x27] = 3;
        p[0x28] = 0;
        *(s16*)(p + 0x18) = sub[2] + *(s8*)(def + 0x1f);
        *(s16*)(p + 0x30) = -1;
        *(s8*)(p + 0x2a) = (s8)(*obj >> 8);
        p[0x2b] = 2;
        *(s16*)(p + 0x20) = 0;
        *(s16*)(p + 0x1e) = 0;
        *(s16*)(p + 0x22) = -1;
        p[0x29] = 0xff;
        *(s8*)(p + 0x2e) = -1;
        *(s16*)(p + 0x24) = 0;
        *(s16*)(p + 0x2c) = 0;
        *(u16*)(p + 0x34) = 0xFFFF;
        *(s16*)(p + 0x1a) = 0;
        *(u8*)(p + 0x32) = sub[4];
        ret = Obj_SetupObject(p, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, *(int*)&((GameObject*)obj)->anim.parent);
        if ((u32)ret != 0)
        {
            *(u8*)(*(int*)&((GameObject*)ret)->extra + 0x404) = 0x20;
        }
        *sub = 100;
        sub[1] = 0;
    }
}

extern f32 lbl_803E5000;
extern f32 mathSinf(f32 angle);

