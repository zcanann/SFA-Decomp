/* DLL 0x0191 — ecshcreator (EarthWalker shrine object creator). TU: 0x801C6E0C–0x801C70F0. */
#include "main/game_object.h"
#include "main/dll/mmshrineanimobj_struct.h"
#include "main/objseq.h"

#include "main/dll/mmshrine/ecsh_shrine_state.h"
#include "main/audio/sfx_ids.h"
#include "main/game_ui_interface.h"
#include "main/obj_placement.h"
#include "main/objanim.h"
#include "main/dll/mmshrine/shrine1C2.h"
#include "main/dll/mmshrine/torch1C1.h"
#include "main/resource.h"
#include "main/screen_transition.h"

extern void* FUN_80017aa4();
extern uint FUN_80017ae8();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f64 DOUBLE_803e5c08;
extern f32 lbl_803E5C00;
extern f32 lbl_803E5C10;

#pragma scheduling on
#pragma peephole on
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern undefined4 FUN_80017830();
extern undefined4 DAT_803dc070;
extern void Sfx_PlayFromObject(s16* obj, int sfxId);
extern int GameBit_Get(int bit);
extern f32 lbl_803E4FF8;
extern int objCreateLight(int a, int b);
extern u8* mmAlloc(int size, int tag, int p);
extern int Obj_SetupObject(u8* def, int a, int b, int c, int d);
extern u8 Obj_IsLoadingLocked(void);
extern u8 framesThisStep;
extern f32 lbl_803E5000;

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

void fn_801C5990(MmShrineAnimObj* obj);

/* segment pragma-stack balance (re-split): */

#pragma scheduling off
#pragma peephole off
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

void ecsh_shrine_release(void);

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

int ecsh_creator_getExtraSize(void) { return 0xa; }
int ecsh_creator_getObjectTypeId(void) { return 0x0; }
int gpsh_shrine_getExtraSize(void);

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
