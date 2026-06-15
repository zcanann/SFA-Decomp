/* DLL 0x0191 — ecshcreator (EarthWalker shrine object creator). TU: 0x801C6E0C–0x801C70F0. */
#include "main/game_object.h"
#include "main/dll/mmshrineanimobj_struct.h"
#include "main/objseq.h"

#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/resource.h"

extern void* FUN_80017aa4();
extern uint FUN_80017ae8();
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
extern u8* mmAlloc(int size, int tag, int p);
extern int Obj_SetupObject(u8* def, int a, int b, int c, int d);
extern u8 Obj_IsLoadingLocked(void);
extern u8 framesThisStep;

void FUN_801c5990(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9, int param_10)
{
    extern undefined4 FUN_80017ae4(); /* #57 */
    uint enabled;
    undefined2* fx;
    undefined4 child;
    int prevAnim;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    int state;
    double biasMagic;
    double baseScale;

    state = *(int*)&((GameObject*)param_9)->extra;
    *(undefined2*)(state + 0x6a) = *(undefined2*)(param_10 + 0x1a);
    *(undefined2*)(state + 0x6e) = 0xffff;
    biasMagic = DOUBLE_803e5c08;
    baseScale = (double)lbl_803E5C00;
    *(float*)(state + 0x24) =
        (float)(baseScale / (double)(float)(baseScale + (double)(float)((double)CONCAT44(0x43300000,
            (uint) * (byte*)(
                param_10 + 0x24)) - DOUBLE_803e5c08)));
    *(undefined4*)(state + 0x28) = 0xffffffff;
    prevAnim = ((GameObject*)param_9)->unkF4;
    if ((prevAnim == 0) && (*(short*)(param_10 + 0x18) != 1))
    {
        (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)param_10);
        ((GameObject*)param_9)->unkF4 = *(short*)(param_10 + 0x18) + 1;
    }
    else if ((prevAnim != 0) && ((int)*(short*)(param_10 + 0x18) != prevAnim + -1))
    {
        (*gObjectTriggerInterface)->freeState((u8*)state);
        if (*(short*)(param_10 + 0x18) != -1)
        {
            (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)param_10);
        }
        ((GameObject*)param_9)->unkF4 = *(short*)(param_10 + 0x18) + 1;
    }
    enabled = FUN_80017ae8();
    if ((enabled & 0xff) != 0)
    {
        fx = FUN_80017aa4(0x24, 0x1b8);
        *(undefined4*)(fx + 4) = *(undefined4*)&((GameObject*)param_9)->anim.localPosX;
        *(undefined4*)(fx + 6) = *(undefined4*)&((GameObject*)param_9)->anim.localPosY;
        *(undefined4*)(fx + 8) = *(undefined4*)&((GameObject*)param_9)->anim.localPosZ;
        *(undefined*)(fx + 2) = 0x20;
        *(undefined*)((int)fx + 5) = 4;
        *(undefined*)((int)fx + 7) = 0xff;
        child = FUN_80017ae4(biasMagic, baseScale, param_3, param_4, param_5, param_6, param_7, param_8, fx, 5, 0xff,
                             0xffffffff, (uint*)0x0, in_r8, in_r9, in_r10);
        *(undefined4*)&((GameObject*)param_9)->childObjs[0] = child;
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
    uint enabled;
    int* res;
    undefined2* spawn;
    undefined4 in_r8;
    int in_r9;
    undefined4 in_r10;
    short* state;
    int def;

    def = *(int*)(param_9 + 0x26);
    state = *(short**)(param_9 + 0x5c);
    if ((*(int*)(param_9 + 0x7c) == '\0') && (enabled = FUN_80017690((int)state[2]), enabled != 0))
    {
        res = (int*)FUN_80006b14(0x82);
        (*(code*)(*res + 4))(param_9, 0, 0, 1, 0xffffffff, 0);
        in_r8 = 0;
        in_r9 = *res;
        (*(code*)(in_r9 + 4))(param_9, 1, 0, 1, 0xffffffff);
        param_1 = FUN_80006824((uint)param_9, SFXwp_mflop7_c);
        FUN_80006b0c((undefined*)res);
        state[1] = 1;
        *(undefined4*)(param_9 + 0x7c) = 1;
    }
    if (state[1] != 0)
    {
        *state = *state - state[1] * (ushort)DAT_803dc070;
    }
    enabled = FUN_80017ae8();
    if (((enabled & 0xff) != 0) && (*state < 1))
    {
        spawn = (undefined2*)FUN_80017830(0x38, 0xe);
        *(undefined4*)(spawn + 4) = *(undefined4*)(def + 8);
        *(undefined4*)(spawn + 6) = *(undefined4*)(def + 0xc);
        *(undefined4*)(spawn + 8) = *(undefined4*)(def + 0x10);
        *spawn = 0x11;
        *(undefined4*)(spawn + 10) = 0xffffffff;
        *(u8*)(spawn + 2) = *(u8*)(def + 4);
        *(u8*)((int)spawn + 5) = *(u8*)(def + 5);
        *(u8*)(spawn + 3) = *(u8*)(def + 6);
        *(u8*)((int)spawn + 7) = *(u8*)(def + 7);
        *(u8*)((int)spawn + 0x27) = 3;
        *(u8*)(spawn + 0x14) = 0;
        spawn[0xc] = state[2] + (short)*(char*)(def + 0x1f);
        spawn[0x18] = 0xffff;
        *(char*)(spawn + 0x15) = (char)((ushort) * param_9 >> 8);
        *(u8*)((int)spawn + 0x2b) = 2;
        spawn[0x10] = 0;
        spawn[0xf] = 0;
        spawn[0x11] = 0xffff;
        *(u8*)((int)spawn + 0x29) = 0xff;
        *(u8*)(spawn + 0x17) = 0xff;
        spawn[0x12] = 0;
        spawn[0x16] = 0;
        spawn[0x1a] = 0xffff;
        spawn[0xd] = 0;
        *(char*)(spawn + 0x19) = (char)state[4];
        def = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, spawn, 5,
                             *(u8*)(param_9 + 0x56), 0xffffffff, *(uint**)(param_9 + 0x18), in_r8,
                             in_r9, in_r10);
        if (def != 0)
        {
            *(u8*)(*(int*)(def + 0xb8) + 0x404) = 0x20;
        }
        *state = 100;
        state[1] = 0;
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
