#include "main/objanim.h"
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/moveLib.h"

typedef struct Dll19State {
    f32 unk0;
    f32 unk4;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    f32 unk14;
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    u8 pad24[0x30 - 0x24];
    u32 unk30;
    u8 pad34[0x8C - 0x34];
    f32 unk8C;
    u8 pad90[0x94 - 0x90];
    f32 unk94;
    u8 pad98[0x261 - 0x98];
    u8 unk261;
    u8 pad262[0x298 - 0x262];
    f32 unk298;
    u8 pad29C[0x2B8 - 0x29C];
    f32 unk2B8;
    u8 pad2BC[0x334 - 0x2BC];
    s16 unk334;
    u8 pad336[0x3F4 - 0x336];
    s16 unk3F4;
    u8 pad3F6[0x400 - 0x3F6];
    u16 flags400;
    u8 pad402[0x405 - 0x402];
    u8 unk405;
    u8 pad406[0x5F8 - 0x406];
    s32 unk5F8;
    s32 unk5FC;
    u8 unk600;
    u8 unk601;
    u8 pad602[0x604 - 0x602];
    s32 unk604;
    s32 unk608;
    s16 unk60C;
    s16 unk60E;
    u8 unk610;
    u8 unk611;
    u8 pad612[0x614 - 0x612];
    f32 unk614;
    s32 unk618;
    u8 pad61C[0x620 - 0x61C];
} Dll19State;


extern undefined4 FUN_80003494();
extern undefined4 FUN_800068f4();
extern int FUN_80006a10();
extern double FUN_80006a30();
extern char FUN_80006a64();
extern undefined8 FUN_80006a68();
extern undefined4 GameBit_Set(int eventId, int value);
extern uint FUN_80017730();
extern int FUN_80017738();
extern undefined4 FUN_80017744();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017a88();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_8002f6ac();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern int ObjGroup_FindNearestObjectToPoint();
extern undefined4 ObjPath_GetPointWorldPosition();
extern void* FUN_80039518();
extern undefined4 FUN_8003964c();
extern undefined4 FUN_8003a9c8();
extern undefined4 FUN_8003ac24();
extern undefined8 FUN_8003ad08();
extern undefined4 FUN_800620e8();
extern int FUN_800632e8();
extern undefined4 FUN_8006f7a0();
extern int objAnimFn_80115650();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803de254;
extern f64 DOUBLE_803e28b0;
extern f64 DOUBLE_803e2918;
extern f64 DOUBLE_803e2928;
extern f32 lbl_803DC074;
extern f32 lbl_803DE250;
extern f32 lbl_803E28AC;
extern f32 lbl_803E28C0;
extern f32 lbl_803E28C8;
extern f32 lbl_803E28DC;
extern f32 lbl_803E28E8;
extern f32 lbl_803E28EC;
extern f32 lbl_803E28F0;
extern f32 lbl_803E28F4;
extern f32 lbl_803E28F8;
extern f32 lbl_803E28FC;
extern f32 lbl_803E2908;
extern f32 lbl_803E290C;
extern f32 lbl_803E2910;
extern f32 lbl_803E2920;
extern f32 lbl_803E2924;
extern f32 lbl_803E2930;
extern f32 lbl_803E2934;
extern f32 lbl_803E2938;
extern f32 lbl_803E2944;
extern f32 lbl_803E2948;
extern f32 lbl_803E294C;

/*
 * --INFO--
 *
 * Function: dll_19_func0F
 * EN v1.0 Address: 0x80113504
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x80113590
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dll_19_func0F(int obj, char *state, char *st, int p4, int p5, s16 p6)
{
    extern int *gPlayerInterface;
    extern f32 lbl_803DD5D8;
    extern s8 lbl_803DD5DC;
    extern f32 lbl_803E1C2C;
    extern f32 lbl_803E1C70;
    extern f32 lbl_803E1C74;
    extern f32 lbl_803E1C6C;
    extern f32 lbl_803E1C5C;
    extern f32 timeDelta;
    extern f32 sqrtf(f32 x);
    extern u8 framesThisStep;
    f32 dist;
    f32 nx;
    f32 nz;
    char *t;

    *(int *)&((BaddieState *)st)->unk318 = 0;
    *(int *)&((BaddieState *)st)->unk31C = 0;
    ((BaddieState *)st)->bool330 = 0;
    {
        f32 rest = lbl_803E1C2C;
        ((BaddieState *)st)->unk290 = rest;
        ((BaddieState *)st)->unk28C = rest;
    }
    if ((s8)*(u8 *)(state + 0x56) != 1) {
        *(f32 *)(state + 0x40) = ((GameObject *)obj)->anim.localPosX;
        *(f32 *)(state + 0x44) = ((GameObject *)obj)->anim.localPosY;
        *(f32 *)(state + 0x48) = ((GameObject *)obj)->anim.localPosZ;
        lbl_803DD5D8 = lbl_803E1C70;
        lbl_803DD5DC = 0;
    }
    *(s16 *)(state + 0x6e) = 0;
    *(u8 *)(state + 0x56) = 1;
    {
        f32 ex = *(f32 *)(state + 0x40) - ((GameObject *)obj)->anim.localPosX;
        f32 ez = *(f32 *)(state + 0x48) - ((GameObject *)obj)->anim.localPosZ;
        dist = sqrtf(ex * ex + ez * ez);
    }
    t = *(char **)&((BaddieState *)st)->targetObj;
    if (t == NULL) {
        return 0;
    }
    nx = *(f32 *)(t + 0xc) - *(f32 *)(state + 0x40);
    nz = *(f32 *)(t + 0x14) - *(f32 *)(state + 0x48);
    {
        f32 total = sqrtf(nx * nx + nz * nz);
        f32 step = timeDelta * (total - dist) * lbl_803E1C74;
        f32 td;
        if (step > lbl_803E1C6C) {
            step = lbl_803E1C6C;
        } else if (step < lbl_803E1C5C) {
            step = lbl_803E1C5C;
        }
        if (dist <= lbl_803DD5D8) {
            lbl_803DD5DC = lbl_803DD5DC + 1;
        }
        if (dist >= total || (s8)lbl_803DD5DC > 9) {
            char *t2 = *(char **)&((BaddieState *)st)->targetObj;
            int delta = ((GameObject *)obj)->anim.rotX - (u16)*(s16 *)t2;
            if (delta > 0x8000) {
                delta -= 0xffff;
            }
            if (delta < -0x8000) {
                delta += 0xffff;
            }
            if (delta > 0x2000) {
                delta = 0x2000;
            }
            if (delta < -0x2000) {
                delta = -0x2000;
            }
            ((GameObject *)obj)->anim.rotX -= (s16)((delta * framesThisStep) >> 3);
            if ((s8)lbl_803DD5DC > 10) {
                delta = 0;
            }
            if (delta < 0x100 && delta > -0x100) {
                *(u8 *)(state + 0x56) = 0;
                *(s16 *)(state + 0x5a) = (s16)(*(s16 *)(state + 0x58) - 1);
            } else {
                td = timeDelta;
                (*(void (**)(int, char *, f32, f32, int, int))(*gPlayerInterface + 0x8))(
                    obj, st, td, td, p4, p5);
            }
        } else {
            nx = nx / total;
            nz = nz / total;
            ((BaddieState *)st)->unk290 = -nx * step;
            ((BaddieState *)st)->unk28C = nz * step;
            ((GameObject *)obj)->anim.localPosX = dist * nx + *(f32 *)(state + 0x40);
            ((GameObject *)obj)->anim.localPosZ = dist * nz + *(f32 *)(state + 0x48);
            td = timeDelta;
            (*(void (**)(int, char *, f32, f32, int, int))(*gPlayerInterface + 0x8))(
                obj, st, td, td, p4, p5);
        }
    }
    lbl_803DD5D8 = dist;
    if ((s8)*(u8 *)(state + 0x56) == 0) {
        *(u8 *)(st + 0x405) = 0;
        ((BaddieState *)st)->controlMode = p6;
        *(int *)&((BaddieState *)st)->targetObj = 0;
        *(s16 *)(state + 0x6e) = -1;
        *(s16 *)(state + 0x6e) = *(s16 *)(state + 0x6e) & ~0x60;
        ((BaddieState *)st)->bool25F = 0;
        GameBit_Set(*(s16 *)(st + 0x3f4), 0);
    }
    return 1;
}


/*
 * --INFO--
 *
 * Function: FUN_801135c0
 * EN v1.0 Address: 0x801135C0
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x80113634
 * EN v1.1 Size: 364b
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
 * Function: FUN_801141dc
 * EN v1.0 Address: 0x801141DC
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80114230
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801141e8
 * EN v1.0 Address: 0x801141E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80114238
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801141e8(int param_1,wchar_t *param_2,wchar_t *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801141ec
 * EN v1.0 Address: 0x801141EC
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801142B4
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


extern f32 Curve_EvalHermite(f32 *points, f32 t, int unused);
extern f32 sqrtf(f32 x);
extern f64 lbl_803E1C98;

#pragma scheduling off
#pragma peephole off
f32 fn_80114224(int p1, int p2, int p3, int p4, int n)
{
    extern f32 lbl_803E1C90;
    f32 prev_x, prev_y, prev_z;
    f32 cur_x, cur_y, cur_z;
    f32 dx, dy, dz;
    f32 total;
    f32 t;
    f32 buf[4];
    int i;

    prev_x = *(f32*)(p1 + 0);
    prev_y = *(f32*)(p1 + 4);
    prev_z = *(f32*)(p1 + 8);
    total = lbl_803E1C90;

    for (i = 1; i < n + 1; i++) {
        t = (f32)i / (f32)n;

        buf[0] = *(f32*)(p1 + 0);
        buf[1] = *(f32*)(p3 + 0);
        buf[2] = *(f32*)(p2 + 0);
        buf[3] = *(f32*)(p4 + 0);
        cur_x = Curve_EvalHermite(buf, t, 0);
        dx = cur_x - prev_x;

        buf[0] = *(f32*)(p1 + 4);
        buf[1] = *(f32*)(p3 + 4);
        buf[2] = *(f32*)(p2 + 4);
        buf[3] = *(f32*)(p4 + 4);
        cur_y = Curve_EvalHermite(buf, t, 0);
        dy = cur_y - prev_y;

        buf[0] = *(f32*)(p1 + 8);
        buf[1] = *(f32*)(p3 + 8);
        buf[2] = *(f32*)(p2 + 8);
        buf[3] = *(f32*)(p4 + 8);
        cur_z = Curve_EvalHermite(buf, t, 0);
        dz = cur_z - prev_z;

        total += sqrtf(dx * dx + dy * dy + dz * dz);
        prev_x = cur_x;
        prev_y = cur_y;
        prev_z = cur_z;
    }

    return total;
}

int fn_80114408(int p1, int p2, int p3, int p4, f32 p5)
{
  extern void vecRotateYXZ(int, int);
  extern f32 fn_80114224(int, int, int, int, int);
  extern u8 framesThisStep;
  extern f32 lbl_803E1C90;
  extern f32 lbl_803E1CA0;
  extern f32 lbl_803E1CA4;
  int ret = 0;

  if ((void *)p2 != NULL) {
    s16 tmp[3];
    f32 vb;
    ((BaddieState *)p3)->posY = lbl_803E1CA0;
    vb = lbl_803E1C90;
    ((BaddieState *)p3)->posZ = vb;
    *(f32 *)(p3 + 0x20) = vb;
    *(f32 *)(p3 + 0x24) = vb;
    *(f32 *)(p3 + 0x28) = vb;
    *(f32 *)(p3 + 0x2c) = vb;
    vecRotateYXZ(p1, p3 + 0x18);
    tmp[2] = 0;
    tmp[1] = (s16)(s8)*(u8 *)(p2 + 0x2d);
    tmp[0] = (s16)(s8)*(u8 *)(p2 + 0x2c);
    vecRotateYXZ((int)tmp, p3 + 0x24);
    *(f32 *)p4 = lbl_803E1C90;
    *(f32 *)(p3 + 0x34) = fn_80114224(p3, p3 + 0x18, p3 + 0xc, p3 + 0x24, 10);
  } else {
    *(f32 *)p4 = *(f32 *)p4 + p5 * (f32)(u32)framesThisStep / *(f32 *)(p3 + 0x34);
    if (*(f32 *)p4 >= lbl_803E1CA4) {
      ret = 1;
      *(f32 *)p4 = lbl_803E1CA4;
    }
  }

  {
    f32 buf[4];
    buf[0] = *(f32 *)(p3 + 0x00);
    buf[1] = *(f32 *)(p3 + 0x0c);
    buf[2] = ((BaddieState *)p3)->posY;
    buf[3] = *(f32 *)(p3 + 0x24);
    *(f32 *)(p1 + 0x0c) = Curve_EvalHermite(buf, *(f32 *)p4, 0);
    buf[0] = *(f32 *)(p3 + 0x04);
    buf[1] = *(f32 *)(p3 + 0x10);
    buf[2] = ((BaddieState *)p3)->posZ;
    buf[3] = *(f32 *)(p3 + 0x28);
    *(f32 *)(p1 + 0x10) = Curve_EvalHermite(buf, *(f32 *)p4, 0);
    buf[0] = *(f32 *)(p3 + 0x08);
    buf[1] = ((BaddieState *)p3)->posX;
    buf[2] = *(f32 *)(p3 + 0x20);
    buf[3] = *(f32 *)(p3 + 0x2c);
    *(f32 *)(p1 + 0x14) = Curve_EvalHermite(buf, *(f32 *)p4, 0);
  }
  return ret;
}

/*
 * --INFO--
 *
 * Function: FUN_801143e8
 * EN v1.0 Address: 0x801143E8
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x801144C0
 * EN v1.1 Size: 484b
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
 * Function: FUN_801145a8
 * EN v1.0 Address: 0x801145A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801146A4
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801145b0
 * EN v1.0 Address: 0x801145B0
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x80114A58
 * EN v1.1 Size: 864b
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
 * Function: FUN_801149b8
 * EN v1.0 Address: 0x801149B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80114E4C
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void FUN_801149b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,float *param_11,short param_12,
                 undefined2 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801149bc
 * EN v1.0 Address: 0x801149BC
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x80115088
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_801149bc(short *param_1,int param_2,int param_3)
{
  float fVar1;
  float fVar2;
  uint *puVar3;
  ushort local_38;
  short local_36;
  short local_34;
  float local_30;
  undefined4 local_2c;
  float local_28;
  float local_24;
  undefined4 uStack_20;
  float local_1c [4];
  
  if (*(char *)(param_2 + 0x601) != '\0') {
    puVar3 = FUN_80039518();
    FUN_8003ac24((int)param_1,puVar3,(uint)*(byte *)(param_2 + 0x610));
    ObjPath_GetPointWorldPosition(param_1,param_3,&local_30,&local_2c,&local_28,0);
    ObjPath_GetPointWorldPosition(param_1,param_3 + 1,&local_24,&uStack_20,local_1c,0);
    fVar2 = lbl_803E294C;
    fVar1 = lbl_803E2948;
    *(float *)(param_2 + 4) = (lbl_803E2948 * local_30 + local_24) * lbl_803E294C;
    *(undefined4 *)(param_2 + 8) = local_2c;
    *(float *)(param_2 + 0xc) = (fVar1 * local_28 + local_1c[0]) * fVar2;
    *(float *)(param_2 + 4) = *(float *)(param_2 + 4) - *(float *)(param_1 + 6);
    *(float *)(param_2 + 8) = *(float *)(param_2 + 8) - *(float *)(param_1 + 8);
    *(float *)(param_2 + 0xc) = *(float *)(param_2 + 0xc) - *(float *)(param_1 + 10);
    local_38 = -param_1[2];
    local_36 = -param_1[1];
    local_34 = -*param_1;
    FUN_80017748(&local_38,(float *)(param_2 + 4));
    *(undefined *)(param_2 + 0x601) = 0;
  }
  ObjPath_GetPointWorldPosition(param_1,param_3,&local_30,&local_2c,&local_28,0);
  *(float *)(param_2 + 0x10) = local_30;
  *(undefined4 *)(param_2 + 0x14) = local_2c;
  *(float *)(param_2 + 0x18) = local_28;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80114b10
 * EN v1.0 Address: 0x80114B10
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80115200
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80114b10(int param_1,undefined4 *param_2,undefined2 param_3,undefined2 param_4,int param_5)
{
  float fVar1;
  uint *puVar2;
  
  *(undefined2 *)(param_2 + 0x183) = param_3;
  *(undefined2 *)((int)param_2 + 0x60e) = param_4;
  *(char *)(param_2 + 0x184) = (char)param_5;
  param_2[0x17f] = 0;
  fVar1 = lbl_803E2910;
  *param_2 = lbl_803E2910;
  param_2[0x17e] = 0;
  param_2[0x181] = 0;
  param_2[0x182] = 0;
  param_2[0x185] = lbl_803E290C;
  *(undefined *)(param_2 + 0x180) = 0;
  *(undefined *)((int)param_2 + 0x601) = 1;
  param_2[1] = fVar1;
  param_2[2] = fVar1;
  param_2[3] = fVar1;
  param_2[0x186] = 0xffffffff;
  puVar2 = FUN_80039518();
  FUN_8003ac24(param_1,puVar2,param_5);
  puVar2 = FUN_80039518();
  FUN_8003ad08(param_1,puVar2,param_5,(int)(param_2 + 7));
  FUN_8003a9c8((int)(param_2 + 7),(uint)*(byte *)(param_2 + 0x184),0,0);
  FUN_80003494((uint)(param_2 + 0x16f),0x8031ad30,(uint)*(byte *)(param_2 + 0x184) << 1);
  FUN_80003494((int)param_2 + 0x5da,0x8031ad30,(uint)*(byte *)(param_2 + 0x184) << 1);
  return;
}


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void dll_19_func04_nop(void) {}
void dll_19_func03_nop(void) {}

/* 8b "li r3, N; blr" returners. */
int dll_19_func09_ret_0(void) { return 0x0; }
int dll_2E_func0F_ret_0(void) { return 0x0; }

/* 12b chained getters. */
f32 dll_19_func0B(int *obj) { return *(f32*)((char*)((int**)obj)[0xb8/4] + 0x3e4); }

/* misc 8b leaves */
void fn_80113F94(int *p, f32 v) { *(f32*)((char*)p + 0x614) = v; }
void dll_2E_func04(int *p, int v) { *(int*)((char*)p + 0x608) = v; }

void dll_2E_func08(int obj, int v1, int v2) {
    *(int *)(obj + 0x618) = v1;
    *(int *)(obj + 0x61c) = v2;
    *(int *)(obj + 0x620) = v1;
}

u16 dll_19_func0A(int obj) {
    void *p = ((GameObject *)obj)->anim.placementData;
    if (p != NULL) return *(u16 *)((char *)p + 0x34);
    return 0xd2;
}

extern void *memcpy(void *dst, const void *src, u32 n);
extern u8 lbl_8031A0E0[];
void dll_2E_func09(int obj, void *src1, void *src2) {
    if (src1 == NULL) src1 = lbl_8031A0E0;
    if (src2 == NULL) src2 = lbl_8031A0E0;
    memcpy((char *)obj + 0x5bc, src1, (u32)*(u8 *)(obj + 0x610) * 2);
    memcpy((char *)obj + 0x5da, src2, (u32)*(u8 *)(obj + 0x610) * 2);
}

extern f32 lbl_803E1C88;
f32 dll_2E_func0B(int obj, int arg) {
    int r = ((int (*)(int))(*gRomCurveInterface)->slot40)(arg);
    if (r > -1) {
        return ((f32 (*)(int, int))(*gRomCurveInterface)->slot24)(obj, r);
    }
    return lbl_803E1C88;
}

extern void *seqFn_800394a0(void);
extern void objFn_8003acfc(int *obj, int *types, int count, char *out);
extern void fn_8003A9C0(char *p, int count, s16 a, s16 b);
void fn_80114B1C(int *obj) {
    char *state;
    int *types;

    types = (int *)seqFn_800394a0();
    state = ((GameObject *)obj)->extra;

    (*gCameraInterface)->setTarget(0);

    *(u8 *)(state + 0x600) = 0;
    objFn_8003acfc(obj, types, *(u8 *)(state + 0x610), state + 0x1c);
    *(int *)(state + 0x5f8) = 0x50;
    fn_8003A9C0(state + 0x1c, *(u8 *)(state + 0x610), 0, 0);
}

/* EN v1.0 0x80114184  size: 160b  Copies a curve point's position and packed
 * angle into the caller's record. */
int dll_2E_func0A(int idx, char *out)
{
    int r;

    if (idx >= 0x1c) {
        return 0;
    }
    r = ((int (*)(int))(*gRomCurveInterface)->slot40)(idx);
    if (r > -1) {
        char *p = (char *)(*gRomCurveInterface)->getById(r);
        *(f32 *)(out + 0xc) = *(f32 *)(p + 0x8);
        *(f32 *)(out + 0x10) = *(f32 *)(p + 0xc);
        *(f32 *)(out + 0x14) = *(f32 *)(p + 0x10);
        *(s16 *)(out + 0x0) = (s16)(*(s8 *)(p + 0x2c) << 8);
        return 1;
    }
    return 0;
}

extern s16 atan2i(int x, int z);
extern f32 lbl_803E1C8C;

/* EN v1.0 0x80114084  size: 256b  Copies a curve point's position into the
 * caller's record and aims its angle at the nearest group-8 object (falling
 * back to the point's packed angle). */
int dll_2E_func0C(int idx, char *out)
{
    f32 range;
    int r;

    range = lbl_803E1C8C;
    r = ((int (*)(int))(*gRomCurveInterface)->slot40)(idx);
    if (r > -1) {
        char *p = (char *)(*gRomCurveInterface)->getById(r);
        char *q;
        *(f32 *)(out + 0xc) = *(f32 *)(p + 0x8);
        *(f32 *)(out + 0x10) = *(f32 *)(p + 0xc);
        *(f32 *)(out + 0x14) = *(f32 *)(p + 0x10);
        q = (char *)ObjGroup_FindNearestObjectToPoint(8, out + 0xc, &range);
        if (q != NULL) {
            *(s16 *)(out + 0x0) = (s16)atan2i((int)(*(f32 *)(q + 0xc) - *(f32 *)(out + 0xc)),
                                         (int)(*(f32 *)(q + 0x14) - *(f32 *)(out + 0x14)));
        } else {
            *(s16 *)(out + 0x0) = (s16)(*(s8 *)(p + 0x2c) << 8);
        }
        return 1;
    }
    return 0;
}

extern f32 timeDelta;
extern f32 lbl_803E1C78;
extern f32 lbl_803E1C2C;
extern f32 lbl_803E1C7C;

/* EN v1.0 0x80113864  size: 248b  Steps the movement blend factors toward the
 * current target and turns the yaw by the buffered turn rate. */
void dll_19_func06(s16 *yaw, char *st, f32 cap, f32 speed)
{
    if (*(f32 *)(st + 0x298) < lbl_803E1C78) {
        f32 rest;
        *(s16 *)(st + 0x334) = 0;
        ((BaddieState *)st)->unk336 = 0;
        rest = lbl_803E1C2C;
        *(f32 *)(st + 0x298) = rest;
        ((BaddieState *)st)->animSpeedA = rest;
    }
    ((BaddieState *)st)->animSpeedB = lbl_803E1C2C;
    *yaw = lbl_803E1C7C * ((f32)((BaddieState *)st)->unk336 * timeDelta / speed) + (f32)*yaw;
    ((BaddieState *)st)->unk294 +=
        timeDelta * ((*(f32 *)(st + 0x298) - ((BaddieState *)st)->unk294) / *(f32 *)(st + 0x2b8));
    ((BaddieState *)st)->animSpeedA +=
        timeDelta * ((*(f32 *)(st + 0x298) - ((BaddieState *)st)->animSpeedA) / *(f32 *)(st + 0x2b8));
    if (((BaddieState *)st)->unk294 > cap) {
        ((BaddieState *)st)->unk294 = cap;
    }
    if (((BaddieState *)st)->animSpeedA > cap) {
        ((BaddieState *)st)->animSpeedA = cap;
    }
}

extern void fn_8003AC14(int obj, void *types, int count);
extern f32 lbl_803E1C90;

/* EN v1.0 0x80114F64  size: 280b  Initializes the movement-state block and
 * primes the animation channel tables. */
void dll_2E_func05(int obj, char *st, s16 a, s16 b, int count)
{
    f32 z;

    *(s16 *)(st + 0x60c) = a;
    *(s16 *)(st + 0x60e) = b;
    *(u8 *)(st + 0x610) = (u8)count;
    *(int *)(st + 0x5fc) = 0;
    z = lbl_803E1C90;
    *(f32 *)(st + 0x0) = z;
    *(int *)(st + 0x5f8) = 0;
    *(int *)(st + 0x604) = 0;
    *(int *)(st + 0x608) = 0;
    *(f32 *)(st + 0x614) = lbl_803E1C8C;
    *(u8 *)(st + 0x600) = 0;
    *(u8 *)(st + 0x601) = 1;
    *(f32 *)(st + 0x4) = z;
    *(f32 *)(st + 0x8) = z;
    *(f32 *)(st + 0xc) = z;
    *(int *)(st + 0x618) = -1;
    fn_8003AC14(obj, seqFn_800394a0(), count);
    objFn_8003acfc((int *)obj, (int *)seqFn_800394a0(), count, st + 0x1c);
    fn_8003A9C0(st + 0x1c, *(u8 *)(st + 0x610), 0, 0);
    dll_2E_func09((int)st, lbl_8031A0E0, lbl_8031A0E0);
}

extern void vecRotateZXY(s16 *angles, f32 *vec);
extern f32 lbl_803E1CC8;
extern f32 lbl_803E1CCC;

/* EN v1.0 0x80114DEC  size: 376b  Latches the path-relative start offset on
 * first use and refreshes the current path point position. */
void dll_2E_func06(int obj, char *st, int point)
{
    struct {
        s16 ang[3];
        f32 x0, y0, z0, x1, y1, z1;
    } v;

    if (*(u8 *)(st + 0x601) != 0) {
        f32 cA;
        f32 cB;
        fn_8003AC14(obj, seqFn_800394a0(), *(u8 *)(st + 0x610));
        ObjPath_GetPointWorldPosition(obj, point, &v.x0, &v.y0, &v.z0, 0);
        ObjPath_GetPointWorldPosition(obj, point + 1, &v.x1, &v.y1, &v.z1, 0);
        cA = lbl_803E1CC8;
        *(f32 *)(st + 0x4) = (cA * v.x0 + v.x1) * (cB = lbl_803E1CCC);
        *(f32 *)(st + 0x8) = v.y0;
        *(f32 *)(st + 0xc) = (cA * v.z0 + v.z1) * cB;
        *(f32 *)(st + 0x4) -= ((GameObject *)obj)->anim.localPosX;
        *(f32 *)(st + 0x8) -= ((GameObject *)obj)->anim.localPosY;
        *(f32 *)(st + 0xc) -= ((GameObject *)obj)->anim.localPosZ;
        v.ang[0] = (s16)-((GameObject *)obj)->anim.rotZ;
        v.ang[1] = (s16)-((GameObject *)obj)->anim.rotY;
        v.ang[2] = (s16)-((GameObject *)obj)->anim.rotX;
        vecRotateZXY(v.ang, (f32 *)(st + 0x4));
        *(u8 *)(st + 0x601) = 0;
    }
    ObjPath_GetPointWorldPosition(obj, point, &v.x0, &v.y0, &v.z0, 0);
    *(f32 *)(st + 0x10) = v.x0;
    *(f32 *)(st + 0x14) = v.y0;
    *(f32 *)(st + 0x18) = v.z0;
}

extern s16 getAngle(f32 x, f32 z);

/* EN v1.0 0x80113BD0  size: 396b  Computes the yaw step, signed yaw delta and
 * distance from an object to its target, updating the wide-turn flag. */
void dll_19_func07(int obj, int target, int div, u16 *outYaw, u16 *outDelta, u16 *outDist)
{
    char *st = ((GameObject *)obj)->extra;
    f32 d[3];
    f32 *dp = d;
    s16 *ovr;
    u16 ang;
    int cur;
    int delta;

    if ((void *)obj == NULL || (void *)target == NULL) {
        *outYaw = 0;
        *outDelta = 0;
        *outDist = 0;
    } else {
        dp[0] = *(f32 *)(target + 0x18) - ((GameObject *)obj)->anim.worldPosX;
        dp[1] = *(f32 *)(target + 0x1c) - ((GameObject *)obj)->anim.worldPosY;
        dp[2] = *(f32 *)(target + 0x20) - ((GameObject *)obj)->anim.worldPosZ;
        ang = getAngle(-dp[0], -dp[2]);
        ovr = *(s16 **)&((GameObject *)obj)->anim.parent;
        if (ovr != NULL) {
            cur = (s16)(((GameObject *)obj)->anim.rotX + *ovr);
        } else {
            cur = ((GameObject *)obj)->anim.rotX;
        }
        delta = ang - (u16)(s16)cur;
        if (delta > 0x8000) {
            delta -= 0xffff;
        }
        if (delta < -0x8000) {
            delta += 0xffff;
        }
        *outDelta = (u16)delta;
        if ((u16)delta < 0x31c4 || (u16)delta > 0xce3b) {
            ((Dll19State *)st)->flags400 &= ~0x10;
        } else {
            ((Dll19State *)st)->flags400 |= 0x10;
        }
        *outYaw = (u16)delta / (0x10000 / (u8)div);
        *outDist = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
    }
}

extern void voxmaps_worldToGrid(f32 *world, int *grid);
extern u8 voxmaps_traceLine(int *from, int *to, int a, u8 *outFlag, int b);
extern int objBboxFn_800640cc(void *pos, f32 *world, f32 rad, int a, void *out, int obj, int b,
                              int c, int d, int e);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern const f32 lbl_803E1C68;
extern const f32 lbl_803E1C80;
extern const f32 lbl_803E1C84;
extern f32 lbl_803E1C48;

/* EN v1.0 0x80113D64  size: 544b  Probes the four compass directions around
 * the object for walkable space, returning a bitmask of clear directions. */
u8 dll_19_func08(int obj, char *st, f32 dist)
{
    u16 i;
    u8 mask;
    u8 hitFlag;
    int grid1[2];
    int grid0[2];
    f32 world[3];
    u8 bboxOut[0x54];
    int cur;
    s16 *ovr;
    u8 ok;
    f32 a;

    mask = 0;
    world[0] = ((GameObject *)obj)->anim.localPosX;
    world[1] = lbl_803E1C68 + ((GameObject *)obj)->anim.localPosY;
    world[2] = ((GameObject *)obj)->anim.localPosZ;
    voxmaps_worldToGrid(world, grid0);
    ovr = *(s16 **)&((GameObject *)obj)->anim.parent;
    if (ovr != NULL) {
        cur = (s16)(((GameObject *)obj)->anim.rotX + *ovr);
    } else {
        cur = ((GameObject *)obj)->anim.rotX;
    }
    for (i = 0; i < 4; i++) {
        a = lbl_803E1C80 * (f32)((s16)cur + (i << 14)) / lbl_803E1C84;
        world[0] = ((GameObject *)obj)->anim.localPosX - dist * mathSinf(a);
        world[1] = lbl_803E1C68 + ((GameObject *)obj)->anim.localPosY;
        world[2] = ((GameObject *)obj)->anim.localPosZ - dist * mathCosf(a);
        voxmaps_worldToGrid(world, grid1);
        if (((GameObject *)obj)->anim.parent != NULL) {
            ok = 1;
        } else {
            ok = (u8)voxmaps_traceLine(grid1, grid0, 0, &hitFlag, 0);
            if (hitFlag == 1) {
                ok = 1;
            }
        }
        if (ok != 0) {
            if (objBboxFn_800640cc((char *)(obj + 0xc), world, lbl_803E1C48, 0, bboxOut, obj,
                                   *(u8 *)(st + 0x261), -1, 0, 0) != 0) {
                ok = 0;
            }
        }
        mask |= ok << i;
    }
    return mask;
}

extern int Curve_AdvanceAlongPath(int curve);
extern int hitDetectFn_800658a4(int obj, f32 x, f32 y, f32 z, f32 *out, int flag);
extern f32 lbl_803E1CB0;

/* EN v1.0 0x801145BC  size: 512b  Advances the object along its movement
 * curve, snapping to ground and easing the yaw toward the path direction. */
int dll_2E_func0E(int obj, int curve, f32 phase, int p4, int c, f32 *d, int *flags)
{
    int moved;
    int hit;
    f32 ground;
    int fl;
    int args[2];

    moved = 1;
    hit = 0;
    ground = lbl_803E1C90;
    fl = *flags;
    if (fl & 0x10) {
        return 1;
    }
    if (fl & 0x4) {
        if (fn_80114408(obj, 0, p4, p4 + 0x30, phase) != 0) {
            args[0] = 0x19;
            args[1] = 0x15;
            (*gRomCurveInterface)->initCurve((void *)curve, (void *)obj, lbl_803E1CB0,
                                             args, (u8)c);
            *flags |= 8;
            moved = 1;
        }
    } else {
        hit = 0;
        if (Curve_AdvanceAlongPath(curve) != 0 || *(int *)(curve + 0x10) != 0) {
            hit = (*gRomCurveInterface)->goNextPoint((void *)curve);
        }
        ((GameObject *)obj)->anim.localPosX = *(f32 *)(curve + 0x68);
        ((GameObject *)obj)->anim.localPosY = *(f32 *)(curve + 0x6c);
        ((GameObject *)obj)->anim.localPosZ = *(f32 *)(curve + 0x70);
        if (hit != 0) {
            *flags |= 0x10;
        }
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(obj, phase, d);
    if (*flags & 1) {
        if (hitDetectFn_800658a4(obj, ((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY,
                                 ((GameObject *)obj)->anim.localPosZ, &ground, 0) == 0) {
            ((GameObject *)obj)->anim.localPosY -= ground;
        }
    }
    if (moved != 0 && (*flags & 0x2) != 0) {
        int t = (s16)(getAngle(((GameObject *)obj)->anim.localPosX - ((GameObject *)obj)->anim.previousLocalPosX,
                               ((GameObject *)obj)->anim.localPosZ - ((GameObject *)obj)->anim.previousLocalPosZ) +
                      0x8000);
        ((GameObject *)obj)->anim.rotX =
            (s16)(((GameObject *)obj)->anim.rotX + ((t - ((GameObject *)obj)->anim.rotX) >> 3));
    }
    return hit;
}

extern int Obj_GetPlayerObject(void);
extern s16 *objModelGetVecFn_800395d8(int obj, int idx);
extern u8 framesThisStep;
extern f32 lbl_803E1CC4;

/* EN v1.0 0x80114BB0  size: 572b  Object-sequence scripted-move step: phase 4
 * arms the move, phase 5 walks the setup/playback sub-phases. */
int dll_2E_func07(int obj, char *state, char *st, s16 a, s16 b)
{
    s16 pair[2];
    int mode;
    int player;

    player = Obj_GetPlayerObject();
    pair[0] = a;
    pair[1] = b;
    {
        char *p = *(char **)&((GameObject *)obj)->anim.hitReactState;
        *(s16 *)(p + 0x60) = *(s16 *)(p + 0x60) | 1;
    }
    mode = (s8)*(u8 *)(state + 0x56);
    if (mode == 4) {
        *(int *)(st + 0x5f8) = 0x50;
        *(s16 *)(state + 0x6e) = *(s16 *)(state + 0x6e) & ~8;
        *(s16 *)(state + 0x6e) = *(s16 *)(state + 0x6e) & ~2;
        *(u8 *)(st + 0x600) = 3;
        *(u8 *)(state + 0x56) = 5;
        if ((*(u8 *)(st + 0x611) & 2) == 0) {
            *(s16 *)(state + 0x6e) = *(s16 *)(state + 0x6e) & ~4;
        }
        *(void (**)(int *))(state + 0xe8) = fn_80114B1C;
        return 0;
    } else if (mode == 5) {
        if (*(u8 *)(st + 0x600) >= 2 && *(u8 *)(st + 0x600) <= 7) {
            void *types = seqFn_800394a0();
            switch (*(u8 *)(st + 0x600)) {
            case 3:
                objFn_8003acfc((int *)obj, (int *)types, *(u8 *)(st + 0x610), st + 0x1c);
                *(int *)(st + 0x5f8) = 0;
                *(u8 *)(st + 0x600) = 2;
            case 2:
                if (objAnimFn_80115650(obj, player, st + 0x5fc, st, st, pair, st + 0x10) == 0) {
                    *(u8 *)(st + 0x600) = 6;
                }
                break;
            case 6:
                *(u8 *)(st + 0x600) = 7;
            case 7:
                *(f32 *)(st + 0x0) = lbl_803E1CC4;
                break;
            }
            *(int *)(st + 0x604) = player;
            ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, *(f32 *)(st + 0x0), (f32)framesThisStep, NULL);
            if (*(u8 *)(st + 0x600) == 7) {
                s16 *v;
                *(s16 *)(state + 0x6e) = *(s16 *)(state + 0x6e) | 8;
                v = objModelGetVecFn_800395d8(obj, 0);
                if (v != NULL) {
                    *(s16 *)(state + 0x114) = v[1];
                    *(s16 *)(state + 0x116) = v[0];
                }
                *(u8 *)(st + 0x600) = 0;
                *(u8 *)(state + 0x56) = 0;
                *(s16 *)(state + 0x6e) = *(s16 *)(state + 0x6e) | 4;
                return 0;
            }
            return 0;
        }
    }
    return 0;
}

extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ,
                                           u32 obj);
extern f32 lbl_803E1C40;

/* EN v1.0 0x8011395C  size: 628b  Constrains a follow point against the
 * object's facing plane and returns the lateral offset of the result. */
f32 dll_19_func05(int obj, f32 px, f32 pz, f32 range, char *st)
{
    f32 dist;
    f32 fz;
    f32 fx;
    f32 c;
    f32 s;
    f32 dx;
    f32 dz;

    dx = *(f32 *)(st + 0x18) - px;
    dz = *(f32 *)(st + 0x20) - pz;
    dist = sqrtf(dx * dx + dz * dz);
    if (dist < range) {
        f32 base;
        f32 d1;
        f32 d2;
        c = mathSinf(lbl_803E1C80 * (f32)((GameObject *)obj)->anim.rotX / lbl_803E1C84);
        s = mathCosf(lbl_803E1C80 * (f32)((GameObject *)obj)->anim.rotX / lbl_803E1C84);
        base = -(c * (px - c) + s * (pz - s));
        d1 = base + (c * *(f32 *)(st + 0x18) + s * *(f32 *)(st + 0x20));
        d2 = base + (c * *(f32 *)(st + 0x8c) + s * *(f32 *)(st + 0x94));
        if (d1 > lbl_803E1C2C && d2 <= lbl_803E1C48) {
            *(f32 *)(st + 0x18) = *(f32 *)(st + 0x18) - c * d1;
            *(f32 *)(st + 0x20) = *(f32 *)(st + 0x20) - s * d1;
            Obj_TransformWorldPointToLocal(*(f32 *)(st + 0x18), *(f32 *)(st + 0x1c),
                                           *(f32 *)(st + 0x20), (f32 *)(st + 0xc),
                                           (f32 *)(st + 0x10), (f32 *)(st + 0x14),
                                           *(u32 *)(st + 0x30));
        } else if (d2 > lbl_803E1C48) {
            dist = lbl_803E1C40 * range;
        }
    }
    if (dist < range) {
        fx = *(f32 *)(st + 0x18);
        fz = *(f32 *)(st + 0x20);
    } else {
        fx = px;
        fz = pz;
    }
    c = mathSinf(lbl_803E1C80 * (f32)(((GameObject *)obj)->anim.rotX + 0x4000) / lbl_803E1C84);
    s = mathCosf(lbl_803E1C80 * (f32)(((GameObject *)obj)->anim.rotX + 0x4000) / lbl_803E1C84);
    return -(-(((GameObject *)obj)->anim.localPosX * c + ((GameObject *)obj)->anim.localPosZ * s) + (c * fx + s * fz));
}

extern void normalize(f32 *x, f32 *y, f32 *z);
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern f32 lbl_803E1CB4;
extern f32 lbl_803E1CB8;
extern f32 lbl_803E1CBC;
extern f32 lbl_803E1CC0;

/* EN v1.0 0x801147BC  size: 864b  Homes the object toward its target at the
 * given speed, snapping when close, easing yaw and pacing the walk anim. */
int dll_2E_func0D(int obj, int target, f32 speed, int move, f32 *out, u8 *flags)
{
    f32 ground;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 dist;
    s16 delta;

    if ((void *)target == NULL) {
        return 0;
    }
    dx = *(f32 *)(target + 0xc) - ((GameObject *)obj)->anim.localPosX;
    dy = *(f32 *)(target + 0x10) - ((GameObject *)obj)->anim.localPosY;
    dz = *(f32 *)(target + 0x14) - ((GameObject *)obj)->anim.localPosZ;
    dist = sqrtf(dz * dz + (dx * dx + dy * dy));
    if (dist < lbl_803E1CB4 * speed) {
        ((GameObject *)obj)->anim.localPosX = *(f32 *)(target + 0xc);
        ((GameObject *)obj)->anim.localPosY = *(f32 *)(target + 0x10);
        ((GameObject *)obj)->anim.localPosZ = *(f32 *)(target + 0x14);
        if (*flags & 1) {
            if (hitDetectFn_800658a4(obj, ((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY,
                                     ((GameObject *)obj)->anim.localPosZ, &ground, 0) == 0) {
                ((GameObject *)obj)->anim.localPosY -= ground;
            }
        }
        return 1;
    }
    normalize(&dx, &dy, &dz);
    ((GameObject *)obj)->anim.velocityX = dx * (speed * timeDelta);
    ((GameObject *)obj)->anim.velocityY = dy * (speed * timeDelta);
    ((GameObject *)obj)->anim.velocityZ = dz * (speed * timeDelta);
    if (*flags & 1) {
        if (hitDetectFn_800658a4(obj, ((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY,
                                 ((GameObject *)obj)->anim.localPosZ, &ground, 0) == 0) {
            ((GameObject *)obj)->anim.localPosY -= ground;
        }
    }
    if (*flags & 2) {
        delta = *(s16 *)(target + 0x0) - (u16)((GameObject *)obj)->anim.rotX;
        if (delta > 0x8000) {
            delta = delta - 0xffff;
        }
        if (delta < -0x8000) {
            delta = delta + 0xffff;
        }
        ((GameObject *)obj)->anim.rotX = (f32)((GameObject *)obj)->anim.rotX +
                              (lbl_803E1CB8 + (f32)delta) * (speed * timeDelta) / dist;
    }
    objMove(obj, ((GameObject *)obj)->anim.velocityX, ((GameObject *)obj)->anim.velocityY, ((GameObject *)obj)->anim.velocityZ);
    if (move != -1) {
        if (((GameObject *)obj)->anim.currentMove != move) {
            ObjAnim_SetCurrentMove(obj, move, lbl_803E1C90, 0);
        }
        delta = ((GameObject *)obj)->anim.rotX - (u16)(s16)getAngle(dx, dz);
        if (delta > 0x8000) {
            delta = delta - 0xffff;
        }
        if (delta < -0x8000) {
            delta = delta + 0xffff;
        }
        speed = speed * -mathCosf(lbl_803E1CBC * (f32)delta / lbl_803E1CC0);
        ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(obj, speed, out);
    }
    return 0;
}
