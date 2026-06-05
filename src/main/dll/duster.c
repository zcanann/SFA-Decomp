#include "ghidra_import.h"
#include "main/dll/duster.h"
#include "main/objanim.h"

#define SFXen_blkscrp6 0x22
#define SFXwatery_bubble2 0x244
#define SFXfox_fightbreath1 0x24b
#define SFXfox_fightbreath2 0x24c
#define SFXfox_fightbreath3 0x24d
#define SFXfox_fightbreath4 0x24e
#define SFXfox_roll1 0x24f
#define SFXfox_roll2 0x250
#define SFXfox_roll3 0x251
#define SFXfox_roll4 0x252
#define SFXfox_runbreath1 0x253
#define SFXfox_runbreath2 0x254
#define SFXfox_climbgrunt1 0x258
#define SFXfox_climbgrunt2 0x259
#define SFXfox_cough3 0x260
#define SFXfox_cough4 0x261
#define SFXfoxcom_decoy 0x262

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on

extern int Sfx_PlayFromObject(u32 obj, int sfxId);
extern int FUN_80006a10();
extern int getAngle(f32 dx, f32 dz);
extern uint randomGetRange();
extern undefined4 fn_80017A88();
extern void* Obj_AllocObjectSetup();
extern int Obj_SetupObject();
extern uint Obj_IsLoadingLocked();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern void ObjHits_DisableObject(int);
extern void ObjHits_EnableObject(int);
extern void fn_80292E20(uint, float *, float *);
extern u8 objBboxFn_800640cc();
extern double sidekickToy_accelerateTowardTargetXZ(double, double, double, double, double, double, double, int);
extern void fn_8014CD1C(double, double, void *, int, int, char);
extern void fn_8014D08C(int, int, int, float, int, int);
extern void fn_80154D0C(int, int, ushort *, float *);
extern uint fn_80154FB4(double, short *, int, uint);
extern int fn_80169EF4(f32 speed, f32 arc, float *src, float *dst, char flag);
extern undefined4 PSVECSubtract();
extern undefined4 PSVECNormalize();
extern double PSVECDotProduct();
extern undefined4 PSVECCrossProduct();
extern void fn_80293018(int angle, float *outSin, float *outCos);
extern double fn_80293900();
extern uint fn_80295CBC();

extern undefined4 lbl_8031F2F8;
extern undefined4 lbl_8031F318;
extern undefined4 lbl_8031F320;
extern undefined4 lbl_803DC940;
extern undefined4* gSHthorntailAnimationInterface;
extern undefined4* lbl_803DD71C;
extern f64 DOUBLE_803e36a8;
extern f64 DOUBLE_803e36b0;
extern f64 DOUBLE_803e3700;
extern f64 DOUBLE_803e3738;
extern f32 timeDelta;
extern f32 lbl_803E2A00;
extern f32 lbl_803E2A04;
extern f32 lbl_803E2A08;
extern f32 lbl_803E2A20;
extern f32 lbl_803E2A24;
extern f32 lbl_803E2A28;
extern f32 lbl_803E2A2C;
extern f32 lbl_803E2A30;
extern f32 lbl_803E2A34;
extern f32 lbl_803E2A38;
extern f32 lbl_803E2A3C;
extern f32 lbl_803E2A40;
extern f32 lbl_803E2A48;
extern f32 lbl_803E2A4C;
extern f32 lbl_803E2A50;
extern f32 lbl_803E2A54;
extern f32 lbl_803E2A58;
extern f32 lbl_803E2A60;
extern f32 lbl_803E2A70;
extern f32 lbl_803E2A74;
extern f32 lbl_803E2A78;
extern f32 lbl_803E2A7C;
extern f32 lbl_803E2A80;
extern f32 lbl_803E2B18;
extern f32 lbl_803E2A5C;
extern f32 lbl_803E2A84;
extern f32 lbl_803E2A88;
extern f32 lbl_803E2A8C;
extern f32 lbl_803E2A90;
extern f32 lbl_803E2A98;
extern f32 lbl_803E2AA8;
extern f32 lbl_803E2AAC;
extern f32 lbl_803E2AB0;
extern f32 lbl_803E2AB4;
extern f32 lbl_803E2AB8;
extern f32 lbl_803E2ABC;
extern f32 lbl_803E2AC0;
extern f32 lbl_803E2AC4;
extern f32 lbl_803E2AC8;
extern f32 lbl_803E2ACC;
extern f32 lbl_803E2AD0;
extern f32 lbl_803E2AD4;
extern f32 lbl_803E2AD8;
extern f32 lbl_803E2ADC;
extern f32 lbl_803E2AE0;
extern f32 lbl_803E2AE4;
extern f32 lbl_803E2AE8;
extern f32 lbl_803E2AEC;
extern f32 lbl_803E2AF0;
extern f32 lbl_803E2AF4;
extern f32 lbl_803E2AF8;
extern f32 lbl_803E2AFC;
extern f32 lbl_803E2B00;
extern f32 lbl_803E2B04;
extern f32 lbl_803DBCEC;


/*
 * --INFO--
 *
 * Function: fn_8015536C
 * EN v1.0 Address: 0x801556D4
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x80155818
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8015536C(float param_1,float param_2,float *param_3,float *param_4)
{
  float hi;
  float lo;
  float local_2c[3];
  float local_38[3];

  hi = param_4[6] - lbl_803E2A20;
  if (param_2 > hi) {
    param_2 = hi;
  } else {
    lo = lbl_803E2A24 + param_4[5];
    if (param_2 < lo) {
      param_2 = lo;
    }
  }
  if (param_4[4] > lbl_803E2A00) {
    hi = param_4[4] - lbl_803E2A20;
    lo = lbl_803E2A20;
  } else {
    hi = lbl_803E2A28;
    lo = lbl_803E2A20 + param_4[4];
  }
  if (param_1 > hi) {
    param_1 = hi;
  } else {
    if (param_1 < lo) {
      param_1 = lo;
    }
  }
  param_3[1] = param_2;
  local_38[0] = lbl_803E2A00;
  local_38[1] = lbl_803E2A04;
  local_38[2] = lbl_803E2A00;
  PSVECCrossProduct(local_38,param_4,local_2c);
  PSVECNormalize(local_2c,local_2c);
  *param_3 = param_1 * local_2c[0] + param_4[7];
  param_3[2] = param_1 * local_2c[2] + param_4[8];
  *param_3 = lbl_803E2A2C * *param_4 + *param_3;
  param_3[1] = lbl_803E2A2C * param_4[1] + param_3[1];
  param_3[2] = lbl_803E2A2C * param_4[2] + param_3[2];
}

/*
 * --INFO--
 *
 * Function: fn_801554B4
 * EN v1.0 Address: 0x80155830
 * EN v1.0 Size: 728b
 * EN v1.1 Address: 0x80155960
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801554B4(int *param_1,int param_2)
{
  u8 cVar3;
  int iVar4;
  float *pfVar5;
  double dVar6;
  float dv[3];
  float local_c4 [3];
  float bv[3];
  float afStack_ac [3];
  float av[3];
  float cv[3];
  float afStack_88 [3];
  float minv[3];
  float maxv[3];
  int iStack_64;
  undefined4 local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  float local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  float local_28;
  float local_24;
  float local_20;
  
  cVar3 = 0;
  pfVar5 = (float *)&lbl_8031F2F8;
  for (iVar4 = 0; cVar3 == 0 && iVar4 < 4; iVar4 = iVar4 + 1) {
    maxv[0] = *(float *)(param_1 + 3) + *pfVar5;
    maxv[1] = *(float *)(param_1 + 4);
    maxv[2] = *(float *)(param_1 + 5) + pfVar5[1];
    minv[0] = *(float *)(param_1 + 3) - *pfVar5;
    minv[1] = *(float *)(param_1 + 4);
    minv[2] = *(float *)(param_1 + 5) - pfVar5[1];
    cVar3 = objBboxFn_800640cc(maxv,minv,(float *)0x3,&iStack_64,param_1,5,3,0xff,0);
    pfVar5 = pfVar5 + 2;
  }
  if (cVar3 != '\0') {
    *(float *)(param_1 + 3) = (local_20 - lbl_803E2A20) * ((minv[0] - maxv[0]) / lbl_803E2A24) +
                      maxv[0];
    *(float *)(param_1 + 5) = (local_20 - lbl_803E2A20) * ((minv[2] - maxv[2]) / lbl_803E2A24) +
                      maxv[2];
    *(undefined4 *)(param_2 + 0x344) = local_48;
    *(undefined4 *)(param_2 + 0x348) = local_44;
    *(undefined4 *)(param_2 + 0x34c) = local_40;
    *(undefined4 *)(param_2 + 0x350) = local_3c;
    if (local_54 < local_58) {
      local_54 = local_58;
    }
    *(float *)(param_2 + 0x358) = local_54;
    if (local_28 < local_24) {
      local_24 = local_28;
    }
    *(float *)(param_2 + 0x35c) = local_24;
    av[0] = lbl_803E2A00;
    av[1] = lbl_803E2A04;
    av[2] = lbl_803E2A00;
    PSVECCrossProduct(av,(float *)(param_2 + 0x344),afStack_88);
    PSVECNormalize(afStack_88,afStack_88);
    *(undefined4 *)(param_2 + 0x360) = local_60;
    *(undefined4 *)(param_2 + 0x364) = local_50;
    cv[0] = local_5c;
    cv[2] = local_4c;
    bv[0] = *(float *)(param_2 + 0x360);
    bv[1] = *(float *)(param_2 + 0x358);
    bv[2] = *(float *)(param_2 + 0x364);
    PSVECSubtract(bv,cv,afStack_ac);
    dVar6 = PSVECDotProduct(afStack_ac,(float *)(param_2 + 0x344));
    bv[0] = (float)((double)*(float *)(param_2 + 0x344) * dVar6 + (double)cv[0]);
    bv[1] = (float)((double)*(float *)(param_2 + 0x348) * dVar6 + (double)cv[1]);
    bv[2] = (float)((double)*(float *)(param_2 + 0x34c) * dVar6 + (double)cv[2]);
    dv[0] = lbl_803E2A00;
    dv[1] = lbl_803E2A04;
    dv[2] = lbl_803E2A00;
    PSVECCrossProduct(dv,(float *)(param_2 + 0x344),local_c4);
    PSVECNormalize(local_c4,local_c4);
    if (lbl_803E2A00 == local_c4[0]) {
      *(float *)(param_2 + 0x354) = (cv[2] - *(float *)(param_2 + 0x364)) / local_c4[2];
    }
    else {
      *(float *)(param_2 + 0x354) = (cv[0] - *(float *)(param_2 + 0x360)) / local_c4[0];
    }
    *(undefined *)(param_2 + 0x33a) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: rachnopUpdateWhileFrozen
 * EN v1.0 Address: 0x80155B08
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80155C1C
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void rachnopUpdateWhileFrozen(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
  }
  else if (param_4 != 0x11) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
    Sfx_PlayFromObject(param_1,SFXfox_runbreath2);
    *(undefined2 *)(param_2 + 0x2b0) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_801557D4
 * EN v1.0 Address: 0x80155B6C
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x80155C80
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801557D4(int *param_9,int param_10)
{
  int iVar1;

  if (*(byte *)(param_10 + 0x33a) == 0) {
    fn_801554B4(param_9,param_10);
  }
  else {
    if ((*(short *)(*(int *)(param_10 + 0x29c) + 0x44) == 1) &&
       (iVar1 = (int)fn_80295CBC(*(int *)(param_10 + 0x29c)), iVar1 != 0)) {
      *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) & ~0x10000;
    }
    if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
      Sfx_PlayFromObject((uint)param_9,SFXfox_runbreath1);
      fn_8014D08C((int)param_9,param_10,2,lbl_803E2A04,0,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80155884
 * EN v1.0 Address: 0x80155CAC
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x80155D30
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80155884(int *param_9,int param_10)
{
  int iVar1;

  if (*(byte *)(param_10 + 0x33a) == 0) {
    fn_801554B4(param_9,param_10);
  }
  else if ((*(short *)(*(int *)(param_10 + 0x29c) + 0x44) == 1) &&
          (iVar1 = (int)fn_80295CBC(*(int *)(param_10 + 0x29c)), iVar1 != 0)) {
    fn_80154FB4((double)lbl_803E2A30,(short *)param_9,param_10,0x19);
    if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
      fn_8014D08C((int)param_9,param_10,0,lbl_803E2A30,0,0);
      Sfx_PlayFromObject((uint)param_9,SFXfox_roll4);
    }
  }
  else {
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80155948
 * EN v1.0 Address: 0x80155E00
 * EN v1.0 Size: 572b
 * EN v1.1 Address: 0x80155DF4
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80155948(int *param_9,int param_10)
{
  short sVar1;
  int iVar2;
  ushort local_18 [2];
  float afStack_14 [3];

  if (*(byte *)(param_10 + 0x33a) == 0) {
    fn_801554B4(param_9,param_10);
  }
  else if ((*(short *)(*(int *)(param_10 + 0x29c) + 0x44) == 1) &&
          (iVar2 = (int)fn_80295CBC(*(int *)(param_10 + 0x29c)), iVar2 != 0)) {
    ObjHits_SetHitVolumeSlot((int)param_9,10,1,0);
    sVar1 = *(short *)(param_9 + 0x28);
    if (sVar1 == 3) {
      fn_80154FB4((double)lbl_803E2A00,(short *)param_9,param_10,0x19);
    }
    else if ((sVar1 == 0) || (sVar1 == 1)) {
      fn_80154FB4((double)lbl_803E2A30,(short *)param_9,param_10,0x19);
    }
    fn_80154D0C((int)param_9,param_10,local_18,afStack_14);
    if (((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) ||
       ((local_18[0] < 0x5dc && (*(short *)(param_9 + 0x28) != 1)))) {
      if (local_18[0] < 0x5dc) {
        Sfx_PlayFromObject((uint)param_9,SFXfox_roll3);
        fn_8014D08C((int)param_9,param_10,1,lbl_803E2A30,0,0);
      }
      else {
        fn_8014D08C((int)param_9,param_10,3,lbl_803E2A30,0,0);
      }
    }
  }
  else {
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: rachnopInit
 * EN v1.0 Address: 0x8015603C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80155F58
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void rachnopInit(undefined4 param_1,int param_2)
{
  float fVar1;
  float fVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E2A34;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  fVar1 = lbl_803E2A38;
  *(float *)(param_2 + 0x308) = lbl_803E2A38;
  *(float *)(param_2 + 0x300) = fVar1;
  *(float *)(param_2 + 0x304) = lbl_803E2A3C;
  *(undefined *)(param_2 + 800) = 0;
  fVar2 = lbl_803E2A40;
  *(float *)(param_2 + 0x314) = lbl_803E2A40;
  *(undefined *)(param_2 + 0x321) = 4;
  fVar1 = lbl_803E2A04;
  *(float *)(param_2 + 0x318) = lbl_803E2A04;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar2;
  *(float *)(param_2 + 0x324) = lbl_803E2A00;
  *(undefined *)(param_2 + 0x33a) = 0;
  *(undefined *)(param_2 + 0x33b) = 0;
  *(float *)(param_2 + 0x2fc) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: pollenFn_80155b10
 * EN v1.0 Address: 0x801560A0
 * EN v1.0 Size: 628b
 * EN v1.1 Address: 0x80155FBC
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pollenFn_80155b10(uint param_9,int param_10)
{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  f32 spd;
  f32 t;
  f32 dx;
  f32 dz;
  f32 a[3];
  f32 b[3];
  float local_3c;
  float local_40;
  float local_44;
  float local_48;

  uVar1 = Obj_IsLoadingLocked();
  if ((uVar1 & 0xff) != 0) {
    a[0] = *(float *)(param_9 + 0xc);
    a[1] = lbl_803E2A48 + *(float *)(param_9 + 0x10);
    a[2] = *(float *)(param_9 + 0x14);
    iVar2 = *(int *)(param_10 + 0x29c);
    b[0] = *(float *)(iVar2 + 0xc);
    b[1] = lbl_803E2A4C + *(float *)(iVar2 + 0x10);
    b[2] = *(float *)(iVar2 + 0x14);
    spd = lbl_803E2A50 *
          (lbl_803E2A58 * (f32)(int)randomGetRange(-10, 10) + lbl_803E2A54);
    iVar2 = fn_80169EF4(spd, lbl_803E2A5C, a, b, 1);
    fn_80293018(iVar2, &local_40, &local_3c);
    local_3c = local_3c * spd;
    local_40 = local_40 * spd;
    dx = b[0] - *(float *)(param_9 + 0xc);
    dz = b[2] - *(float *)(param_9 + 0x14);
    if (lbl_803E2A60 != dz) {
      iVar2 = getAngle(dx, dz);
      fn_80293018(iVar2, &local_48, &local_44);
      t = local_3c;
      local_44 = local_44 * t;
      local_3c = t * local_48;
    }
    else {
      local_44 = lbl_803E2A60;
    }
    puVar3 = Obj_AllocObjectSetup(0x24,0x47b);
    *(float *)(puVar3 + 4) = a[0];
    *(float *)(puVar3 + 6) = a[1];
    *(undefined4 *)(puVar3 + 8) = a[2];
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)(puVar3 + 3) = 0xff;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    iVar2 = Obj_SetupObject(puVar3,5,-1,-1,0);
    if (iVar2 != 0) {
      *(float *)(iVar2 + 0x24) = local_3c;
      *(float *)(iVar2 + 0x28) = local_40;
      *(float *)(iVar2 + 0x2c) = local_44;
      *(uint *)(iVar2 + 0xc4) = param_9;
      Sfx_PlayFromObject(param_9,SFXfox_climbgrunt2);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: timeOfDayFn_80155cf8
 * EN v1.0 Address: 0x80156314
 * EN v1.0 Size: 472b
 * EN v1.1 Address: 0x801561A4
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void timeOfDayFn_80155cf8(int param_9,int param_10)
{
  byte bVar1;
  float local_18 [4];

  (*(code *)(*(int *)gSHthorntailAnimationInterface + 0x14))(local_18);
  if ((local_18[0] >= lbl_803E2A70) && (local_18[0] <= lbl_803E2A74)) {
    bVar1 = 1;
  }
  else {
    bVar1 = 0;
  }
  if ((bVar1 != 0) && (*(byte *)(param_10 + 0x33a) == 0)) {
    *(undefined *)(param_10 + 0x33a) = 1;
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    fn_8014D08C(param_9,param_10,1,lbl_803E2A78,0,0);
  }
  else if ((bVar1 == 0) && (*(byte *)(param_10 + 0x33a) == 2)) {
    *(undefined *)(param_10 + 0x33a) = 1;
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    fn_8014D08C(param_9,param_10,3,lbl_803E2A78,0,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: baddieUpdateWhileFrozen_80155e10
 * EN v1.0 Address: 0x801564EC
 * EN v1.0 Size: 384b
 * EN v1.1 Address: 0x801562BC
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void baddieUpdateWhileFrozen_80155e10(uint param_9,int param_10,undefined4 param_11,int param_12,undefined4 param_13,int param_14)
{
  if (param_12 == 0x10) {
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x20;
  }
  else if (param_12 == 0x11) {
    if ((*(byte *)(param_10 + 0x33a) == 2) && (*(short *)(param_9 + 0xa0) != 5)) {
      fn_8014D08C(param_9,param_10,5,lbl_803E2A7C,0,0);
    }
  }
  else if ((*(short *)(param_9 + 0xa0) == 5) || (*(short *)(param_9 + 0xa0) == 4)) {
    if (param_14 > (int)(uint)*(ushort *)(param_10 + 0x2b0)) {
      *(undefined2 *)(param_10 + 0x2b0) = 0;
      Sfx_PlayFromObject(param_9,SFXfox_climbgrunt1);
      Sfx_PlayFromObject(param_9,SFXen_blkscrp6);
    }
    else {
      *(ushort *)(param_10 + 0x2b0) = *(ushort *)(param_10 + 0x2b0) - param_14;
      Sfx_PlayFromObject(param_9,SFXfox_roll1);
      Sfx_PlayFromObject(param_9,SFXen_blkscrp6);
    }
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 8;
  }
  else {
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x10;
    Sfx_PlayFromObject(param_9,SFXfox_roll2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80155F20
 * EN v1.0 Address: 0x8015666C
 * EN v1.0 Size: 780b
 * EN v1.1 Address: 0x801563CC
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80155F20(int param_9,int param_10)
{
  *(float *)(param_10 + 0x324) = lbl_803E2A60;
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    if (*(byte *)(param_10 + 0x33a) == 1) {
      if (*(short *)(param_9 + 0xa0) == 1) {
        *(undefined *)(param_10 + 0x33a) = 2;
        *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) & ~0x10000;
      }
      else if (*(short *)(param_9 + 0xa0) == 3) {
        *(undefined *)(param_10 + 0x33a) = 0;
        *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
        fn_8014D08C(param_9,param_10,0,lbl_803E2A54,0,0);
      }
    }
    else if ((*(byte *)(param_10 + 0x33a) == 2) && (*(short *)(param_9 + 0xa0) != 2)) {
      fn_8014D08C(param_9,param_10,2,lbl_803E2A54,0,0);
    }
  }
  timeOfDayFn_80155cf8(param_9,param_10);
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80156010
 * EN v1.0 Address: 0x80156978
 * EN v1.0 Size: 1132b
 * EN v1.1 Address: 0x801564BC
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80156010(uint param_9,int param_10)
{
  bool bVar1;
  short sVar2;
  double dVar3;
  
  bVar1 = false;
  *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - timeDelta;
  if (*(float *)(param_10 + 0x324) <= lbl_803E2A60) {
    bVar1 = true;
    *(float *)(param_10 + 0x324) = lbl_803E2A60;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    sVar2 = *(short *)(param_9 + 0xa0);
    if (sVar2 == 4) {
      pollenFn_80155b10(param_9,param_10);
      *(float *)(param_10 + 0x324) = lbl_803E2A80;
      fn_8014D08C(param_9,param_10,5,lbl_803E2A54,0,0);
    }
    else if ((sVar2 == 5) && (bVar1)) {
      fn_8014D08C(param_9,param_10,6,lbl_803E2A54,0,0);
      Sfx_PlayFromObject(param_9,SFXfox_fightbreath2);
    }
    else if (sVar2 == 6) {
      fn_8014D08C(param_9,param_10,2,lbl_803E2A54,0,0);
      *(float *)(param_10 + 0x324) = lbl_803E2A80;
    }
    else if (((sVar2 == 2) && (bVar1)) && ((*(uint *)(param_10 + 0x2dc) & 0x4000000) != 0)) {
      fn_8014D08C(param_9,param_10,4,lbl_803E2A54,0,0);
      dVar3 = (double)Sfx_PlayFromObject(param_9,SFXfox_fightbreath1);
    }
  }
  timeOfDayFn_80155cf8(param_9,param_10);
  return;
}

/*
 * --INFO--
 *
 * Function: baddieInit_80156188
 * EN v1.0 Address: 0x80156DE4
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80156634
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void baddieInit_80156188(undefined4 param_1,int param_2)
{
  float fVar1;
  float fVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E2A84;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(float *)(param_2 + 0x308) = lbl_803E2A58;
  *(float *)(param_2 + 0x300) = lbl_803E2A88;
  *(float *)(param_2 + 0x304) = lbl_803E2A8C;
  *(undefined *)(param_2 + 800) = 0;
  fVar2 = lbl_803E2A90;
  *(float *)(param_2 + 0x314) = lbl_803E2A90;
  *(undefined *)(param_2 + 0x321) = 7;
  fVar1 = lbl_803E2A54;
  *(float *)(param_2 + 0x318) = lbl_803E2A54;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar2;
  *(undefined *)(param_2 + 0x33a) = 0;
  *(float *)(param_2 + 0x324) = lbl_803E2A60;
  *(float *)(param_2 + 0x2fc) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: wbUpdateWhileFrozen
 * EN v1.0 Address: 0x80156E48
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80156698
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wbUpdateWhileFrozen(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if (param_4 != 0x11) {
    if (param_4 == 0x10) {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
    }
    else {
      Sfx_PlayFromObject(param_1,SFXfox_cough3);
      *(undefined2 *)(param_2 + 0x2b0) = 0;
      *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x20;
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8015625C
 * EN v1.0 Address: 0x80156EB8
 * EN v1.0 Size: 872b
 * EN v1.1 Address: 0x80156708
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8015625C(ushort *param_9,int param_10)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  
  if (*(float *)(param_10 + 0x328) > lbl_803E2AA8) {
    *(float *)(param_10 + 0x328) = lbl_803E2AAC;
  }
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x70) = 0;
  uVar4 = 0;
  ObjHits_SetHitVolumeSlot((int)param_9,10,1,0);
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    Sfx_PlayFromObject((uint)param_9,SFXfox_cough4);
  }
  *(float *)(param_10 + 0x328) = *(float *)(param_10 + 0x328) - timeDelta;
  if (*(float *)(param_10 + 0x328) <= lbl_803E2A98) {
    if ((*(uint *)(param_10 + 0x2dc) & 0x600) != 0) {
      uVar2 = randomGetRange(0x96,0xfa);
      *(float *)(param_10 + 0x328) =
           (float)(int)uVar2;
    }
    else {
      uVar2 = randomGetRange(600,0x352);
      *(float *)(param_10 + 0x328) =
           (float)(int)uVar2;
    }
    Sfx_PlayFromObject((uint)param_9,SFXfoxcom_decoy);
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    ObjAnim_SetCurrentMove((int)param_9,3,lbl_803E2A98,(uint)*(byte *)(param_10 + 0x323));
  }
  fVar1 = lbl_803E2A98;
  if (*(float *)(param_10 + 0x324) <= lbl_803E2A98) {
    if ((*(uint *)(param_10 + 0x2dc) & 0x400) != 0) {
      *(float *)(param_10 + 0x324) = lbl_803E2AB0;
    }
  }
  else {
    *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - timeDelta;
    if (*(float *)(param_10 + 0x324) <= fVar1) {
      *(float *)(param_10 + 0x324) = lbl_803E2AB0;
      *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    }
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x8000000) == 0) {
    iVar3 = *(int *)(param_10 + 0x29c);
    dVar5 = sidekickToy_accelerateTowardTargetXZ((double)*(float *)(iVar3 + 0x18),
                         (double)(lbl_803E2AB8 + *(float *)(iVar3 + 0x1c)),
                         (double)*(float *)(iVar3 + 0x20),(double)lbl_803E2ABC,
                         (double)lbl_803E2AC0,(double)lbl_803E2AC4,
                         (double)*(float *)(param_10 + 0x304),(int)param_9);
  }
  else {
    dVar5 = (double)lbl_803E2AB4;
  }
  if ((((double)lbl_803E2A98 < dVar5) && (*(float *)(param_9 + 0x14) < lbl_803E2AC8)) ||
     ((*(uint *)(param_10 + 0x2dc) & 0x8000000) != 0)) {
    *(undefined *)(param_10 + 0x33a) = 1;
  }
  if ((*(byte *)(param_10 + 0x33a) == 0) || (dVar5 <= (double)lbl_803E2A98)) {
    *(undefined *)(param_10 + 0x33a) = 0;
    if (*(float *)(param_10 + 0x308) > lbl_803E2ADC) {
      *(float *)(param_10 + 0x308) =
           -(lbl_803E2AE0 * timeDelta - *(float *)(param_10 + 0x308));
    }
  }
  else {
    *(float *)(param_10 + 0x308) = lbl_803E2ACC;
    if (*(short *)(param_10 + 0x2b0) != 0) {
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) + lbl_803E2AD0;
    }
    if (lbl_803E2AD4 <= *(float *)(param_9 + 0x14)) {
      if (*(float *)(param_9 + 0x14) > lbl_803E2AD8) {
        *(float *)(param_9 + 0x14) = lbl_803E2AD8;
      }
    }
    else {
      *(float *)(param_9 + 0x14) = lbl_803E2AD4;
    }
  }
  fn_8014CD1C((double)lbl_803E2A98,(double)lbl_803E2A98,param_9,param_10,0x2d,'\0');
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8015652C
 * EN v1.0 Address: 0x80157220
 * EN v1.0 Size: 1284b
 * EN v1.1 Address: 0x801569D8
 * EN v1.1 Size: 892b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8015652C(ushort *param_9,int param_10)
{
  uint uVar2;
  char cVar3;
  int iVar5;
  float *pfVar6;
  double dVar7;

  pfVar6 = *(float **)param_10;
  iVar5 = *(int *)(param_9 + 0x26);
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x70) = 0;
  ObjHits_SetHitVolumeSlot((int)param_9,10,1,0);
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    Sfx_PlayFromObject((uint)param_9,SFXfox_cough4);
  }
  *(float *)(param_10 + 0x328) = *(float *)(param_10 + 0x328) - timeDelta;
  if (*(float *)(param_10 + 0x328) <= lbl_803E2A98) {
    if ((*(uint *)(param_10 + 0x2dc) & 0x600) != 0) {
      uVar2 = randomGetRange(0x96,0xfa);
      *(float *)(param_10 + 0x328) = (float)(int)uVar2;
    }
    else {
      uVar2 = randomGetRange(600,0x352);
      *(float *)(param_10 + 0x328) = (float)(int)uVar2;
    }
    Sfx_PlayFromObject((uint)param_9,SFXfoxcom_decoy);
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    ObjAnim_SetCurrentMove((int)param_9,0,lbl_803E2A98,(uint)*(byte *)(param_10 + 0x323));
  }
  if (*(float *)(param_10 + 0x324) <= lbl_803E2A98) {
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) & 0xfffeffff;
  }
  else {
    *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - timeDelta;
    if (*(float *)(param_10 + 0x324) <= lbl_803E2A98) {
      *(float *)(param_10 + 0x324) = lbl_803E2A98;
    }
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x2000) == 0) {
    if ((*(uint *)(param_10 + 0x2dc) & 0x8000000) == 0) {
      dVar7 = sidekickToy_accelerateTowardTargetXZ((double)*(float *)(iVar5 + 8),(double)*(float *)(iVar5 + 0xc),
                           (double)*(float *)(iVar5 + 0x10),(double)lbl_803E2ABC,
                           (double)lbl_803E2AC0,(double)lbl_803E2AC4,
                           (double)*(float *)(param_10 + 0x304),(int)param_9);
    }
    else {
      dVar7 = (double)lbl_803E2ABC;
    }
  }
  else {
    iVar5 = FUN_80006a10((double)*(float *)(param_10 + 0x2fc),pfVar6);
    if ((((iVar5 != 0) || (pfVar6[4] != 0.0)) &&
        (cVar3 = (**(code **)(*lbl_803DD71C + 0x90))(pfVar6), cVar3 != '\0')) &&
       (cVar3 = (**(code **)(*lbl_803DD71C + 0x8c))
                          ((double)lbl_803E2AE4,*(int *)param_10,param_9,&lbl_803DC940,0xffffffff),
       cVar3 != '\0')) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xffffdfff;
    }
    if ((*(uint *)(param_10 + 0x2dc) & 0x8000000) == 0) {
      dVar7 = sidekickToy_accelerateTowardTargetXZ((double)pfVar6[0x1a],(double)pfVar6[0x1b],(double)pfVar6[0x1c],
                           (double)lbl_803E2ABC,(double)lbl_803E2AC0,(double)lbl_803E2AC4,
                           (double)*(float *)(param_10 + 0x304),(int)param_9);
    }
    else {
      dVar7 = (double)lbl_803E2ABC;
    }
  }
  if ((((double)lbl_803E2A98 < dVar7) && (*(float *)(param_9 + 0x14) < lbl_803E2AC8)) ||
     ((*(uint *)(param_10 + 0x2dc) & 0x8000000) != 0)) {
    *(undefined *)(param_10 + 0x33a) = 1;
  }
  if ((*(byte *)(param_10 + 0x33a) == 0) || (dVar7 <= (double)lbl_803E2A98)) {
    *(undefined *)(param_10 + 0x33a) = 0;
    if (*(float *)(param_10 + 0x308) > lbl_803E2ADC) {
      *(float *)(param_10 + 0x308) = -(lbl_803E2AE0 * timeDelta - *(float *)(param_10 + 0x308));
    }
  }
  else {
    *(float *)(param_10 + 0x308) = lbl_803E2ACC;
    if (*(short *)(param_10 + 0x2b0) != 0) {
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) + lbl_803E2AD0;
    }
    if (lbl_803E2AD4 <= *(float *)(param_9 + 0x14)) {
      if (*(float *)(param_9 + 0x14) > lbl_803E2AD8) {
        *(float *)(param_9 + 0x14) = lbl_803E2AD8;
      }
    }
    else {
      *(float *)(param_9 + 0x14) = lbl_803E2AD4;
    }
  }
  fn_8014CD1C((double)lbl_803E2A98,(double)lbl_803E2A98,param_9,param_10,0x2d,'\0');
  return;
}

/*
 * --INFO--
 *
 * Function: wbInit
 * EN v1.0 Address: 0x80157724
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x80156D54
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wbInit(undefined4 param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E2AE8;
  *(undefined4 *)(param_2 + 0x2e4) = 0x2002b029;
  *(float *)(param_2 + 0x308) = lbl_803E2ACC;
  *(float *)(param_2 + 0x300) = lbl_803E2AEC;
  *(float *)(param_2 + 0x304) = lbl_803E2AF0;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = lbl_803E2AF4;
  *(float *)(param_2 + 0x314) = lbl_803E2AF4;
  *(undefined *)(param_2 + 0x321) = 1;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 2;
  *(float *)(param_2 + 0x31c) = fVar1;
  uVar2 = randomGetRange(0x78,0x1e0);
  *(float *)(param_2 + 0x328) =
       (float)(int)uVar2;
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80156950
 * EN v1.0 Address: 0x801577C8
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x80156DFC
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80156950(uint param_1,int param_2)
{
  switch (*(short *)(param_1 + 0xa0)) {
  case 5:
    if (*(ushort *)(param_2 + 0x2f8) != 0) {
      Sfx_PlayFromObject(param_1,SFXfox_fightbreath3);
    }
    break;
  case 6:
    if (*(ushort *)(param_2 + 0x2f8) != 0) {
      Sfx_PlayFromObject(param_1,SFXfox_fightbreath3);
    }
    break;
  case 7:
    if (*(ushort *)(param_2 + 0x2f8) != 0) {
      if (*(float *)(param_1 + 0x98) >= lbl_803E2AF8) {
        Sfx_PlayFromObject(param_1,SFXfox_fightbreath2);
      }
      else {
        Sfx_PlayFromObject(param_1,SFXfox_fightbreath3);
      }
    }
    break;
  case 8:
    if (*(ushort *)(param_2 + 0x2f8) != 0) {
      if (*(float *)(param_1 + 0x98) >= lbl_803E2AFC) {
        if (*(float *)(param_1 + 0x98) >= lbl_803E2B00) {
          Sfx_PlayFromObject(param_1,SFXfox_fightbreath2);
        }
        else {
          Sfx_PlayFromObject(param_1,SFXfox_fightbreath4);
        }
      }
      else {
        Sfx_PlayFromObject(param_1,SFXfox_fightbreath1);
      }
    }
    break;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: mutatedEbaUpdateWhileFrozen
 * EN v1.0 Address: 0x801578C4
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x80156EF0
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void mutatedEbaUpdateWhileFrozen(uint param_9,int param_10,undefined4 param_11,int param_12)
{
  short sVar1;
  
  if (param_12 != 0x11) {
    if (param_12 == 0x10) {
      *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x20;
    }
    else {
      sVar1 = *(short *)(param_9 + 0xa0);
      if ((((sVar1 == 0) || (sVar1 == 1)) || (sVar1 == 3)) || (sVar1 == 4)) {
        Sfx_PlayFromObject(param_9,SFXfox_roll2);
        *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x10;
      }
      else {
        fn_8014D08C(param_9,param_10,4,lbl_803E2B04,0,0);
        *(undefined *)(param_10 + 0x33a) = 0;
        Sfx_PlayFromObject(param_9,SFXfox_roll1);
        *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 8;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80156B0C
 * EN v1.0 Address: 0x801579F4
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x80156FB8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80156B0C(uint param_9,int param_10)
{
  int iVar1;
  
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
  if (((*(uint *)(param_10 + 0x2dc) & 0x80000000) != 0) && (*(byte *)(param_10 + 0x33a) <= 1)) {
    *(undefined *)(param_10 + 0x33a) = 1;
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x40000000;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    *(byte *)(param_10 + 0x33a) = *(byte *)(param_10 + 0x33a) + 1;
    if (10 < *(byte *)(param_10 + 0x33a)) {
      *(undefined *)(param_10 + 0x33a) = 3;
    }
    if (*(ushort *)(param_10 + 0x2a0) < 4) {
      iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      fn_8014D08C(param_9,param_10,(uint)((byte *)&lbl_8031F318)[iVar1 + 8],
                   *(float *)((byte *)&lbl_8031F318 + iVar1),0,0);
    }
    else {
      iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      fn_8014D08C(param_9,param_10,(uint)((byte *)&lbl_8031F318)[iVar1 + 9],
                   *(float *)((byte *)&lbl_8031F318 + iVar1),0,0);
    }
  }
  fn_80156950(param_9,param_10);
  return;
}

/*
 * --INFO--
 * Function: fn_80156C34
 * EN v1.0 Address: 0x80156C34
 * EN v1.0 Size: 168b
 */
void fn_80156C34(uint param_9,int param_10)
{
  int iVar1;
  
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    if (*(byte *)(param_10 + 0x33a) == 0) {
      *(undefined *)(param_10 + 0x33a) = 1;
    }
    else if (*(byte *)(param_10 + 0x33a) >= 2) {
      *(undefined *)(param_10 + 0x33a) = 0;
    }
    iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
    fn_8014D08C(param_9,param_10,(uint)((byte *)&lbl_8031F318)[iVar1 + 8],
                 *(float *)((byte *)&lbl_8031F318 + iVar1),0,0);
  }
  fn_80156950(param_9,param_10);
  return;
}

/*
 * --INFO--
 * Function: mutatedEbaInit
 * EN v1.0 Address: 0x80156CDC
 * EN v1.0 Size: 104b
 */
void mutatedEbaInit(undefined4 param_1,int param_2)
{
  float fVar1;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E2A84;
  *(undefined4 *)(param_2 + 0x2e4) = 0x46001;
  *(float *)(param_2 + 0x308) = lbl_803E2A58;
  *(float *)(param_2 + 0x300) = lbl_803E2A88;
  *(float *)(param_2 + 0x304) = lbl_803E2A8C;
  *(undefined *)(param_2 + 0x320) = 0;
  fVar1 = lbl_803E2A54;
  *(float *)(param_2 + 0x314) = lbl_803E2A54;
  *(undefined *)(param_2 + 0x321) = 4;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 3;
  *(float *)(param_2 + 0x31c) = fVar1;
  *(undefined *)(param_2 + 0x33a) = 1;
  *(undefined2 *)(param_2 + 0x2b0) = 0xa;
  return;
}

/*
 * --INFO--
 * Function: hoodedZyckUpdateWhileFrozen
 * EN v1.0 Address: 0x80156D44
 * EN v1.0 Size: 92b
 */
void hoodedZyckUpdateWhileFrozen(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
  }
  else {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
    Sfx_PlayFromObject(param_1,SFXwatery_bubble2);
    *(undefined2 *)(param_2 + 0x2b0) = 0;
  }
  return;
}

/*
 * --INFO--
 * Function: fn_80156DA0
 * EN v1.0 Address: 0x80156DA0
 * EN v1.0 Size: 612b
 */
void fn_80156DA0(int param_9,int param_10)
{
  bool bVar1;
  int iVar2;
  ushort uVar3;
  float local_98 [3];
  float local_8c [3];
  float local_80;
  float local_7c;
  undefined4 local_70;

  *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - timeDelta;
  if (*(float *)(param_10 + 0x324) <= lbl_803E2A60) {
    *(float *)(param_10 + 0x324) = (float)(int)randomGetRange(0x3c,0x78);
  }
  if (lbl_803E2A60 != *(float *)(param_10 + 0x328)) {
    ObjHits_DisableObject(param_9);
    if (*(short *)(param_9 + 0xa0) != 5) {
      fn_8014D08C(param_9,param_10,5,lbl_803DBCEC,0,0);
    }
    else if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
      ObjHits_EnableObject(param_9);
      *(float *)(param_10 + 0x328) = lbl_803E2A60;
    }
    *(byte *)(param_9 + 0x36) = 0xff;
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  if (!bVar1) {
    *(short *)param_9 = (short)((short)*(short *)param_9 + (short)*(ushort *)(param_10 + 0x338));
    local_98[0] = *(float *)(param_9 + 0xc);
    local_98[1] = *(float *)(param_9 + 0x10);
    local_98[2] = *(float *)(param_9 + 0x14);
    fn_80292E20((uint)*(ushort *)param_9,&local_80,&local_7c);
    local_8c[0] = *(float *)(param_9 + 0xc) - lbl_803E2ABC * local_80;
    local_8c[1] = lbl_803E2AC0 + *(float *)(param_9 + 0x10);
    local_8c[2] = *(float *)(param_9 + 0x14) - lbl_803E2ABC * local_7c;
    local_70 = 0;
    iVar2 = objBboxFn_800640cc(local_98,local_8c,(float *)0x3,&local_70,param_9,
                         (uint)*(byte *)(param_10 + 0x261),0xff,0xffffffff,0);
    if (((iVar2 & 0xff) == 0) || ((*(uint *)(param_10 + 0x2dc) & 0x40000000) == 0)) {
      if ((iVar2 & 0xff) != 0) {
        if (*(short *)(param_9 + 0xa0) == 0) {
          *(undefined2 *)(param_10 + 0x338) = 0;
          fn_8014D08C(param_9,param_10,0,lbl_803E2AC8,0,1);
        }
        else {
          float fz;
          fn_8014D08C(param_9,param_10,1,lbl_803E2ACC,0,0);
          fz = lbl_803E2B18;
          *(float *)(param_9 + 0x24) = fz;
          *(float *)(param_9 + 0x28) = fz;
          *(float *)(param_9 + 0x2c) = fz;
          uVar3 = (ushort)randomGetRange(0,1);
          *(undefined2 *)(param_10 + 0x338) = (ushort)((uVar3 - 1) * 0x12c);
        }
      }
    }
    *(short *)(param_9 + 0x2) = *(short *)(param_10 + 0x19c);
    *(short *)(param_9 + 0x4) = *(short *)(param_10 + 0x19e);
  }
  return;
}
