#include "ghidra_import.h"
#include "main/dll/duster.h"

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on

extern int Sfx_PlayFromObject(u32 obj, int sfxId);
extern int FUN_80006a10();
extern int getAngle();
extern uint randomGetRange();
extern undefined4 fn_80017A88();
extern void* Obj_AllocObjectSetup();
extern int Obj_SetupObject();
extern uint Obj_IsLoadingLocked();
extern void ObjAnim_SetCurrentMove(uint obj, int mode, float val, uint flags);
extern undefined4 ObjHits_SetHitVolumeSlot();
extern void ObjHits_DisableObject(int);
extern void ObjHits_EnableObject(int);
extern void fn_80292E20(uint, float *, float *);
extern char objBboxFn_800640cc();
extern double fn_8014CB54(double, double, double, double, double, double, double, int);
extern void fn_8014CD1C(double, double, void *, int, int, char);
extern void fn_8014D08C(int, int, int, float, int, int);
extern void fn_80154D0C(int, int, ushort *, float *);
extern int fn_80154FB4(int, int, int, float);
extern int fn_80169EF4();
extern undefined4 PSVECSubtract();
extern undefined4 PSVECNormalize();
extern double PSVECDotProduct();
extern undefined4 PSVECCrossProduct();
extern undefined4 fn_80293018();
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
extern f32 lbl_803DC074;
extern f32 timeDelta;
extern f32 lbl_803E3698;
extern f32 lbl_803E369C;
extern f32 lbl_803E36A0;
extern f32 lbl_803E36B8;
extern f32 lbl_803E36BC;
extern f32 lbl_803E36C0;
extern f32 lbl_803E36C4;
extern f32 lbl_803E36C8;
extern f32 lbl_803E36CC;
extern f32 lbl_803E36D0;
extern f32 lbl_803E36D4;
extern f32 lbl_803E36D8;
extern f32 lbl_803E36E0;
extern f32 lbl_803E36E4;
extern f32 lbl_803E36E8;
extern f32 lbl_803E36EC;
extern f32 lbl_803E36F0;
extern f32 lbl_803E36F4;
extern f32 lbl_803E36F8;
extern f32 lbl_803E3708;
extern f32 lbl_803E370C;
extern f32 lbl_803E3710;
extern f32 lbl_803E3714;
extern f32 lbl_803E3718;
extern f32 lbl_803E371C;
extern f32 lbl_803E3720;
extern f32 lbl_803E3724;
extern f32 lbl_803E3728;
extern f32 lbl_803E3730;
extern f32 lbl_803E3740;
extern f32 lbl_803E3744;
extern f32 lbl_803E3748;
extern f32 lbl_803E374C;
extern f32 lbl_803E3750;
extern f32 lbl_803E3754;
extern f32 lbl_803E3758;
extern f32 lbl_803E375C;
extern f32 lbl_803E3760;
extern f32 lbl_803E3764;
extern f32 lbl_803E3768;
extern f32 lbl_803E376C;
extern f32 lbl_803E3770;
extern f32 lbl_803E3774;
extern f32 lbl_803E3778;
extern f32 lbl_803E377C;
extern f32 lbl_803E3780;
extern f32 lbl_803E3784;
extern f32 lbl_803E3788;
extern f32 lbl_803E378C;
extern f32 lbl_803E3790;
extern f32 lbl_803E3794;
extern f32 lbl_803E3798;
extern f32 lbl_803E379C;
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
void fn_8015536C(double param_1,double param_2,float *param_3,float *param_4)
{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  float local_38;
  float local_34;
  float local_30;
  float local_2c [2];
  float local_24;
  
  dVar2 = (double)(param_4[6] - lbl_803E36B8);
  if ((param_2 <= dVar2) && (dVar2 = param_2, param_2 < (double)(lbl_803E36BC + param_4[5]))) {
    dVar2 = (double)(lbl_803E36BC + param_4[5]);
  }
  dVar4 = (double)param_4[4];
  if (dVar4 <= (double)lbl_803E3698) {
    dVar3 = (double)(float)((double)lbl_803E36B8 + dVar4);
    fVar1 = lbl_803E36C0;
  }
  else {
    dVar3 = (double)lbl_803E36B8;
    fVar1 = (float)(dVar4 - dVar3);
  }
  dVar4 = (double)fVar1;
  if ((param_1 <= dVar4) && (dVar4 = param_1, param_1 < dVar3)) {
    dVar4 = dVar3;
  }
  param_3[1] = (float)dVar2;
  local_38 = lbl_803E3698;
  local_34 = lbl_803E369C;
  local_30 = lbl_803E3698;
  PSVECCrossProduct(&local_38,param_4,local_2c);
  PSVECNormalize(local_2c,local_2c);
  *param_3 = (float)(dVar4 * (double)local_2c[0] + (double)param_4[7]);
  param_3[2] = (float)(dVar4 * (double)local_24 + (double)param_4[8]);
  fVar1 = lbl_803E36C4;
  *param_3 = lbl_803E36C4 * *param_4 + *param_3;
  param_3[1] = fVar1 * param_4[1] + param_3[1];
  param_3[2] = fVar1 * param_4[2] + param_3[2];
  return;
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
  float fVar1;
  float fVar2;
  char cVar3;
  int iVar4;
  float *pfVar5;
  double dVar6;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4 [2];
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float afStack_ac [3];
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float afStack_88 [3];
  float local_7c;
  int local_78;
  float local_74;
  float local_70;
  int local_6c;
  float local_68;
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
  
  cVar3 = '\0';
  pfVar5 = (float *)&lbl_8031F2F8;
  for (iVar4 = 0; (fVar2 = lbl_803E36BC, fVar1 = lbl_803E36B8, cVar3 == '\0' && (iVar4 < 4));
      iVar4 = iVar4 + 1) {
    local_70 = *(float *)(param_1 + 3) + *pfVar5;
    local_78 = param_1[4];
    local_68 = *(float *)(param_1 + 5) + pfVar5[1];
    local_7c = *(float *)(param_1 + 3) - *pfVar5;
    local_74 = *(float *)(param_1 + 5) - pfVar5[1];
    local_6c = local_78;
    cVar3 = objBboxFn_800640cc(&local_70,&local_7c,(float *)0x3,&iStack_64,param_1,5,3,0xff,0);
    pfVar5 = pfVar5 + 2;
  }
  if (cVar3 != '\0') {
    *(float *)(param_1 + 3) = (local_20 - lbl_803E36B8) * ((local_7c - local_70) / lbl_803E36BC) +
                      local_70;
    *(float *)(param_1 + 5) = (local_20 - fVar1) * ((local_74 - local_68) / fVar2) + local_68;
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
    local_a0 = lbl_803E3698;
    local_9c = lbl_803E369C;
    local_98 = lbl_803E3698;
    PSVECCrossProduct(&local_a0,(float *)(param_2 + 0x344),afStack_88);
    PSVECNormalize(afStack_88,afStack_88);
    *(undefined4 *)(param_2 + 0x360) = local_60;
    *(undefined4 *)(param_2 + 0x364) = local_50;
    local_94 = local_5c;
    local_8c = local_4c;
    local_b8 = *(float *)(param_2 + 0x360);
    local_b4 = *(float *)(param_2 + 0x358);
    local_b0 = *(float *)(param_2 + 0x364);
    PSVECSubtract(&local_b8,&local_94,afStack_ac);
    dVar6 = PSVECDotProduct(afStack_ac,(float *)(param_2 + 0x344));
    local_b8 = (float)((double)*(float *)(param_2 + 0x344) * dVar6 + (double)local_94);
    local_b4 = (float)((double)*(float *)(param_2 + 0x348) * dVar6 + (double)local_90);
    local_b0 = (float)((double)*(float *)(param_2 + 0x34c) * dVar6 + (double)local_8c);
    local_d0 = lbl_803E3698;
    local_cc = lbl_803E369C;
    local_c8 = lbl_803E3698;
    PSVECCrossProduct(&local_d0,(float *)(param_2 + 0x344),local_c4);
    PSVECNormalize(local_c4,local_c4);
    if (lbl_803E3698 == local_c4[0]) {
      *(float *)(param_2 + 0x354) = (local_8c - *(float *)(param_2 + 0x364)) / local_bc;
    }
    else {
      *(float *)(param_2 + 0x354) = (local_94 - *(float *)(param_2 + 0x360)) / local_c4[0];
    }
    *(undefined *)(param_2 + 0x33a) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80155770
 * EN v1.0 Address: 0x80155B08
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80155C1C
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80155770(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
  }
  else if (param_4 != 0x11) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
    Sfx_PlayFromObject(param_1,0x254);
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
      Sfx_PlayFromObject((uint)param_9,0x253);
      fn_8014D08C((int)param_9,param_10,2,lbl_803E369C,0,0);
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
    fn_80154FB4((int)param_9,param_10,0x19,lbl_803E36C8);
    if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
      fn_8014D08C((int)param_9,param_10,0,lbl_803E36C8,0,0);
      Sfx_PlayFromObject((uint)param_9,0x252);
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
      fn_80154FB4((int)param_9,param_10,0x19,lbl_803E3698);
    }
    else if ((sVar1 == 0) || (sVar1 == 1)) {
      fn_80154FB4((int)param_9,param_10,0x19,lbl_803E36C8);
    }
    fn_80154D0C((int)param_9,param_10,local_18,afStack_14);
    if (((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) ||
       ((local_18[0] < 0x5dc && (*(short *)(param_9 + 0x28) != 1)))) {
      if (local_18[0] < 0x5dc) {
        Sfx_PlayFromObject((uint)param_9,0x251);
        fn_8014D08C((int)param_9,param_10,1,lbl_803E36C8,0,0);
      }
      else {
        fn_8014D08C((int)param_9,param_10,3,lbl_803E36C8,0,0);
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
 * Function: fn_80155AAC
 * EN v1.0 Address: 0x8015603C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80155F58
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80155AAC(undefined4 param_1,int param_2)
{
  float fVar1;
  float fVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E36CC;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  fVar1 = lbl_803E36D0;
  *(float *)(param_2 + 0x308) = lbl_803E36D0;
  *(float *)(param_2 + 0x300) = fVar1;
  *(float *)(param_2 + 0x304) = lbl_803E36D4;
  *(undefined *)(param_2 + 800) = 0;
  fVar2 = lbl_803E36D8;
  *(float *)(param_2 + 0x314) = lbl_803E36D8;
  *(undefined *)(param_2 + 0x321) = 4;
  fVar1 = lbl_803E369C;
  *(float *)(param_2 + 0x318) = lbl_803E369C;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar2;
  *(float *)(param_2 + 0x324) = lbl_803E3698;
  *(undefined *)(param_2 + 0x33a) = 0;
  *(undefined *)(param_2 + 0x33b) = 0;
  *(float *)(param_2 + 0x2fc) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80155B10
 * EN v1.0 Address: 0x801560A0
 * EN v1.0 Size: 628b
 * EN v1.1 Address: 0x80155FBC
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80155B10(uint param_9,int param_10)
{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  double dVar4;
  double dVar5;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  undefined4 local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar1 = Obj_IsLoadingLocked();
  if ((uVar1 & 0xff) != 0) {
    local_2c = *(float *)(param_9 + 0xc);
    local_28 = lbl_803E36E0 + *(float *)(param_9 + 0x10);
    local_24 = *(undefined4 *)(param_9 + 0x14);
    iVar2 = *(int *)(param_10 + 0x29c);
    local_38 = *(float *)(iVar2 + 0xc);
    local_34 = lbl_803E36E4 + *(float *)(iVar2 + 0x10);
    local_30 = *(float *)(iVar2 + 0x14);
    dVar5 = (double)(lbl_803E36E8 *
                    (lbl_803E36F0 *
                     (float)(int)randomGetRange(0xfffffff6,10) +
                    lbl_803E36EC));
    iVar2 = fn_80169EF4(dVar5,(double)lbl_803E36F4,&local_2c,&local_38,'\x01');
    fn_80293018(iVar2,&local_40,&local_3c);
    local_3c = (float)((double)local_3c * dVar5);
    local_40 = (float)((double)local_40 * dVar5);
    dVar5 = (double)(local_38 - *(float *)(param_9 + 0xc));
    dVar4 = (double)(local_30 - *(float *)(param_9 + 0x14));
    if ((double)lbl_803E36F8 == dVar4) {
      local_44 = lbl_803E36F8;
    }
    else {
      iVar2 = getAngle();
      fn_80293018(iVar2,&local_48,&local_44);
      dVar5 = (double)local_3c;
      local_44 = (float)((double)local_44 * dVar5);
      local_3c = (float)(dVar5 * (double)local_48);
    }
    puVar3 = Obj_AllocObjectSetup(0x24,0x47b);
    *(float *)(puVar3 + 4) = local_2c;
    *(float *)(puVar3 + 6) = local_28;
    *(undefined4 *)(puVar3 + 8) = local_24;
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
      Sfx_PlayFromObject(param_9,0x259);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80155CF8
 * EN v1.0 Address: 0x80156314
 * EN v1.0 Size: 472b
 * EN v1.1 Address: 0x801561A4
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80155CF8(int param_9,int param_10)
{
  byte bVar1;
  float local_18 [4];

  (*(code *)(*(int *)gSHthorntailAnimationInterface + 0x14))(local_18);
  if ((local_18[0] >= lbl_803E3708) && (local_18[0] <= lbl_803E370C)) {
    bVar1 = 1;
  }
  else {
    bVar1 = 0;
  }
  if ((bVar1 != 0) && (*(byte *)(param_10 + 0x33a) == 0)) {
    *(undefined *)(param_10 + 0x33a) = 1;
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    fn_8014D08C(param_9,param_10,1,lbl_803E3710,0,0);
  }
  else if ((bVar1 == 0) && (*(byte *)(param_10 + 0x33a) == 2)) {
    *(undefined *)(param_10 + 0x33a) = 1;
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    fn_8014D08C(param_9,param_10,3,lbl_803E3710,0,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80155E10
 * EN v1.0 Address: 0x801564EC
 * EN v1.0 Size: 384b
 * EN v1.1 Address: 0x801562BC
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80155E10(uint param_9,int param_10,undefined4 param_11,int param_12,undefined4 param_13,int param_14)
{
  if (param_12 == 0x10) {
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x20;
  }
  else if (param_12 == 0x11) {
    if ((*(char *)(param_10 + 0x33a) == '\x02') && (*(short *)(param_9 + 0xa0) != 5)) {
      fn_8014D08C(param_9,param_10,5,lbl_803E3714,0,0);
    }
  }
  else if ((*(short *)(param_9 + 0xa0) == 5) || (*(short *)(param_9 + 0xa0) == 4)) {
    if ((int)(uint)*(ushort *)(param_10 + 0x2b0) < param_14) {
      *(undefined2 *)(param_10 + 0x2b0) = 0;
      Sfx_PlayFromObject(param_9,600);
      Sfx_PlayFromObject(param_9,0x22);
    }
    else {
      *(ushort *)(param_10 + 0x2b0) = *(ushort *)(param_10 + 0x2b0) - (short)param_14;
      Sfx_PlayFromObject(param_9,0x24f);
      Sfx_PlayFromObject(param_9,0x22);
    }
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 8;
  }
  else {
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x10;
    Sfx_PlayFromObject(param_9,0x250);
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
  *(float *)(param_10 + 0x324) = lbl_803E36F8;
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    if (*(byte *)(param_10 + 0x33a) == 1) {
      if (*(short *)(param_9 + 0xa0) == 1) {
        *(undefined *)(param_10 + 0x33a) = 2;
        *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) & ~0x10000;
      }
      else if (*(short *)(param_9 + 0xa0) == 3) {
        *(undefined *)(param_10 + 0x33a) = 0;
        *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
        fn_8014D08C(param_9,param_10,0,lbl_803E36EC,0,0);
      }
    }
    else if ((*(byte *)(param_10 + 0x33a) == 2) && (*(short *)(param_9 + 0xa0) != 2)) {
      fn_8014D08C(param_9,param_10,2,lbl_803E36EC,0,0);
    }
  }
  fn_80155CF8(param_9,param_10);
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
  *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - lbl_803DC074;
  if ((double)*(float *)(param_10 + 0x324) <= (double)lbl_803E36F8) {
    bVar1 = true;
    *(float *)(param_10 + 0x324) = lbl_803E36F8;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    sVar2 = *(short *)(param_9 + 0xa0);
    if (sVar2 == 4) {
      fn_80155B10(param_9,param_10);
      *(float *)(param_10 + 0x324) = lbl_803E3718;
      fn_8014D08C(param_9,param_10,5,lbl_803E36EC,0,0);
    }
    else if ((sVar2 == 5) && (bVar1)) {
      fn_8014D08C(param_9,param_10,6,lbl_803E36EC,0,0);
      Sfx_PlayFromObject(param_9,0x24c);
    }
    else if (sVar2 == 6) {
      fn_8014D08C(param_9,param_10,2,lbl_803E36EC,0,0);
      *(float *)(param_10 + 0x324) = lbl_803E3718;
    }
    else if (((sVar2 == 2) && (bVar1)) && ((*(uint *)(param_10 + 0x2dc) & 0x4000000) != 0)) {
      fn_8014D08C(param_9,param_10,4,lbl_803E36EC,0,0);
      dVar3 = (double)Sfx_PlayFromObject(param_9,0x24b);
    }
  }
  fn_80155CF8(param_9,param_10);
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80156188
 * EN v1.0 Address: 0x80156DE4
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80156634
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80156188(undefined4 param_1,int param_2)
{
  float fVar1;
  float fVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E371C;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(float *)(param_2 + 0x308) = lbl_803E36F0;
  *(float *)(param_2 + 0x300) = lbl_803E3720;
  *(float *)(param_2 + 0x304) = lbl_803E3724;
  *(undefined *)(param_2 + 800) = 0;
  fVar2 = lbl_803E3728;
  *(float *)(param_2 + 0x314) = lbl_803E3728;
  *(undefined *)(param_2 + 0x321) = 7;
  fVar1 = lbl_803E36EC;
  *(float *)(param_2 + 0x318) = lbl_803E36EC;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar2;
  *(undefined *)(param_2 + 0x33a) = 0;
  *(float *)(param_2 + 0x324) = lbl_803E36F8;
  *(float *)(param_2 + 0x2fc) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: fn_801561EC
 * EN v1.0 Address: 0x80156E48
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80156698
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801561EC(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if (param_4 != 0x11) {
    if (param_4 == 0x10) {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
    }
    else {
      Sfx_PlayFromObject(param_1,0x260);
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
  
  if (lbl_803E3740 < *(float *)(param_10 + 0x328)) {
    *(float *)(param_10 + 0x328) = lbl_803E3744;
  }
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x70) = 0;
  uVar4 = 0;
  ObjHits_SetHitVolumeSlot((int)param_9,10,1,0);
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    Sfx_PlayFromObject((uint)param_9,0x261);
  }
  *(float *)(param_10 + 0x328) = *(float *)(param_10 + 0x328) - lbl_803DC074;
  if (*(float *)(param_10 + 0x328) <= lbl_803E3730) {
    if ((*(uint *)(param_10 + 0x2dc) & 0x600) == 0) {
      uVar2 = randomGetRange(600,0x352);
      *(float *)(param_10 + 0x328) =
           (float)(int)uVar2;
    }
    else {
      uVar2 = randomGetRange(0x96,0xfa);
      *(float *)(param_10 + 0x328) =
           (float)(int)uVar2;
    }
    Sfx_PlayFromObject((uint)param_9,0x262);
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    ObjAnim_SetCurrentMove((uint)param_9,3,lbl_803E3730,(uint)*(byte *)(param_10 + 0x323));
  }
  fVar1 = lbl_803E3730;
  if (*(float *)(param_10 + 0x324) <= lbl_803E3730) {
    if ((*(uint *)(param_10 + 0x2dc) & 0x400) != 0) {
      *(float *)(param_10 + 0x324) = lbl_803E3748;
    }
  }
  else {
    *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - lbl_803DC074;
    if (*(float *)(param_10 + 0x324) <= fVar1) {
      *(float *)(param_10 + 0x324) = lbl_803E3748;
      *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    }
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x8000000) == 0) {
    iVar3 = *(int *)(param_10 + 0x29c);
    dVar5 = fn_8014CB54((double)*(float *)(iVar3 + 0x18),
                         (double)(lbl_803E3750 + *(float *)(iVar3 + 0x1c)),
                         (double)*(float *)(iVar3 + 0x20),(double)lbl_803E3754,
                         (double)lbl_803E3758,(double)lbl_803E375C,
                         (double)*(float *)(param_10 + 0x304),(int)param_9);
  }
  else {
    dVar5 = (double)lbl_803E374C;
  }
  if ((((double)lbl_803E3730 < dVar5) && (*(float *)(param_9 + 0x14) < lbl_803E3760)) ||
     ((*(uint *)(param_10 + 0x2dc) & 0x8000000) != 0)) {
    *(undefined *)(param_10 + 0x33a) = 1;
  }
  if ((*(byte *)(param_10 + 0x33a) == 0) || (dVar5 <= (double)lbl_803E3730)) {
    *(undefined *)(param_10 + 0x33a) = 0;
    if (lbl_803E3774 < *(float *)(param_10 + 0x308)) {
      *(float *)(param_10 + 0x308) =
           -(lbl_803E3778 * lbl_803DC074 - *(float *)(param_10 + 0x308));
    }
  }
  else {
    *(float *)(param_10 + 0x308) = lbl_803E3764;
    if (*(short *)(param_10 + 0x2b0) != 0) {
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) + lbl_803E3768;
    }
    if (lbl_803E376C <= *(float *)(param_9 + 0x14)) {
      if (lbl_803E3770 < *(float *)(param_9 + 0x14)) {
        *(float *)(param_9 + 0x14) = lbl_803E3770;
      }
    }
    else {
      *(float *)(param_9 + 0x14) = lbl_803E376C;
    }
  }
  fn_8014CD1C((double)lbl_803E3730,(double)lbl_803E3730,param_9,param_10,0x2d,'\0');
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
    Sfx_PlayFromObject((uint)param_9,0x261);
  }
  *(float *)(param_10 + 0x328) = *(float *)(param_10 + 0x328) - lbl_803DC074;
  if (*(float *)(param_10 + 0x328) <= lbl_803E3730) {
    if ((*(uint *)(param_10 + 0x2dc) & 0x600) == 0) {
      uVar2 = randomGetRange(600,0x352);
      *(float *)(param_10 + 0x328) = (float)(int)uVar2;
    }
    else {
      uVar2 = randomGetRange(0x96,0xfa);
      *(float *)(param_10 + 0x328) = (float)(int)uVar2;
    }
    Sfx_PlayFromObject((uint)param_9,0x262);
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    ObjAnim_SetCurrentMove((uint)param_9,0,lbl_803E3730,(uint)*(byte *)(param_10 + 0x323));
  }
  if (*(float *)(param_10 + 0x324) <= lbl_803E3730) {
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) & 0xfffeffff;
  }
  else {
    *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - lbl_803DC074;
    if (*(float *)(param_10 + 0x324) <= lbl_803E3730) {
      *(float *)(param_10 + 0x324) = lbl_803E3730;
    }
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x2000) == 0) {
    if ((*(uint *)(param_10 + 0x2dc) & 0x8000000) == 0) {
      dVar7 = fn_8014CB54((double)*(float *)(iVar5 + 8),(double)*(float *)(iVar5 + 0xc),
                           (double)*(float *)(iVar5 + 0x10),(double)lbl_803E3754,
                           (double)lbl_803E3758,(double)lbl_803E375C,
                           (double)*(float *)(param_10 + 0x304),(int)param_9);
    }
    else {
      dVar7 = (double)lbl_803E3754;
    }
  }
  else {
    iVar5 = FUN_80006a10((double)*(float *)(param_10 + 0x2fc),pfVar6);
    if ((((iVar5 != 0) || (pfVar6[4] != 0.0)) &&
        (cVar3 = (**(code **)(*lbl_803DD71C + 0x90))(pfVar6), cVar3 != '\0')) &&
       (cVar3 = (**(code **)(*lbl_803DD71C + 0x8c))
                          ((double)lbl_803E377C,*(int *)param_10,param_9,&lbl_803DC940,0xffffffff),
       cVar3 != '\0')) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xffffdfff;
    }
    if ((*(uint *)(param_10 + 0x2dc) & 0x8000000) == 0) {
      dVar7 = fn_8014CB54((double)pfVar6[0x1a],(double)pfVar6[0x1b],(double)pfVar6[0x1c],
                           (double)lbl_803E3754,(double)lbl_803E3758,(double)lbl_803E375C,
                           (double)*(float *)(param_10 + 0x304),(int)param_9);
    }
    else {
      dVar7 = (double)lbl_803E3754;
    }
  }
  if ((((double)lbl_803E3730 < dVar7) && (*(float *)(param_9 + 0x14) < lbl_803E3760)) ||
     ((*(uint *)(param_10 + 0x2dc) & 0x8000000) != 0)) {
    *(undefined *)(param_10 + 0x33a) = 1;
  }
  if ((*(byte *)(param_10 + 0x33a) == 0) || (dVar7 <= (double)lbl_803E3730)) {
    *(undefined *)(param_10 + 0x33a) = 0;
    if (lbl_803E3774 < *(float *)(param_10 + 0x308)) {
      *(float *)(param_10 + 0x308) = -(lbl_803E3778 * lbl_803DC074 - *(float *)(param_10 + 0x308));
    }
  }
  else {
    *(float *)(param_10 + 0x308) = lbl_803E3764;
    if (*(short *)(param_10 + 0x2b0) != 0) {
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) + lbl_803E3768;
    }
    if (lbl_803E376C <= *(float *)(param_9 + 0x14)) {
      if (lbl_803E3770 < *(float *)(param_9 + 0x14)) {
        *(float *)(param_9 + 0x14) = lbl_803E3770;
      }
    }
    else {
      *(float *)(param_9 + 0x14) = lbl_803E376C;
    }
  }
  fn_8014CD1C((double)lbl_803E3730,(double)lbl_803E3730,param_9,param_10,0x2d,'\0');
  return;
}

/*
 * --INFO--
 *
 * Function: fn_801568A8
 * EN v1.0 Address: 0x80157724
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x80156D54
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801568A8(undefined4 param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E3780;
  *(undefined4 *)(param_2 + 0x2e4) = 0x2002b029;
  *(float *)(param_2 + 0x308) = lbl_803E3764;
  *(float *)(param_2 + 0x300) = lbl_803E3784;
  *(float *)(param_2 + 0x304) = lbl_803E3788;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = lbl_803E378C;
  *(float *)(param_2 + 0x314) = lbl_803E378C;
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
  case 7:
    if (*(ushort *)(param_2 + 0x2f8) != 0) {
      if (*(float *)(param_1 + 0x98) >= lbl_803E3790) {
        Sfx_PlayFromObject(param_1,0x24c);
      }
      else {
        Sfx_PlayFromObject(param_1,0x24d);
      }
    }
    break;
  case 5:
    if (*(ushort *)(param_2 + 0x2f8) != 0) {
      Sfx_PlayFromObject(param_1,0x24d);
    }
    break;
  case 6:
    if (*(ushort *)(param_2 + 0x2f8) != 0) {
      Sfx_PlayFromObject(param_1,0x24d);
    }
    break;
  case 8:
    if (*(ushort *)(param_2 + 0x2f8) != 0) {
      if (*(float *)(param_1 + 0x98) >= lbl_803E3794) {
        if (*(float *)(param_1 + 0x98) >= lbl_803E3798) {
          Sfx_PlayFromObject(param_1,0x24c);
        }
        else {
          Sfx_PlayFromObject(param_1,0x24e);
        }
      }
      else {
        Sfx_PlayFromObject(param_1,0x24b);
      }
    }
    break;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80156A44
 * EN v1.0 Address: 0x801578C4
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x80156EF0
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80156A44(uint param_9,int param_10,undefined4 param_11,int param_12)
{
  short sVar1;
  
  if (param_12 != 0x11) {
    if (param_12 == 0x10) {
      *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x20;
    }
    else {
      sVar1 = *(short *)(param_9 + 0xa0);
      if ((((sVar1 == 0) || (sVar1 == 1)) || (sVar1 == 3)) || (sVar1 == 4)) {
        Sfx_PlayFromObject(param_9,0x250);
        *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x10;
      }
      else {
        fn_8014D08C(param_9,param_10,4,lbl_803E379C,0,0);
        *(undefined *)(param_10 + 0x33a) = 0;
        Sfx_PlayFromObject(param_9,0x24f);
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
 * Function: fn_80156CDC
 * EN v1.0 Address: 0x80156CDC
 * EN v1.0 Size: 104b
 */
void fn_80156CDC(undefined4 param_1,int param_2)
{
  float fVar1;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E371C;
  *(undefined4 *)(param_2 + 0x2e4) = 0x46001;
  *(float *)(param_2 + 0x308) = lbl_803E36F0;
  *(float *)(param_2 + 0x300) = lbl_803E3720;
  *(float *)(param_2 + 0x304) = lbl_803E3724;
  *(undefined *)(param_2 + 0x320) = 0;
  fVar1 = lbl_803E36EC;
  *(float *)(param_2 + 0x314) = lbl_803E36EC;
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
 * Function: fn_80156D44
 * EN v1.0 Address: 0x80156D44
 * EN v1.0 Size: 92b
 */
void fn_80156D44(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
  }
  else {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
    Sfx_PlayFromObject(param_1,0x244);
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
  if (*(float *)(param_10 + 0x324) <= lbl_803E36F8) {
    *(float *)(param_10 + 0x324) = (float)(int)randomGetRange(0x3c,0x78);
  }
  if (lbl_803E36F8 != *(float *)(param_10 + 0x328)) {
    ObjHits_DisableObject(param_9);
    if (*(short *)(param_9 + 0xa0) != 5) {
      fn_8014D08C(param_9,param_10,5,lbl_803DBCEC,0,0);
    }
    else if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
      ObjHits_EnableObject(param_9);
      *(float *)(param_10 + 0x328) = lbl_803E36F8;
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
    local_8c[0] = *(float *)(param_9 + 0xc) - lbl_803E3754 * local_80;
    local_8c[1] = lbl_803E3758 + *(float *)(param_9 + 0x10);
    local_8c[2] = *(float *)(param_9 + 0x14) - lbl_803E3754 * local_7c;
    local_70 = 0;
    iVar2 = objBboxFn_800640cc(local_98,local_8c,(float *)0x3,&local_70,param_9,
                         (uint)*(byte *)(param_10 + 0x261),0xff,0xffffffff,0);
    if (((iVar2 & 0xff) == 0) || ((*(uint *)(param_10 + 0x2dc) & 0x40000000) == 0)) {
      if ((iVar2 & 0xff) != 0) {
        if (*(short *)(param_9 + 0xa0) == 0) {
          *(undefined2 *)(param_10 + 0x338) = 0;
          fn_8014D08C(param_9,param_10,0,lbl_803E3760,0,1);
        }
        else {
          fn_8014D08C(param_9,param_10,1,lbl_803E3764,0,0);
          *(float *)(param_9 + 0x24) = lbl_803E36F8;
          *(float *)(param_9 + 0x28) = lbl_803E36F8;
          *(float *)(param_9 + 0x2c) = lbl_803E36F8;
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
