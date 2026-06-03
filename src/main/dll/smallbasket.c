#include "ghidra_import.h"
#include "main/dll/smallbasket.h"

#define SFXen_blkscrp6 0x22
#define SFXfox_swimstroke322 0x23d
#define SFXfox_swimstroke422 0x23e
#define SFXfox_outofwater122 0x23f
#define SFXwatery_bubble2 0x244
#define SFXfox_fightbreath4 0x24e

extern undefined4 FUN_800067e8();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006924();
extern int FUN_80006a10();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_800175ec();
extern void* FUN_80017624();
extern undefined4 FUN_80017668();
extern uint GameBit_Get(int eventId);
extern undefined4 FUN_8001771c();
extern uint FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_800178a4();
extern undefined4 FUN_800178b4();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_SetHitVolumeMasks();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjGroup_FindNearestObject();
extern undefined4 ObjLink_AttachChild();
extern undefined8 ObjPath_GetPointWorldPosition();
extern int Obj_GetYawDeltaToObject();
extern uint FUN_800620e8();
extern byte FUN_8014c78c();
extern undefined4 FUN_8014cfac();
extern void enemy_free(double param_1,double param_2,ushort *param_3,int param_4,uint param_5,
                       char param_6);
extern undefined8 FUN_8014d3d0();
extern undefined8 FUN_8014d4c8();
extern undefined4 FUN_8014d59c();
extern undefined4 FUN_801577c8();
extern undefined4 FUN_8020a3fc();
extern undefined4 FUN_8020a404();
extern undefined4 PSVECDotProduct();
extern undefined4 FUN_80247cd8();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293130();
extern undefined4 FUN_8029346c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_802949e8();
extern int FUN_80294c14();
extern uint countLeadingZeros();

extern undefined4 DAT_8031ff68;
extern undefined4 DAT_8031ff70;
extern undefined4 DAT_80320798;
extern undefined4 DAT_8032079c;
extern undefined4 DAT_803207a0;
extern undefined4 DAT_803207c0;
extern undefined4 DAT_803207c8;
extern undefined4 DAT_803207c9;
extern undefined4 DAT_803207ca;
extern undefined4 DAT_803ad108;
extern undefined4 DAT_803ad10c;
extern undefined4 DAT_803dc958;
extern undefined4 DAT_803dc960;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e37b8;
extern f64 DOUBLE_803e37f0;
extern f64 DOUBLE_803e3828;
extern f64 DOUBLE_803e3830;
extern f64 DOUBLE_803e38c0;
extern f32 lbl_803DC074;
extern f32 lbl_803DC948;
extern f32 lbl_803DC94C;
extern f32 lbl_803DC950;
extern f32 lbl_803DC954;
extern f32 lbl_803DE6F0;
extern f32 lbl_803E379C;
extern f32 lbl_803E37A0;
extern f32 lbl_803E37A4;
extern f32 lbl_803E37A8;
extern f32 lbl_803E37AC;
extern f32 lbl_803E37B0;
extern f32 lbl_803E37C0;
extern f32 lbl_803E37C4;
extern f32 lbl_803E37C8;
extern f32 lbl_803E37CC;
extern f32 lbl_803E37D0;
extern f32 lbl_803E37D4;
extern f32 lbl_803E37D8;
extern f32 lbl_803E37DC;
extern f32 lbl_803E37E0;
extern f32 lbl_803E37E4;
extern f32 lbl_803E37E8;
extern f32 lbl_803E37F8;
extern f32 lbl_803E37FC;
extern f32 lbl_803E3800;
extern f32 lbl_803E3804;
extern f32 lbl_803E3808;
extern f32 lbl_803E380C;
extern f32 lbl_803E3810;
extern f32 lbl_803E3818;
extern f32 lbl_803E381C;
extern f32 lbl_803E3820;
extern f32 lbl_803E3838;
extern f32 lbl_803E383C;
extern f32 lbl_803E3840;
extern f32 lbl_803E3844;
extern f32 lbl_803E3848;
extern f32 lbl_803E384C;
extern f32 lbl_803E3850;
extern f32 lbl_803E3854;
extern f32 lbl_803E3858;
extern f32 lbl_803E385C;
extern f32 lbl_803E3860;
extern f32 lbl_803E3864;
extern f32 lbl_803E3868;
extern f32 lbl_803E386C;
extern f32 lbl_803E3870;
extern f32 lbl_803E3874;
extern f32 lbl_803E387C;
extern f32 lbl_803E3880;
extern f32 lbl_803E3884;
extern f32 lbl_803E3888;
extern f32 lbl_803E388C;
extern f32 lbl_803E3890;
extern f32 lbl_803E3894;
extern f32 lbl_803E3898;
extern f32 lbl_803E389C;
extern f32 lbl_803E38A0;
extern f32 lbl_803E38A4;
extern f32 lbl_803E38A8;
extern f32 lbl_803E38AC;
extern f32 lbl_803E38B0;
extern f32 lbl_803E38B4;
extern f32 lbl_803E38BC;
extern f32 lbl_803E38C8;
extern f32 lbl_803E38CC;
extern f32 lbl_803E38D0;
extern f32 lbl_803E38D4;
extern f32 lbl_803E38D8;
extern f32 lbl_803E38DC;
extern f32 lbl_803E38E0;
extern f32 lbl_803E38E4;
extern f32 lbl_803E38E8;
extern f32 lbl_803E38EC;
extern f32 lbl_803E38F0;
extern f32 lbl_803E38F4;
extern f32 lbl_803E38F8;
extern f32 lbl_803E38FC;
extern f32 lbl_803E3900;
extern f32 lbl_803E3904;
extern f32 lbl_803E3908;
extern f32 lbl_803E390C;
extern f32 lbl_803E3910;
extern f32 lbl_803E3914;
extern f32 lbl_803E3918;
extern f32 lbl_803E391C;
extern f32 lbl_803E3920;
extern f32 lbl_803E3924;
extern f32 lbl_803E3928;
extern f32 lbl_803E392C;
extern f32 lbl_803E3930;
extern f32 lbl_803E3934;
extern f32 lbl_803E3940;
extern f32 lbl_803E3950;
extern f32 lbl_803E3954;
extern void* PTR_DAT_80320738;
extern void* PTR_DAT_8032073c;
extern void* PTR_DAT_80320740;
extern void* PTR_DAT_80320744;
extern void* PTR_DAT_80320748;
extern void* PTR_DAT_8032074c;
extern void* PTR_DAT_80320750;
extern void* PTR_DAT_80320754;
extern void* PTR_DAT_8032099c;

/*
 * --INFO--
 *
 * Function: FUN_80157004
 * EN v1.0 Address: 0x80157004
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x801570E0
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80157004(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  int iVar1;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    if (*(byte *)(param_10 + 0x33a) == 0) {
      *(undefined *)(param_10 + 0x33a) = 1;
    }
    else if (1 < *(byte *)(param_10 + 0x33a)) {
      *(undefined *)(param_10 + 0x33a) = 0;
    }
    iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
    FUN_8014d4c8((double)*(float *)(&DAT_8031ff68 + iVar1),param_2,param_3,param_4,param_5,param_6,
                 param_7,param_8,param_9,param_10,(uint)(byte)(&DAT_8031ff70)[iVar1],0,0,in_r8,in_r9
                 ,in_r10);
  }
  FUN_801577c8(param_9,param_10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80157100
 * EN v1.0 Address: 0x80157100
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x80157188
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80157100(undefined4 param_1,int param_2)
{
  float fVar1;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E37A0;
  *(undefined4 *)(param_2 + 0x2e4) = 0x46001;
  *(float *)(param_2 + 0x308) = lbl_803E37A4;
  *(float *)(param_2 + 0x300) = lbl_803E37A8;
  *(float *)(param_2 + 0x304) = lbl_803E37AC;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = lbl_803E379C;
  *(float *)(param_2 + 0x314) = lbl_803E379C;
  *(undefined *)(param_2 + 0x321) = 4;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 3;
  *(float *)(param_2 + 0x31c) = fVar1;
  *(undefined *)(param_2 + 0x33a) = 1;
  *(undefined2 *)(param_2 + 0x2b0) = 10;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80157168
 * EN v1.0 Address: 0x80157168
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801571F0
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80157168(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
  }
  else {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
    FUN_80006824(param_1,SFXwatery_bubble2);
    *(undefined2 *)(param_2 + 0x2b0) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801571c4
 * EN v1.0 Address: 0x801571C4
 * EN v1.0 Size: 840b
 * EN v1.1 Address: 0x8015724C
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801571c4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10)
{
  bool bVar1;
  float fVar2;
  uint uVar3;
  undefined4 in_r8;
  uint uVar4;
  undefined4 in_r9;
  undefined4 uVar5;
  undefined4 in_r10;
  undefined4 uVar6;
  double dVar7;
  float local_90;
  float local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  float local_7c;
  float local_78;
  float local_74;
  int aiStack_70 [22];
  undefined4 local_18;
  uint uStack_14;
  
  *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - lbl_803DC074;
  if (*(float *)(param_10 + 0x324) <= lbl_803E37B0) {
    uStack_14 = randomGetRange(0x3c,0x78);
    *(float *)(param_10 + 0x324) = (f32)(s32)uStack_14
    ;
  }
  if (lbl_803E37B0 == *(float *)(param_10 + 0x328)) {
    bVar1 = false;
  }
  else {
    ObjHits_DisableObject((int)param_9);
    if (param_9[0x50] == 5) {
      if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
        ObjHits_EnableObject((int)param_9);
        *(float *)(param_10 + 0x328) = lbl_803E37B0;
      }
    }
    else {
      FUN_8014d4c8((double)lbl_803DC954,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,param_10,5,0,0,in_r8,in_r9,in_r10);
    }
    *(undefined *)(param_9 + 0x1b) = 0xff;
    bVar1 = true;
  }
  if (!bVar1) {
    *param_9 = *param_9 + *(short *)(param_10 + 0x338);
    local_88 = *(undefined4 *)(param_9 + 6);
    local_84 = *(undefined4 *)(param_9 + 8);
    local_80 = *(undefined4 *)(param_9 + 10);
    FUN_8029346c((uint)*param_9,&local_90,&local_8c);
    dVar7 = (double)lbl_803E37D0;
    local_7c = -(float)(dVar7 * (double)local_90 - (double)*(float *)(param_9 + 6));
    local_78 = lbl_803E37D4 + *(float *)(param_9 + 8);
    local_74 = -(float)(dVar7 * (double)local_8c - (double)*(float *)(param_9 + 10));
    uVar4 = (uint)*(byte *)(param_10 + 0x261);
    uVar5 = 0xffffffff;
    uVar6 = 0xff;
    uVar3 = FUN_800620e8(&local_88,&local_7c,(float *)0x3,aiStack_70,(int *)param_9,uVar4,0xffffffff
                         ,0xff,0);
    uVar3 = countLeadingZeros(uVar3 & 0xff);
    uVar3 = uVar3 >> 5 & 0xff;
    if ((uVar3 == 0) || ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0)) {
      if ((uVar3 == 0) || (param_9[0x50] == 0)) {
        FUN_8014d4c8((double)lbl_803E37DC,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)param_9,param_10,1,0,0,uVar4,uVar5,uVar6);
        fVar2 = lbl_803E37B0;
        *(float *)(param_9 + 0x12) = lbl_803E37B0;
        *(float *)(param_9 + 0x14) = fVar2;
        *(float *)(param_9 + 0x16) = fVar2;
        uVar3 = randomGetRange(0,1);
        *(short *)(param_10 + 0x338) = ((short)uVar3 + -1) * 300;
      }
      else {
        *(undefined2 *)(param_10 + 0x338) = 0;
        FUN_8014d4c8((double)lbl_803E37D8,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)param_9,param_10,0,0,1,uVar4,uVar5,uVar6);
      }
    }
    param_9[1] = *(ushort *)(param_10 + 0x19c);
    param_9[2] = *(ushort *)(param_10 + 0x19e);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015750c
 * EN v1.0 Address: 0x8015750C
 * EN v1.0 Size: 1628b
 * EN v1.1 Address: 0x801574B0
 * EN v1.1 Size: 1364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015750c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  bool bVar2;
  ushort *puVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  int iVar7;
  short sVar8;
  char cVar9;
  int iVar10;
  undefined4 in_r8;
  uint uVar11;
  undefined4 in_r9;
  undefined4 uVar12;
  undefined4 in_r10;
  undefined4 uVar13;
  double dVar14;
  double in_f31;
  double dVar15;
  double in_ps31_1;
  undefined8 uVar16;
  float local_130;
  float local_12c;
  float local_128;
  float local_124;
  float local_120;
  undefined4 local_11c;
  undefined4 local_118;
  undefined4 local_114;
  float local_110;
  float local_10c;
  float local_108;
  undefined4 local_104;
  undefined4 local_100;
  undefined4 local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  int aiStack_ec [21];
  int aiStack_98 [22];
  undefined8 local_40;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar16 = FUN_80286840();
  dVar14 = DOUBLE_803e37f0;
  puVar3 = (ushort *)((ulonglong)uVar16 >> 0x20);
  iVar10 = (int)uVar16;
  uStack_34 = (uint)*(byte *)(*(int *)(puVar3 + 0x26) + 0x2f);
  local_40 = (double)CONCAT44(0x43300000,uStack_34);
  local_38 = 0x43300000;
  fVar1 = (float)(local_40 - DOUBLE_803e37f0);
  if (lbl_803E37B0 == (f32)(s32)uStack_34) {
    fVar1 = lbl_803E37D0;
  }
  dVar15 = (double)(fVar1 / lbl_803E37D0);
  *(float *)(iVar10 + 0x324) = *(float *)(iVar10 + 0x324) - lbl_803DC074;
  if (*(float *)(iVar10 + 0x324) <= lbl_803E37B0) {
    uStack_34 = randomGetRange(0x3c,0x78);
    uStack_34 = uStack_34 ^ 0x80000000;
    *(float *)(iVar10 + 0x324) = (f32)(s32)uStack_34;
  }
  local_38 = 0x43300000;
  if (lbl_803E37B0 == *(float *)(iVar10 + 0x328)) {
    bVar2 = false;
  }
  else {
    ObjHits_DisableObject((int)puVar3);
    if (puVar3[0x50] == 5) {
      if ((*(uint *)(iVar10 + 0x2dc) & 0x40000000) != 0) {
        ObjHits_EnableObject((int)puVar3);
        *(float *)(iVar10 + 0x328) = lbl_803E37B0;
      }
    }
    else {
      FUN_8014d4c8((double)lbl_803DC954,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)puVar3,iVar10,5,0,0,in_r8,in_r9,in_r10);
    }
    *(undefined *)(puVar3 + 0x1b) = 0xff;
    bVar2 = true;
  }
  if (!bVar2) {
    *puVar3 = *puVar3 + *(short *)(iVar10 + 0x338);
    local_104 = *(undefined4 *)(puVar3 + 6);
    local_100 = *(undefined4 *)(puVar3 + 8);
    local_fc = *(undefined4 *)(puVar3 + 10);
    FUN_8029346c((uint)*puVar3,&local_128,&local_124);
    local_f8 = -(lbl_803E37D0 * local_128 - *(float *)(puVar3 + 6));
    local_f4 = lbl_803E37D4 + *(float *)(puVar3 + 8);
    local_f0 = -(lbl_803E37D0 * local_124 - *(float *)(puVar3 + 10));
    uVar11 = (uint)*(byte *)(iVar10 + 0x261);
    uVar12 = 0xffffffff;
    uVar13 = 0xff;
    uVar4 = FUN_800620e8(&local_104,&local_f8,(float *)0x3,aiStack_98,(int *)puVar3,uVar11,
                         0xffffffff,0xff,0);
    uVar4 = countLeadingZeros(uVar4 & 0xff);
    uVar4 = uVar4 >> 5 & 0xff;
    dVar14 = (double)(*(float *)(puVar3 + 10) - *(float *)(*(int *)(iVar10 + 0x29c) + 0x14));
    uVar5 = FUN_80017730();
    uStack_34 = (uVar5 & 0xffff) - (uint)*puVar3 ^ 0x80000000;
    local_38 = 0x43300000;
    fVar1 = (f32)(s32)uStack_34;
    if (lbl_803E37C4 < fVar1) {
      fVar1 = lbl_803E37C0 + fVar1;
    }
    if (fVar1 < lbl_803E37CC) {
      fVar1 = lbl_803E37C8 + fVar1;
    }
    local_40 = (double)(longlong)(int)fVar1;
    sVar8 = (short)(int)fVar1;
    uVar5 = (uint)sVar8;
    if ((int)uVar5 < 0) {
      uVar5 = -uVar5;
    }
    uVar5 = uVar5 & 0xffff;
    uVar6 = FUN_80017a98();
    iVar7 = FUN_80294c14(uVar6);
    if (iVar7 != 0) {
      local_120 = lbl_803E37E0;
      iVar7 = ObjGroup_FindNearestObject(0x30,puVar3,&local_120);
      if (iVar7 != 0) {
        iVar7 = Obj_GetYawDeltaToObject(puVar3,iVar7,&local_120);
        sVar8 = (short)iVar7;
        if (sVar8 < -300) {
          sVar8 = -300;
        }
        else if (300 < sVar8) {
          sVar8 = 300;
        }
        iVar7 = (int)sVar8;
        *(short *)(iVar10 + 0x338) = sVar8;
        if (iVar7 < 0) {
          iVar7 = -iVar7;
        }
        if (iVar7 < 0x4000) {
          *puVar3 = -*puVar3;
          local_11c = *(undefined4 *)(puVar3 + 6);
          local_118 = *(undefined4 *)(puVar3 + 8);
          local_114 = *(undefined4 *)(puVar3 + 10);
          FUN_8029346c((uint)*puVar3,&local_130,&local_12c);
          dVar14 = (double)lbl_803E37D0;
          local_110 = -(float)(dVar14 * (double)local_130 - (double)*(float *)(puVar3 + 6));
          local_10c = lbl_803E37D4 + *(float *)(puVar3 + 8);
          local_108 = -(float)(dVar14 * (double)local_12c - (double)*(float *)(puVar3 + 10));
          uVar4 = (uint)*(byte *)(iVar10 + 0x261);
          uVar12 = 0xffffffff;
          uVar13 = 0xff;
          cVar9 = FUN_800620e8(&local_11c,&local_110,(float *)0x3,aiStack_ec,(int *)puVar3,uVar4,
                               0xffffffff,0xff,0);
          if (cVar9 == '\0') {
            if ((*(uint *)(iVar10 + 0x2dc) & 0x40000000) != 0) {
              FUN_8014d4c8((double)(lbl_803E37D8 / (float)((double)lbl_803E37E4 * dVar15)),
                           dVar14,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar3,iVar10
                           ,7,0,1,uVar4,uVar12,uVar13);
            }
            puVar3[1] = *(ushort *)(iVar10 + 0x19c);
            puVar3[2] = *(ushort *)(iVar10 + 0x19e);
          }
          *puVar3 = -*puVar3;
        }
        goto LAB_801579e4;
      }
    }
    if ((*(int *)(iVar10 + 0x29c) != 0) &&
       (lbl_803E37E8 < *(float *)(*(int *)(iVar10 + 0x29c) + 0xa8))) {
      *(float *)(iVar10 + 0x2ac) = lbl_803DC950;
    }
    if ((((*(uint *)(iVar10 + 0x2dc) & 0x40000000) != 0) || (uVar4 == 0)) ||
       ((uVar5 < 3000 && ((uVar4 != 0 && (puVar3[0x50] != 0)))))) {
      if ((uVar4 == 0) || (2999 < uVar5)) {
        FUN_8014d4c8((double)(float)((double)lbl_803E37DC / dVar15),dVar14,param_3,param_4,param_5
                     ,param_6,param_7,param_8,(int)puVar3,iVar10,1,0,0,uVar11,uVar12,uVar13);
        fVar1 = lbl_803E37B0;
        *(float *)(puVar3 + 0x12) = lbl_803E37B0;
        *(float *)(puVar3 + 0x14) = fVar1;
        *(float *)(puVar3 + 0x16) = fVar1;
        if (uVar5 < 3000) {
          uVar4 = randomGetRange(0,1);
          *(short *)(iVar10 + 0x338) = ((short)uVar4 + -1) * 300;
        }
        else if (sVar8 < 0) {
          *(undefined2 *)(iVar10 + 0x338) = 0xfed4;
        }
        else {
          *(undefined2 *)(iVar10 + 0x338) = 300;
        }
      }
      else {
        *(undefined2 *)(iVar10 + 0x338) = 0;
        FUN_8014d4c8((double)(float)((double)lbl_803E37D8 / dVar15),dVar14,param_3,param_4,param_5
                     ,param_6,param_7,param_8,(int)puVar3,iVar10,0,0,1,uVar11,uVar12,uVar13);
      }
    }
    puVar3[1] = *(ushort *)(iVar10 + 0x19c);
    puVar3[2] = *(ushort *)(iVar10 + 0x19e);
  }
LAB_801579e4:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80157b68
 * EN v1.0 Address: 0x80157B68
 * EN v1.0 Size: 1204b
 * EN v1.1 Address: 0x80157A04
 * EN v1.1 Size: 832b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80157b68(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10)
{
  float fVar1;
  ushort uVar2;
  bool bVar3;
  uint uVar4;
  uint uVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar6;
  double dVar7;
  
  *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - lbl_803DC074;
  if (*(float *)(param_10 + 0x324) <= lbl_803E37B0) {
    uVar5 = randomGetRange(0x3c,0x78);
    *(float *)(param_10 + 0x324) =
         (f32)(s32)(uVar5);
  }
  if (lbl_803E37B0 == *(float *)(param_10 + 0x328)) {
    bVar3 = false;
  }
  else {
    ObjHits_DisableObject((int)param_9);
    if (param_9[0x50] == 5) {
      if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
        ObjHits_EnableObject((int)param_9);
        *(float *)(param_10 + 0x328) = lbl_803E37B0;
      }
    }
    else {
      FUN_8014d4c8((double)lbl_803DC954,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,param_10,5,0,0,in_r8,in_r9,in_r10);
    }
    *(undefined *)(param_9 + 0x1b) = 0xff;
    bVar3 = true;
  }
  if (!bVar3) {
    dVar7 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x338)) -
                           DOUBLE_803e37f0);
    *param_9 = (ushort)(int)(dVar7 * (double)lbl_803DC074 +
                            (double)(float)((double)CONCAT44(0x43300000,
                                                             (int)(short)*param_9 ^ 0x80000000) -
                                           DOUBLE_803e37b8));
    fVar1 = lbl_803E37B0;
    *(float *)(param_9 + 0x12) = lbl_803E37B0;
    *(float *)(param_9 + 0x14) = fVar1;
    *(float *)(param_9 + 0x16) = fVar1;
    ObjHits_SetHitVolumeSlot((int)param_9,9,1,-1);
    dVar6 = (double)(*(float *)(param_9 + 10) - *(float *)(*(int *)(param_10 + 0x29c) + 0x14));
    uVar5 = FUN_80017730();
    fVar1 = (float)((double)CONCAT44(0x43300000,(uVar5 & 0xffff) - (uint)*param_9 ^ 0x80000000) -
                   DOUBLE_803e37b8);
    if (lbl_803E37C4 < fVar1) {
      fVar1 = lbl_803E37C0 + fVar1;
    }
    if (fVar1 < lbl_803E37CC) {
      fVar1 = lbl_803E37C8 + fVar1;
    }
    uVar5 = (uint)(short)(int)fVar1;
    if ((int)uVar5 < 0) {
      uVar5 = -uVar5;
    }
    ObjHits_EnableObject((int)param_9);
    uVar4 = *(uint *)(param_10 + 0x2dc) & 0x40000000;
    if ((uVar4 == 0) || (param_9[0x50] != 6)) {
      if ((uVar4 != 0) ||
         (((((uVar5 & 0xffff) < 1000 && (uVar2 = param_9[0x50], uVar2 != 2)) && (uVar2 != 4)) &&
          (uVar2 != 6)))) {
        if ((uVar5 & 0xffff) < 1000) {
          if (lbl_803E37F8 <= *(float *)(param_10 + 0x2ac)) {
            FUN_8014d4c8((double)lbl_803DC94C,dVar6,dVar7,param_4,param_5,param_6,param_7,param_8,
                         (int)param_9,param_10,6,0,0,in_r8,in_r9,in_r10);
          }
          else {
            FUN_8014d4c8((double)lbl_803E37DC,dVar6,dVar7,param_4,param_5,param_6,param_7,param_8,
                         (int)param_9,param_10,2,0,0,in_r8,in_r9,in_r10);
          }
          *(undefined2 *)(param_10 + 0x338) = 0;
        }
        else {
          FUN_8014d4c8((double)lbl_803E37DC,dVar6,dVar7,param_4,param_5,param_6,param_7,param_8,
                       (int)param_9,param_10,1,0,0,in_r8,in_r9,in_r10);
          if ((short)(int)fVar1 < 0) {
            *(undefined2 *)(param_10 + 0x338) = 0xfed4;
          }
          else {
            *(undefined2 *)(param_10 + 0x338) = 300;
          }
        }
      }
      param_9[1] = *(ushort *)(param_10 + 0x19c);
      param_9[2] = *(ushort *)(param_10 + 0x19e);
    }
    else {
      FUN_8014d4c8((double)lbl_803DC948,dVar6,dVar7,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,param_10,4,0,1,in_r8,in_r9,in_r10);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015801c
 * EN v1.0 Address: 0x8015801C
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x80157D44
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015801c(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  
  uVar4 = (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x2f);
  fVar1 = (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e37f0);
  if (lbl_803E37B0 == (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e37f0)) {
    fVar1 = lbl_803E37D0;
  }
  fVar1 = fVar1 / lbl_803E37D0;
  *(float *)(param_2 + 0x2ac) = lbl_803E37FC;
  *(undefined4 *)(param_2 + 0x2e4) = 0x8b;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x20;
  *(float *)(param_2 + 0x308) = lbl_803E3800 * fVar1;
  fVar2 = lbl_803E37D8;
  *(float *)(param_2 + 0x300) = lbl_803E37D8;
  *(float *)(param_2 + 0x304) = lbl_803E3804;
  *(undefined *)(param_2 + 800) = 0;
  *(float *)(param_2 + 0x314) = lbl_803E3808;
  *(undefined *)(param_2 + 0x321) = 3;
  fVar3 = lbl_803E37E4;
  *(float *)(param_2 + 0x318) = lbl_803E37E4;
  *(undefined *)(param_2 + 0x322) = 5;
  *(float *)(param_2 + 0x31c) = fVar3;
  *(undefined2 *)(param_2 + 0x338) = 0;
  *(float *)(param_2 + 0x324) = lbl_803E380C;
  *(float *)(param_2 + 0x328) = fVar2;
  *(undefined *)(param_1 + 0x36) = 0;
  *(float *)(param_2 + 0x2fc) = lbl_803E3810 * fVar1;
  *(undefined4 *)(param_2 + 0x2e8) = 0;
  ObjHits_EnableObject(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80158114
 * EN v1.0 Address: 0x80158114
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x80157E34
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80158114(undefined4 param_1)
{
  bool bVar1;
  byte bVar3;
  uint uVar2;
  byte bVar4;
  
  bVar3 = FUN_8014c78c(param_1,0,0x28,&DAT_803ad108);
  bVar1 = true;
  if (bVar3 != 0) {
    for (bVar4 = 0; bVar4 < bVar3; bVar4 = bVar4 + 1) {
      if (((*(short *)((&DAT_803ad108)[(uint)bVar4 * 2] + 0x46) == 0x6a3) &&
          (uVar2 = *(uint *)(*(int *)((&DAT_803ad108)[(uint)bVar4 * 2] + 0xb8) + 0x2dc),
          (uVar2 & 0x20000000) != 0)) && ((uVar2 & 0x1800) == 0)) {
        bVar1 = false;
        bVar4 = bVar3;
      }
    }
  }
  if (bVar1) {
    (**(code **)(*DAT_803dd6d0 + 0x24))(0,0,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801581cc
 * EN v1.0 Address: 0x801581CC
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x80157F04
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801581cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar5;
  
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_80017aa4(0x24,0x710);
    uVar4 = 0;
    uVar5 = ObjPath_GetPointWorldPosition(param_9,0,(float *)(puVar2 + 4),(undefined4 *)(puVar2 + 6),
                         (float *)(puVar2 + 8),0);
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    *(undefined *)(puVar2 + 0xc) = 0;
    *(undefined *)((int)puVar2 + 0x19) = 0;
    puVar2[0xd] = 0;
    puVar2[0xe] = 10;
    puVar2[0xf] = 0;
    puVar2[0x10] = 0;
    *(undefined *)(puVar2 + 0x11) = 3;
    *(undefined *)((int)puVar2 + 0x23) = 0;
    iVar3 = FUN_80017ae4(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff
                         ,0xffffffff,(uint *)0x0,uVar4,in_r9,in_r10);
    if (iVar3 != 0) {
      ObjLink_AttachChild(param_9,iVar3,0);
      FUN_8020a404(iVar3);
      *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80158344
 * EN v1.0 Address: 0x80158344
 * EN v1.0 Size: 504b
 * EN v1.1 Address: 0x80158004
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80158344(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar5;
  double dVar6;
  
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_80017aa4(0x24,0x869);
    uVar4 = 0;
    uVar5 = ObjPath_GetPointWorldPosition(param_9,0,(float *)(puVar2 + 4),(undefined4 *)(puVar2 + 6),
                         (float *)(puVar2 + 8),0);
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    iVar3 = FUN_80017ae4(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff
                         ,0xffffffff,(uint *)0x0,uVar4,in_r9,in_r10);
    if (iVar3 != 0) {
      dVar6 = (double)(lbl_803E381C *
                      ((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x2a4)) -
                              DOUBLE_803e3828) / *(float *)(param_10 + 0x2a8)));
      *(float *)(iVar3 + 0x24) =
           (float)((double)(*(float *)(*(int *)(param_10 + 0x29c) + 0xc) - *(float *)(puVar2 + 4)) /
                  dVar6);
      uVar1 = randomGetRange(0xfffffff6,10);
      *(float *)(iVar3 + 0x28) =
           (float)((double)((lbl_803E3820 + *(float *)(*(int *)(param_10 + 0x29c) + 0x10) +
                            (f32)(s32)(uVar1)) - *(float *)(puVar2 + 6)) / dVar6);
      *(float *)(iVar3 + 0x2c) =
           (float)((double)(*(float *)(*(int *)(param_10 + 0x29c) + 0x14) - *(float *)(puVar2 + 8))
                  / dVar6);
    }
    FUN_80006824(param_9,0x4ae);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015853c
 * EN v1.0 Address: 0x8015853C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80158188
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015853c(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80158540
 * EN v1.0 Address: 0x80158540
 * EN v1.0 Size: 1816b
 * EN v1.1 Address: 0x80158368
 * EN v1.1 Size: 1496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80158540(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined *puVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_8028683c();
  uVar3 = (uint)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  uVar5 = (uint)*(byte *)(iVar4 + 0x33b);
  puVar7 = (&PTR_DAT_8032074c)[uVar5 * 8];
  iVar6 = param_14;
  if (param_12 == 0xe) {
    iVar6 = param_14 << 3;
  }
  if ((uVar5 == 0) && (param_12 == 5)) {
    iVar6 = iVar6 << 2;
  }
  if ((uVar5 == 1) &&
     (((*(short *)(param_11 + 0x46) == 0x1b5 || (*(short *)(param_11 + 0x44) == 0x1c)) ||
      (param_12 == 0x1f)))) goto LAB_80158928;
  if (((*(byte *)(iVar4 + 0x33c) & 4) == 0) &&
     ((uVar5 != 0 || ((*(byte *)(iVar4 + 0x2f1) & 0x40) == 0)))) {
    if ((uVar5 == 1) && (*(int *)(uVar3 + 200) != 0)) {
      FUN_8020a3fc(*(int *)(uVar3 + 200));
    }
    *(byte *)(iVar4 + 0x33d) = *(byte *)(iVar4 + 0x33d) & 0xbf;
    *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) & 0xffffffbf;
    if ((param_12 == 0x10) && (*(char *)(iVar4 + 0x33b) != '\0')) {
      *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x20;
      goto LAB_80158928;
    }
    if (*(char *)(iVar4 + 0x33f) == '\0') {
      if ((((*(char *)(iVar4 + 0x33b) != '\0') || (param_12 != 0x11)) ||
          (uVar5 = GameBit_Get(0xc55), uVar5 == 0)) && (*(char *)(iVar4 + 0x33b) != '\x01')) {
        if (param_12 != 0x11) {
          if (*(short *)(uVar3 + 0x46) == 0x6a2) {
            if ((lbl_803DE6F0 <= lbl_803E3840) && (param_11 != 0)) {
              sVar1 = *(short *)(param_11 + 0x46);
              if (sVar1 == 0x69) {
LAB_801588ec:
                FUN_80006824(uVar3,SFXen_blkscrp6);
              }
              else if (sVar1 < 0x69) {
                if (sVar1 == 0) goto LAB_801588ec;
              }
              else if (sVar1 == 0x416) {
                FUN_80006824(uVar3,0x36e);
              }
              FUN_80006824(uVar3,0x4aa);
              lbl_803DE6F0 = lbl_803E3844;
            }
          }
          else {
            FUN_80006824(uVar3,SFXfox_swimstroke422);
          }
        }
        *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x10;
        goto LAB_80158928;
      }
      FUN_8014d4c8((double)*(float *)(puVar7 + 0x10),param_2,param_3,param_4,param_5,param_6,param_7
                   ,param_8,uVar3,iVar4,(uint)(byte)puVar7[0x18],0,*(uint *)(puVar7 + 0x14) & 0xff,
                   param_14,param_15,param_16);
      *(char *)(iVar4 + 0x33c) = (char)*(undefined4 *)(puVar7 + 0x1c);
      *(byte *)(uVar3 + 0xe4) = *(byte *)(iVar4 + 0x33c) & 1;
      *(undefined *)(iVar4 + 0x33f) = puVar7[0x19];
      if (*(char *)(iVar4 + 0x33b) != '\0') {
        if (*(char *)(iVar4 + 0x33b) != '\x01') goto LAB_80158928;
        *(float *)(iVar4 + 0x328) =
             lbl_803E384C *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar4 + 0x2ec)) - DOUBLE_803e3828
                    );
        if (*(short *)(uVar3 + 0x46) == 0x6a2) {
          if ((lbl_803DE6F0 <= lbl_803E3840) && (param_11 != 0)) {
            sVar1 = *(short *)(param_11 + 0x46);
            if (sVar1 == 0x69) {
LAB_80158844:
              FUN_80006824(uVar3,SFXen_blkscrp6);
            }
            else if (sVar1 < 0x69) {
              if (sVar1 == 0) goto LAB_80158844;
            }
            else if (sVar1 == 0x416) {
              FUN_80006824(uVar3,0x36e);
            }
            FUN_80006824(uVar3,0x4aa);
            lbl_803DE6F0 = lbl_803E3844;
          }
        }
        else {
          FUN_80006824(uVar3,SFXfox_swimstroke422);
        }
        *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x10;
        goto LAB_80158928;
      }
      *(float *)(iVar4 + 0x328) =
           lbl_803E3848 *
           (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar4 + 0x2ec)) - DOUBLE_803e3828);
      *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 8;
      if (*(short *)(uVar3 + 0x46) != 0x6a2) {
        FUN_80006824(uVar3,SFXfox_outofwater122);
        goto LAB_80158928;
      }
      if ((lbl_803E3840 < lbl_803DE6F0) || (param_11 == 0)) goto LAB_80158928;
      sVar1 = *(short *)(param_11 + 0x46);
      if (sVar1 == 0x69) {
LAB_80158780:
        FUN_80006824(uVar3,SFXen_blkscrp6);
      }
      else if (sVar1 < 0x69) {
        if (sVar1 == 0) goto LAB_80158780;
      }
      else if (sVar1 == 0x416) {
        FUN_80006824(uVar3,0x36e);
      }
      FUN_80006824(uVar3,0x4aa);
      lbl_803DE6F0 = lbl_803E3844;
      goto LAB_80158928;
    }
    if (*(char *)(iVar4 + 0x33b) == '\0') {
      iVar2 = 4;
    }
    else {
      iVar2 = 3;
    }
    iVar2 = iVar2 * 0x10;
    FUN_8014d4c8((double)*(float *)(puVar7 + iVar2),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,uVar3,iVar4,(uint)(byte)puVar7[iVar2 + 8],0,
                 *(uint *)(puVar7 + iVar2 + 4) & 0xff,param_14,param_15,param_16);
    *(char *)(iVar4 + 0x33c) = (char)*(undefined4 *)(puVar7 + iVar2 + 0xc);
    *(byte *)(uVar3 + 0xe4) = *(byte *)(iVar4 + 0x33c) & 1;
    *(undefined *)(iVar4 + 0x33f) = puVar7[iVar2 + 9];
    *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 8;
    if (*(short *)(uVar3 + 0x46) == 0x6a2) {
      if ((lbl_803DE6F0 <= lbl_803E3840) && (param_11 != 0)) {
        sVar1 = *(short *)(param_11 + 0x46);
        if (sVar1 == 0x69) {
LAB_801585f4:
          FUN_80006824(uVar3,SFXen_blkscrp6);
        }
        else if (sVar1 < 0x69) {
          if (sVar1 == 0) goto LAB_801585f4;
        }
        else if (sVar1 == 0x416) {
          FUN_80006824(uVar3,0x36e);
        }
        FUN_80006824(uVar3,0x4aa);
        lbl_803DE6F0 = lbl_803E3844;
      }
    }
    else {
      FUN_80006824(uVar3,SFXfox_outofwater122);
    }
    if ((int)(uint)*(ushort *)(iVar4 + 0x2b0) < iVar6) {
      *(undefined2 *)(iVar4 + 0x2b0) = 0;
    }
    else {
      *(ushort *)(iVar4 + 0x2b0) = *(ushort *)(iVar4 + 0x2b0) - (short)iVar6;
    }
    if ((*(short *)(iVar4 + 0x2b0) == 0) && (*(char *)(iVar4 + 0x33b) == '\0')) {
      FUN_80158114(uVar3);
    }
    goto LAB_80158928;
  }
  if (param_12 == 0x11) goto LAB_80158928;
  if (*(short *)(uVar3 + 0x46) == 0x6a2) {
    if ((lbl_803DE6F0 <= lbl_803E3840) && (param_11 != 0)) {
      sVar1 = *(short *)(param_11 + 0x46);
      if (sVar1 == 0x69) {
LAB_80158484:
        FUN_80006824(uVar3,SFXen_blkscrp6);
      }
      else if (sVar1 < 0x69) {
        if (sVar1 == 0) goto LAB_80158484;
      }
      else if (sVar1 == 0x416) {
        FUN_80006824(uVar3,0x36e);
      }
      lbl_803DE6F0 = lbl_803E3844;
    }
  }
  else {
    FUN_80006824(uVar3,SFXfox_swimstroke422);
  }
  *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x10;
LAB_80158928:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80158c58
 * EN v1.0 Address: 0x80158C58
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80158940
 * EN v1.1 Size: 1944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80158c58(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80158c5c
 * EN v1.0 Address: 0x80158C5C
 * EN v1.0 Size: 2244b
 * EN v1.1 Address: 0x801590D8
 * EN v1.1 Size: 1624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80158c5c(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  ushort *puVar4;
  int iVar5;
  int iVar6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  undefined *puVar10;
  undefined *puVar11;
  float *pfVar12;
  double dVar13;
  undefined8 extraout_f1;
  double dVar14;
  undefined8 uVar15;
  
  uVar15 = FUN_80286834();
  puVar4 = (ushort *)((ulonglong)uVar15 >> 0x20);
  iVar6 = (int)uVar15;
  uVar2 = (uint)*(byte *)(iVar6 + 0x33b);
  pfVar12 = (float *)(&PTR_DAT_80320748)[uVar2 * 8];
  puVar11 = (&PTR_DAT_80320740)[uVar2 * 8];
  puVar10 = (&PTR_DAT_80320744)[uVar2 * 8];
  puVar9 = (&PTR_DAT_8032074c)[uVar2 * 8];
  puVar8 = (&PTR_DAT_8032073c)[uVar2 * 8];
  puVar7 = (&PTR_DAT_80320750)[uVar2 * 8];
  if ((*(int *)(iVar6 + 0x29c) != 0) && (*(short *)(*(int *)(iVar6 + 0x29c) + 0x44) == 1)) {
    FUN_80017668();
  }
  if ((*(uint *)(iVar6 + 0x2dc) & 0x80000000) != 0) {
    if (*(char *)(iVar6 + 0x33b) == '\0') {
      (**(code **)(*DAT_803dd6d0 + 0x24))(0,0x6c,0);
    }
    *(byte *)(iVar6 + 0x33d) = *(byte *)(iVar6 + 0x33d) | 0x10;
    *(undefined *)(iVar6 + 0x33a) = 0;
    if (puVar4[0x23] == 0x6a2) {
      FUN_80006824((uint)puVar4,0x4a9);
      if (*(int *)(puVar4 + 100) != 0) {
        FUN_8020a3fc(*(int *)(puVar4 + 100));
      }
    }
  }
  fVar1 = lbl_803E3840;
  dVar14 = (double)*(float *)(iVar6 + 0x328);
  dVar13 = (double)lbl_803E3840;
  if (((dVar14 != dVar13) && (*(char *)(iVar6 + 0x33f) != '\0')) &&
     (*(float *)(iVar6 + 0x328) = (float)(dVar14 - (double)lbl_803DC074),
     (double)*(float *)(iVar6 + 0x328) <= dVar13)) {
    *(float *)(iVar6 + 0x328) = fVar1;
    *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) | 0x40000000;
    *(char *)(iVar6 + 0x33c) =
         (char)*(undefined4 *)(puVar9 + (uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 0xc);
    *(byte *)(puVar4 + 0x72) = *(byte *)(iVar6 + 0x33c) & 1;
    *(undefined *)(iVar6 + 0x33f) = puVar9[(uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 10];
  }
  iVar5 = FUN_8014c78c(puVar4,1,0x28,&DAT_803ad108);
  uVar15 = extraout_f1;
  if (iVar5 < 1) {
    if ((*(uint *)(iVar6 + 0x2dc) & 0x40000000) != 0) {
      *(byte *)(iVar6 + 0x33d) = *(byte *)(iVar6 + 0x33d) & 0xcf;
      if ((puVar4[0x23] == 0x6a2) && (*(int *)(puVar4 + 100) != 0)) {
        FUN_8020a3fc(*(int *)(puVar4 + 100));
      }
      if (*(byte *)(iVar6 + 0x33f) == 0) {
        iVar5 = (uint)*(byte *)(iVar6 + 0x33e) * 0xc;
        puVar9 = puVar8 + iVar5;
        if ((*(uint *)(iVar6 + 0x2dc) & *(uint *)(puVar9 + 4)) == 0) {
          iVar5 = (uint)*(ushort *)(iVar6 + 0x2a0) * 0xc;
          if ((byte)puVar10[iVar5 + 8] == 0) {
            uVar2 = randomGetRange(1,(uint)(byte)puVar11[8]);
            iVar5 = (uVar2 & 0xff) * 0xc;
            uVar15 = FUN_8014d4c8((double)*(float *)(puVar11 + iVar5),dVar14,param_3,param_4,param_5
                                  ,param_6,param_7,param_8,(int)puVar4,iVar6,
                                  (uint)(byte)puVar11[iVar5 + 8],0,(uint)(byte)puVar11[iVar5 + 10],
                                  puVar9,in_r9,in_r10);
          }
          else {
            uVar15 = FUN_8014d4c8((double)*(float *)(puVar10 + iVar5),dVar14,param_3,param_4,param_5
                                  ,param_6,param_7,param_8,(int)puVar4,iVar6,
                                  (uint)(byte)puVar10[iVar5 + 8],0,(uint)(byte)puVar10[iVar5 + 10],
                                  puVar9,in_r9,in_r10);
          }
        }
        else {
          iVar3 = (uint)*(ushort *)(iVar6 + 0x2a0) * 0xc;
          if ((byte)puVar10[iVar3 + 8] == 0) {
            uVar15 = FUN_8014d4c8((double)*(float *)(puVar8 + iVar5),dVar14,param_3,param_4,param_5,
                                  param_6,param_7,param_8,(int)puVar4,iVar6,(uint)(byte)puVar9[8],0,
                                  (uint)(byte)puVar9[10],puVar9,in_r9,in_r10);
          }
          else {
            uVar15 = FUN_8014d4c8((double)*(float *)(puVar10 + iVar3),dVar14,param_3,param_4,param_5
                                  ,param_6,param_7,param_8,(int)puVar4,iVar6,
                                  (uint)(byte)puVar10[iVar3 + 8],0,(uint)(byte)puVar10[iVar3 + 10],
                                  puVar9,in_r9,in_r10);
          }
        }
        *(undefined *)(iVar6 + 0x33e) = puVar8[(uint)*(byte *)(iVar6 + 0x33e) * 0xc + 9];
      }
      else {
        iVar5 = (uint)*(byte *)(iVar6 + 0x33f) * 0x10;
        uVar15 = FUN_8014d4c8((double)*(float *)(puVar9 + iVar5),dVar14,param_3,param_4,param_5,
                              param_6,param_7,param_8,(int)puVar4,iVar6,
                              (uint)(byte)puVar9[iVar5 + 8],0,*(uint *)(puVar9 + iVar5 + 4) & 0xff,
                              in_r8,in_r9,in_r10);
        *(char *)(iVar6 + 0x33c) =
             (char)*(undefined4 *)(puVar9 + (uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 0xc);
        *(byte *)(puVar4 + 0x72) = *(byte *)(iVar6 + 0x33c) & 1;
        *(undefined *)(iVar6 + 0x33f) = puVar9[(uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 9];
      }
    }
  }
  else if (((*(byte *)(iVar6 + 0x33d) & 0x20) == 0) ||
          ((*(uint *)(iVar6 + 0x2dc) & 0x40000000) != 0)) {
    if (*(byte *)(iVar6 + 0x33f) == 0) {
      dVar14 = -(double)(*(float *)(puVar4 + 0x10) - *(float *)(DAT_803ad108 + 0x20));
      uVar2 = FUN_80017730();
      uVar2 = (uVar2 & 0xffff) - (uint)*puVar4;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      uVar2 = (uVar2 & 0xffff) >> 0xd;
      if ((uVar2 == 0) || (6 < uVar2)) {
        uVar15 = FUN_8014d4c8((double)*pfVar12,dVar14,param_3,param_4,param_5,param_6,param_7,
                              param_8,(int)puVar4,iVar6,(uint)*(byte *)(pfVar12 + 2),0,
                              (uint)*(byte *)((int)pfVar12 + 10),in_r8,in_r9,in_r10);
      }
      else if ((uVar2 < 3) || (4 < uVar2)) {
        iVar5 = (uint)*(ushort *)(iVar6 + 0x2a0) * 0xc;
        if ((byte)puVar10[iVar5 + 8] == 0) {
          iVar5 = (uint)*(byte *)(iVar6 + 0x33e) * 0xc;
          uVar15 = FUN_8014d4c8((double)*(float *)(puVar8 + iVar5),dVar14,param_3,param_4,param_5,
                                param_6,param_7,param_8,(int)puVar4,iVar6,
                                (uint)(byte)puVar8[iVar5 + 8],0,(uint)(byte)puVar8[iVar5 + 10],in_r8
                                ,in_r9,in_r10);
          *(undefined *)(iVar6 + 0x33e) = puVar8[(uint)*(byte *)(iVar6 + 0x33e) * 0xc + 9];
        }
        else {
          uVar15 = FUN_8014d4c8((double)*(float *)(puVar10 + iVar5),dVar14,param_3,param_4,param_5,
                                param_6,param_7,param_8,(int)puVar4,iVar6,
                                (uint)(byte)puVar10[iVar5 + 8],0,(uint)(byte)puVar10[iVar5 + 10],
                                in_r8,in_r9,in_r10);
        }
      }
      else {
        uVar2 = randomGetRange(1,(uint)(byte)puVar11[8]);
        iVar5 = (uVar2 & 0xff) * 0xc;
        uVar15 = FUN_8014d4c8((double)*(float *)(puVar11 + iVar5),dVar14,param_3,param_4,param_5,
                              param_6,param_7,param_8,(int)puVar4,iVar6,
                              (uint)(byte)puVar11[iVar5 + 8],0,(uint)(byte)puVar11[iVar5 + 10],in_r8
                              ,in_r9,in_r10);
      }
      *(byte *)(iVar6 + 0x33d) = *(byte *)(iVar6 + 0x33d) | 0x20;
      *(byte *)(iVar6 + 0x33d) = *(byte *)(iVar6 + 0x33d) & 0xef;
    }
    else {
      iVar5 = (uint)*(byte *)(iVar6 + 0x33f) * 0x10;
      uVar15 = FUN_8014d4c8((double)*(float *)(puVar9 + iVar5),dVar14,param_3,param_4,param_5,
                            param_6,param_7,param_8,(int)puVar4,iVar6,(uint)(byte)puVar9[iVar5 + 8],
                            0,*(uint *)(puVar9 + iVar5 + 4) & 0xff,in_r8,in_r9,in_r10);
      *(char *)(iVar6 + 0x33c) =
           (char)*(undefined4 *)(puVar9 + (uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 0xc);
      *(byte *)(puVar4 + 0x72) = *(byte *)(iVar6 + 0x33c) & 1;
      *(undefined *)(iVar6 + 0x33f) = puVar9[(uint)*(byte *)(iVar6 + 0x33f) * 0x10 + 9];
    }
  }
  *(undefined *)(*(int *)(puVar4 + 0x2a) + 0x6e) = 0;
  *(undefined *)(*(int *)(puVar4 + 0x2a) + 0x6f) = 0;
  iVar5 = 1;
  uVar2 = (uint)(byte)puVar7[8];
  puVar8 = puVar7;
  do {
    if (uVar2 == 0) {
LAB_801596cc:
      if (((*(byte *)(iVar6 + 0x323) & 8) == 0) && ((*(byte *)(iVar6 + 0x33d) & 0x10) == 0)) {
        dVar14 = (double)*(float *)(*(int *)(iVar6 + 0x29c) + 0x14);
        uVar15 = FUN_8014d3d0((short *)puVar4,iVar6,0x1e,0);
      }
      FUN_8015853c(uVar15,dVar14,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_80286880();
      return;
    }
    if (puVar4[0x50] == (ushort)(byte)puVar8[0x14]) {
      *(char *)(*(int *)(puVar4 + 0x2a) + 0x6e) = (char)*(undefined4 *)(puVar7 + iVar5 * 0xc + 4);
      *(undefined *)(*(int *)(puVar4 + 0x2a) + 0x6f) = puVar7[iVar5 * 0xc + 9];
      if (*(char *)(*(int *)(puVar4 + 0x2a) + 0x6e) == '\x1f') {
        *(uint *)(iVar6 + 0x2e8) = *(uint *)(iVar6 + 0x2e8) | 0x40;
      }
      else {
        *(uint *)(iVar6 + 0x2e8) = *(uint *)(iVar6 + 0x2e8) & 0xffffffbf;
      }
      goto LAB_801596cc;
    }
    iVar5 = iVar5 + 1;
    uVar2 = uVar2 - 1;
    puVar8 = puVar8 + 0xc;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_80159520
 * EN v1.0 Address: 0x80159520
 * EN v1.0 Size: 1216b
 * EN v1.1 Address: 0x80159730
 * EN v1.1 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80159520(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_8028683c();
  psVar3 = (short *)((ulonglong)uVar12 >> 0x20);
  iVar4 = (int)uVar12;
  uVar2 = (uint)*(byte *)(iVar4 + 0x33b);
  puVar9 = (&PTR_DAT_80320748)[uVar2 * 8];
  puVar8 = (&PTR_DAT_80320750)[uVar2 * 8];
  puVar7 = (&PTR_DAT_80320744)[uVar2 * 8];
  puVar6 = (&PTR_DAT_8032074c)[uVar2 * 8];
  if ((*(int *)(iVar4 + 0x29c) != 0) && (*(short *)(*(int *)(iVar4 + 0x29c) + 0x44) == 1)) {
    FUN_80017668();
  }
  if ((*(uint *)(iVar4 + 0x2dc) & 0x80000000) != 0) {
    if (*(char *)(iVar4 + 0x33b) == '\0') {
      (**(code **)(*DAT_803dd6d0 + 0x24))(0,0x6c,0);
    }
    if ((psVar3[0x23] == 0x6a2) && (*(int *)(psVar3 + 100) != 0)) {
      FUN_8020a3fc(*(int *)(psVar3 + 100));
    }
    *(byte *)(iVar4 + 0x33d) = *(byte *)(iVar4 + 0x33d) | 0x10;
  }
  fVar1 = lbl_803E3840;
  dVar11 = (double)*(float *)(iVar4 + 0x328);
  dVar10 = (double)lbl_803E3840;
  if (((dVar11 != dVar10) && (*(char *)(iVar4 + 0x33f) != '\0')) &&
     (*(float *)(iVar4 + 0x328) = (float)(dVar11 - (double)lbl_803DC074),
     (double)*(float *)(iVar4 + 0x328) <= dVar10)) {
    *(float *)(iVar4 + 0x328) = fVar1;
    *(uint *)(iVar4 + 0x2dc) = *(uint *)(iVar4 + 0x2dc) | 0x40000000;
    *(char *)(iVar4 + 0x33c) =
         (char)*(undefined4 *)(puVar6 + (uint)*(byte *)(iVar4 + 0x33f) * 0x10 + 0xc);
    *(byte *)(psVar3 + 0x72) = *(byte *)(iVar4 + 0x33c) & 1;
    *(undefined *)(iVar4 + 0x33f) = puVar6[(uint)*(byte *)(iVar4 + 0x33f) * 0x10 + 10];
  }
  if ((*(uint *)(iVar4 + 0x2dc) & 0x40000000) != 0) {
    *(byte *)(iVar4 + 0x33d) = *(byte *)(iVar4 + 0x33d) & 0xcf;
    if ((psVar3[0x23] == 0x6a2) && (*(int *)(psVar3 + 100) != 0)) {
      FUN_8020a3fc(*(int *)(psVar3 + 100));
    }
    if (*(byte *)(iVar4 + 0x33f) == 0) {
      iVar5 = (uint)*(ushort *)(iVar4 + 0x2a0) * 0xc;
      if ((byte)puVar7[iVar5 + 8] == 0) {
        if (0x4f < *(ushort *)(iVar4 + 0x2a4)) {
          *(undefined *)(iVar4 + 0x33a) = 0;
        }
        FUN_8014c78c(psVar3,6,0x28,&DAT_803ad108);
        if (((*(uint *)(iVar4 + 0x2dc) &
             *(uint *)(puVar9 + (uint)*(byte *)(iVar4 + 0x33a) * 0xc + 4)) == 0) &&
           (puVar9[(uint)*(byte *)(iVar4 + 0x33a) * 0xc + 9] != '\0')) {
          *(undefined *)(iVar4 + 0x33a) = puVar9[(uint)*(byte *)(iVar4 + 0x33a) * 0xc + 9];
        }
        iVar5 = (uint)*(byte *)(iVar4 + 0x33a) * 0xc;
        dVar10 = (double)FUN_8014d4c8((double)*(float *)(puVar9 + iVar5),dVar11,param_3,param_4,
                                      param_5,param_6,param_7,param_8,(int)psVar3,iVar4,
                                      (uint)(byte)puVar9[iVar5 + 8],0,(uint)(byte)puVar9[iVar5 + 10]
                                      ,in_r8,in_r9,in_r10);
        *(undefined *)(iVar4 + 0x33a) = puVar9[(uint)*(byte *)(iVar4 + 0x33a) * 0xc + 9];
      }
      else {
        dVar10 = (double)FUN_8014d4c8((double)*(float *)(puVar7 + iVar5),dVar11,param_3,param_4,
                                      param_5,param_6,param_7,param_8,(int)psVar3,iVar4,
                                      (uint)(byte)puVar7[iVar5 + 8],0,(uint)(byte)puVar7[iVar5 + 10]
                                      ,in_r8,in_r9,in_r10);
      }
    }
    else {
      iVar5 = (uint)*(byte *)(iVar4 + 0x33f) * 0x10;
      dVar10 = (double)FUN_8014d4c8((double)*(float *)(puVar6 + iVar5),dVar11,param_3,param_4,
                                    param_5,param_6,param_7,param_8,(int)psVar3,iVar4,
                                    (uint)(byte)puVar6[iVar5 + 8],0,
                                    *(uint *)(puVar6 + iVar5 + 4) & 0xff,in_r8,in_r9,in_r10);
      *(char *)(iVar4 + 0x33c) =
           (char)*(undefined4 *)(puVar6 + (uint)*(byte *)(iVar4 + 0x33f) * 0x10 + 0xc);
      *(byte *)(psVar3 + 0x72) = *(byte *)(iVar4 + 0x33c) & 1;
      *(undefined *)(iVar4 + 0x33f) = puVar6[(uint)*(byte *)(iVar4 + 0x33f) * 0x10 + 9];
    }
  }
  *(undefined *)(*(int *)(psVar3 + 0x2a) + 0x6e) = 0;
  *(undefined *)(*(int *)(psVar3 + 0x2a) + 0x6f) = 0;
  iVar5 = 1;
  uVar2 = (uint)(byte)puVar8[8];
  puVar6 = puVar8;
  do {
    if (uVar2 == 0) {
LAB_80159a9c:
      if (((*(byte *)(iVar4 + 0x323) & 8) == 0) && ((*(byte *)(iVar4 + 0x33d) & 0x10) == 0)) {
        dVar11 = (double)*(float *)(*(int *)(iVar4 + 0x29c) + 0x14);
        dVar10 = (double)FUN_8014d3d0(psVar3,iVar4,0x1e,0);
      }
      FUN_8015853c(dVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_80286888();
      return;
    }
    if (psVar3[0x50] == (ushort)(byte)puVar6[0x14]) {
      *(char *)(*(int *)(psVar3 + 0x2a) + 0x6e) = (char)*(undefined4 *)(puVar8 + iVar5 * 0xc + 4);
      *(undefined *)(*(int *)(psVar3 + 0x2a) + 0x6f) = puVar8[iVar5 * 0xc + 9];
      if (*(char *)(*(int *)(psVar3 + 0x2a) + 0x6e) == '\x1f') {
        *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) | 0x40;
      }
      else {
        *(uint *)(iVar4 + 0x2e8) = *(uint *)(iVar4 + 0x2e8) & 0xffffffbf;
      }
      goto LAB_80159a9c;
    }
    iVar5 = iVar5 + 1;
    uVar2 = uVar2 - 1;
    puVar6 = puVar6 + 0xc;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_801599e0
 * EN v1.0 Address: 0x801599E0
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x80159B00
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801599e0(int param_1,int param_2)
{
  short sVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  *(undefined4 *)(param_2 + 0x2e4) = 0xb;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x400b0;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x40001040;
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x6a3) {
    *(float *)(param_2 + 0x2ac) = lbl_803E387C;
    *(float *)(param_2 + 0x2a8) = lbl_803E3850;
    *(undefined2 *)(param_2 + 0x2b0) = 0x1e;
    *(undefined *)(param_2 + 0x33b) = 0;
    *(undefined *)(param_2 + 800) = 9;
    fVar2 = lbl_803E3880;
    *(float *)(param_2 + 0x314) = lbl_803E3880;
    *(undefined *)(param_2 + 0x321) = 0xc;
    *(float *)(param_2 + 0x318) = lbl_803E3884;
    *(undefined *)(param_2 + 0x322) = 9;
    *(float *)(param_2 + 0x31c) = fVar2;
    *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x400;
  }
  else if (sVar1 < 0x6a3) {
    if (0x6a1 < sVar1) {
      *(float *)(param_2 + 0x2ac) = lbl_803E3888;
      *(float *)(param_2 + 0x2a8) = lbl_803E3850;
      *(undefined2 *)(param_2 + 0x2b0) = 0x32;
      *(undefined *)(param_2 + 0x33b) = 1;
      *(undefined *)(param_2 + 800) = 0xe;
      fVar2 = lbl_803E3880;
      *(float *)(param_2 + 0x314) = lbl_803E3880;
      *(undefined *)(param_2 + 0x321) = 0xd;
      *(float *)(param_2 + 0x318) = lbl_803E3884;
      *(undefined *)(param_2 + 0x322) = 0xe;
      *(float *)(param_2 + 0x31c) = fVar2;
      *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0xc00;
    }
  }
  else if (sVar1 < 0x6a5) {
    *(float *)(param_2 + 0x2ac) = lbl_803E388C;
    *(float *)(param_2 + 0x2a8) = lbl_803E3890;
    *(undefined2 *)(param_2 + 0x2b0) = 0xf;
    *(undefined *)(param_2 + 0x33b) = 2;
    *(undefined *)(param_2 + 800) = 0xd;
    fVar2 = lbl_803E3880;
    *(float *)(param_2 + 0x314) = lbl_803E3880;
    *(undefined *)(param_2 + 0x321) = 0x10;
    *(float *)(param_2 + 0x318) = lbl_803E3884;
    *(undefined *)(param_2 + 0x322) = 0xd;
    *(float *)(param_2 + 0x31c) = fVar2;
    *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0xc00;
  }
  *(float *)(param_2 + 0x308) = lbl_803E386C;
  *(float *)(param_2 + 0x300) = lbl_803E3894;
  *(float *)(param_2 + 0x304) = lbl_803E3898;
  *(float *)(param_2 + 0x2fc) = *(float *)(param_2 + 0x2fc) * lbl_803E389C;
  if (*(char *)(iVar3 + 0x2e) != -1) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 1;
  }
  *(float *)(param_1 + 8) =
       lbl_803E38A0 +
       (float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar3 + 0x28) ^ 0x80000000) -
              DOUBLE_803e3830) / lbl_803E38A4;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80159bd0
 * EN v1.0 Address: 0x80159BD0
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x80159CE8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80159bd0(undefined4 param_1,undefined4 param_2,float *param_3,undefined4 param_4,
                 uint param_5)
{
  double dVar1;
  float afStack_48 [12];
  undefined4 local_18;
  uint uStack_14;
  
  uStack_14 = param_5 ^ 0x80000000;
  local_18 = 0x43300000;
  dVar1 = (double)FUN_802949e8();
  PSVECDotProduct((double)(float)((double)lbl_803E38B4 * dVar1),afStack_48,0x79);
  FUN_80247cd8(afStack_48,param_3,param_3);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80159c3c
 * EN v1.0 Address: 0x80159C3C
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80159D64
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80159c3c(int param_1)
{
  FUN_80006810(param_1,1000);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80159c60
 * EN v1.0 Address: 0x80159C60
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x80159D88
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80159c60(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if (param_4 != 0x11) {
    if (param_4 == 0x10) {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
    }
    else {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
      FUN_80006810(param_1,1000);
      FUN_80006824(param_1,0x3ea);
      *(undefined2 *)(param_2 + 0x2b0) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80159cdc
 * EN v1.0 Address: 0x80159CDC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80159E04
 * EN v1.1 Size: 1652b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80159cdc(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,double param_6,double param_7,undefined8 param_8,ushort *param_9,
                 undefined4 *param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80159ce0
 * EN v1.0 Address: 0x80159CE0
 * EN v1.0 Size: 1596b
 * EN v1.1 Address: 0x8015A478
 * EN v1.1 Size: 1112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80159ce0(short *param_1,int *param_2)
{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int *piVar5;
  int iVar6;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 in_f8;
  undefined auStack_4c [6];
  undefined2 local_46;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  iVar7 = *param_2;
  if ((param_2[0xd0] != 0) && (param_2[0xd0] == param_2[0xa7])) {
    param_2[0xb9] = param_2[0xb9] | 0x10000;
    param_2[0xcc] = (int)lbl_803E390C;
  }
  param_2[0xba] = param_2[0xba] | 0x100;
  local_40 = lbl_803E38C8;
  local_3c = lbl_803E38CC;
  local_38 = lbl_803E38C8;
  local_44 = lbl_803E38BC;
  local_46 = 0x605;
  if ((param_1[0x58] & 0x800U) != 0) {
    in_r8 = 0;
    in_r9 = *DAT_803dd708;
    (**(code **)(in_r9 + 8))(param_1,1999,auStack_4c,2,0xffffffff);
    piVar5 = (int *)param_2[0xda];
    if (piVar5 != (int *)0x0) {
      FUN_800175ec((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                   (double)*(float *)(param_1 + 10),piVar5);
    }
    else {
      if (piVar5 == (int *)0x0) {
        piVar5 = FUN_80017624(0,'\x01');
        param_2[0xda] = (int)piVar5;
      }
      if (param_2[0xda] != 0) {
        FUN_800175b0(param_2[0xda],2);
        FUN_800175ec((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                     (double)*(float *)(param_1 + 10),(int *)param_2[0xda]);
        FUN_8001759c(param_2[0xda],0xc0,0x40,0xff,0xff);
        FUN_80017588(param_2[0xda],0xc0,0x40,0xff,0xff);
        FUN_800175d0((double)lbl_803E38A8,(double)lbl_803E38AC,param_2[0xda]);
        FUN_800175bc(param_2[0xda],1);
        FUN_800175cc((double)lbl_803E38B0,param_2[0xda],'\x01');
        FUN_8001753c(param_2[0xda],0,0);
        FUN_800175d8(param_2[0xda],0);
      }
    }
  }
  if ((param_2[0xb7] & 0x80000000U) != 0) {
    *(undefined *)((int)param_2 + 0x33a) = 3;
    param_2[0xb7] = param_2[0xb7] | 0x40000000;
  }
  iVar6 = param_2[0xa7];
  dVar10 = (double)lbl_803E38E0;
  dVar8 = (double)(float)(dVar10 + (double)*(float *)(iVar6 + 0x1c));
  dVar9 = (double)*(float *)(iVar6 + 0x20);
  dVar11 = (double)lbl_803E3910;
  dVar12 = (double)lbl_803E38E8;
  dVar13 = (double)(float)param_2[0xc1];
  FUN_8014cfac((double)*(float *)(iVar6 + 0x18),dVar8,dVar9,dVar10,dVar11,dVar12,dVar13,(int)param_1
              );
  if ((param_2[0xb7] & 0x40000000U) != 0) {
    iVar6 = (uint)*(byte *)((int)param_2 + 0x33a) * 0xc;
    FUN_8014d4c8((double)*(float *)(&DAT_803207c0 + iVar6),dVar8,dVar9,dVar10,dVar11,dVar12,dVar13,
                 in_f8,(int)param_1,(int)param_2,(uint)(byte)(&DAT_803207c8)[iVar6],0,0,in_r8,in_r9,
                 in_r10);
    *(undefined *)((int)param_2 + 0x33a) =
         (&DAT_803207c9)[(uint)*(byte *)((int)param_2 + 0x33a) * 0xc];
  }
  dVar8 = (double)FUN_80293130((double)(float)param_2[0xc1],(double)lbl_803DC074);
  uStack_2c = (int)param_1[1] ^ 0x80000000;
  local_30 = 0x43300000;
  iVar6 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e38c0) * dVar8);
  local_28 = (longlong)iVar6;
  param_1[1] = (short)iVar6;
  dVar8 = (double)FUN_80293130((double)(float)param_2[0xc1],(double)lbl_803DC074);
  local_20 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
  param_1[2] = (short)(int)((double)(float)(local_20 - DOUBLE_803e38c0) * dVar8);
  if (lbl_803E3908 <= (float)param_2[0xc9]) {
    param_2[0xc9] = (int)lbl_803E3908;
  }
  else {
    param_2[0xc9] = (int)(lbl_803E38EC * lbl_803DC074 + (float)param_2[0xc9]);
  }
  local_18 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
  iVar6 = (int)((float)param_2[0xc9] * lbl_803DC074 + (float)(local_18 - DOUBLE_803e38c0));
  local_20 = (double)(longlong)iVar6;
  *param_1 = (short)iVar6;
  param_2[0xca] = (int)lbl_803E38D0;
  if ((param_2[0xb7] & 0x2000U) != 0) {
    fVar2 = *(float *)(iVar7 + 0x68) - *(float *)(param_1 + 0xc);
    fVar3 = *(float *)(iVar7 + 0x6c) - *(float *)(param_1 + 0xe);
    fVar4 = *(float *)(iVar7 + 0x70) - *(float *)(param_1 + 0x10);
    dVar8 = FUN_80293900((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
    param_2[0xcb] = (int)(float)dVar8;
    if (lbl_803E38D8 < (float)param_2[0xcb]) {
      param_2[0xb9] = param_2[0xb9] | 0x10000;
      param_2[0xcc] = (int)lbl_803E38C8;
    }
  }
  if ((float)param_2[0xc9] <= lbl_803E38C8) {
    FUN_80006810((int)param_1,1000);
  }
  else {
    FUN_80006824((uint)param_1,1000);
    iVar7 = (int)((lbl_803E3904 * (float)param_2[0xc9]) / lbl_803E3908);
    local_18 = (double)(longlong)iVar7;
    FUN_80006818((double)((float)param_2[0xc9] / lbl_803E3908),(int)param_1,1000,(byte)iVar7);
  }
  if ((param_2[0xd0] != 0) &&
     ((sVar1 = *(short *)(param_2[0xd0] + 0x46), sVar1 == 0x1f || (sVar1 == 0)))) {
    FUN_80006824((uint)param_1,SFXfox_swimstroke322);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015a31c
 * EN v1.0 Address: 0x8015A31C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8015A8D0
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015a31c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8015a320
 * EN v1.0 Address: 0x8015A320
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x8015A9D8
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015a320(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar4;
  
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_80017aa4(0x24,0x51b);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar4 = (double)lbl_803E3930;
    *(float *)(puVar2 + 6) = (float)(dVar4 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    iVar3 = FUN_80017ae4(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff
                         ,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar3 != 0) {
      dVar4 = (double)FUN_80293f90();
      *(float *)(iVar3 + 0x24) = (float)((double)lbl_803E3934 * -dVar4);
      *(float *)(iVar3 + 0x28) = lbl_803E3940;
      dVar4 = (double)FUN_80294964();
      *(float *)(iVar3 + 0x2c) = (float)((double)lbl_803E3934 * -dVar4);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015a4c4
 * EN v1.0 Address: 0x8015A4C4
 * EN v1.0 Size: 508b
 * EN v1.1 Address: 0x8015AB0C
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015a4c4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int in_r6;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar5 >> 0x20);
  iVar3 = (int)uVar5;
  puVar4 = (&PTR_DAT_8032099c)[(uint)*(ushort *)(iVar3 + 0x338) * 2];
  if (in_r6 != 0x11) {
    if (in_r6 == 0x10) {
      *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 0x20;
    }
    else {
      if (*(ushort *)(iVar3 + 0x2a0) < 4) {
        FUN_8014d4c8((double)lbl_803E3950,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     uVar1,iVar3,5,0,0,in_r8,in_r9,in_r10);
      }
      else {
        FUN_8014d4c8((double)lbl_803E3950,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     uVar1,iVar3,6,0,0,in_r8,in_r9,in_r10);
      }
      uVar2 = randomGetRange(0,3);
      *(undefined *)(iVar3 + 0x33a) = puVar4[uVar2];
      *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 8;
      if ((int)(uint)*(ushort *)(iVar3 + 0x2b0) < in_r8) {
        *(undefined2 *)(iVar3 + 0x2b0) = 0;
      }
      else {
        *(ushort *)(iVar3 + 0x2b0) = *(ushort *)(iVar3 + 0x2b0) - (short)in_r8;
      }
      if (*(short *)(iVar3 + 0x2b0) == 0) {
        FUN_80006824(uVar1,0x49e);
      }
      if (in_r6 != 0x1a) {
        FUN_80006824(uVar1,SFXen_blkscrp6);
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015a6c0
 * EN v1.0 Address: 0x8015A6C0
 * EN v1.0 Size: 432b
 * EN v1.1 Address: 0x8015AC28
 * EN v1.1 Size: 424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015a6c0(uint param_1,int param_2)
{
  bool bVar1;
  
  bVar1 = false;
  switch(*(undefined2 *)(param_1 + 0xa0)) {
  case 2:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      FUN_800067e8(param_1,0x49b,2);
    }
    bVar1 = true;
    break;
  case 3:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      FUN_80006824(param_1,0x498);
    }
    break;
  case 4:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      if (lbl_803E3954 <= *(float *)(param_1 + 0x98)) {
        FUN_80006824(param_1,SFXfox_fightbreath4);
      }
      else {
        FUN_80006824(param_1,0x499);
      }
    }
    break;
  case 5:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      FUN_80006824(param_1,0x49d);
    }
    break;
  case 6:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      FUN_80006824(param_1,0x49d);
    }
    break;
  case 7:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      FUN_800067e8(param_1,0x49c,2);
    }
    bVar1 = true;
    break;
  case 9:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      FUN_80006824(param_1,0x49a);
    }
  }
  if (bVar1) {
    if (*(short *)(param_2 + 0x338) == 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x809,0,2,0xffffffff,0);
    }
    else {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x802,0,2,0xffffffff,0);
    }
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void smallbasket_nop(void) {}

/* call(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void smallbasket_stopLoopSfx(int x) { Sfx_StopFromObject(x, 0x3e8); }
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E2CC0;
extern f32 lbl_803E2CC4;
extern f32 lbl_803E2CC8;
extern f32 lbl_803E2CCC;
extern f32 lbl_803E2CD0;
extern f32 lbl_803E2CD4;
extern u8 Obj_IsLoadingLocked(void);
extern int *Obj_AllocObjectSetup(int p1, int p2);
extern int *Obj_SetupObject(int *obj, int p1, int p2, int p3, int p4);
extern void firepipe_setLinkedUpdateFlag(int *obj);

/* Spawns the linked firepipe child object and attaches it to this basket. */
#pragma scheduling off
#pragma peephole off
void smallbasket_spawnLinkedFirepipe(int *obj) {
    int *child;
    if (Obj_IsLoadingLocked() != 0) {
        child = Obj_AllocObjectSetup(0x24, 0x710);
        ObjPath_GetPointWorldPosition(obj, 0, (char*)child + 0x8, (char*)child + 0xc, (char*)child + 0x10, 0);
        *((u8*)child + 0x4) = 1;
        *((u8*)child + 0x5) = 4;
        *((u8*)child + 0x6) = 0xff;
        *((u8*)child + 0x7) = 0xff;
        *((u8*)child + 0x18) = 0;
        *((u8*)child + 0x19) = 0;
        *(s16*)((char*)child + 0x1a) = 0;
        *(s16*)((char*)child + 0x1c) = 0xa;
        *(s16*)((char*)child + 0x1e) = 0;
        *(s16*)((char*)child + 0x20) = 0;
        *((u8*)child + 0x22) = 3;
        *((u8*)child + 0x23) = 0;
        child = Obj_SetupObject(child, 5, -1, -1, 0);
        if (child != 0) {
            ObjLink_AttachChild(obj, child, 0);
            firepipe_setLinkedUpdateFlag(child);
            *(s16*)((char*)child + 0x6) = (s16)(*(s16*)((char*)child + 0x6) | 0x4000);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E2B18;
extern f32 lbl_803E2B38;
extern f32 lbl_803E2B40;
extern f32 lbl_803E2B4C;
extern f64 lbl_803E2B58;
extern f32 lbl_803E2B64;
extern f32 lbl_803E2B68;
extern f32 lbl_803E2B6C;
extern f32 lbl_803E2B70;
extern f32 lbl_803E2B74;
extern f32 lbl_803E2B78;
extern f32 lbl_803E2C3C;
extern f32 lbl_803E2C58;
extern f32 lbl_803E2C7C;
extern f32 lbl_803E2C80;
extern f32 lbl_803E2C84;
extern f32 lbl_803E2C88;
extern f32 lbl_803E2C8C;
extern f32 lbl_803E2C90;
extern f32 lbl_803E2C94;
extern u8 lbl_8031FB70[];
extern u8 lbl_8031FC2C[];
extern int fn_8014D08C(int *obj, int *st, int p3, f32 f, int p5, int p6);
extern int *allocModelStruct2(int p1, int p2);
extern void tailFn_80026c38(int *p, f32 a, f32 b, f32 c);
extern int baddieAfterUpdateBonesCb(void);
extern f32 lbl_803E2CBC;
extern int *gPartfxInterface;
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern u8 lbl_8031FD48[];

extern void smallbasket_playReactionEffects(int *obj, int *st);

extern f32 lbl_803E2CB8;

/* Handles reaction event commands and updates the current reaction cue. */
#pragma scheduling off
#pragma peephole off
void smallbasket_handleReactionEvent(int obj, int *st, int p3, int cmd, int p5, int sub) {
    u8 *base;
    u32 r;

    {
        u8 *bbase;
        u32 idx;
        bbase = lbl_8031FD48;
        idx = *(u16*)((char*)st + 0x338);
        bbase = bbase + idx * 8;
        base = *(u8**)(bbase + 4);
    }

    if (cmd == 0x11) {
        return;
    }
    if (cmd == 0x10) {
        *(u32*)((char*)st + 0x2e8) |= 0x20;
        return;
    }
    if (*(u16*)((char*)st + 0x2a0) > 3) {
        fn_8014D08C((int*)obj, st, 6, lbl_803E2CB8, 0, 0);
    } else {
        fn_8014D08C((int*)obj, st, 5, lbl_803E2CB8, 0, 0);
    }
    r = randomGetRange(0, 3);
    *((u8*)st + 0x33a) = base[r];
    *(u32*)((char*)st + 0x2e8) |= 0x8;
    if (sub > (int)*(u16*)((char*)st + 0x2b0)) {
        *(u16*)((char*)st + 0x2b0) = 0;
    } else {
        *(u16*)((char*)st + 0x2b0) = (u16)(*(u16*)((char*)st + 0x2b0) - sub);
    }
    if (*(u16*)((char*)st + 0x2b0) == 0) {
        Sfx_PlayFromObject(obj, 0x49e);
    }
    if (cmd == 0x1a) return;
    Sfx_PlayFromObject(obj, SFXen_blkscrp6);
}
#pragma peephole reset
#pragma scheduling reset

/* Applies the current reaction table entry, then emits its effects. */
#pragma scheduling off
#pragma peephole off
void smallbasket_applyReactionState(int *obj, int *st) {
    u8 *t1;
    {
        u32 idx = *(u16*)((char*)st + 0x338);
        t1 = *(u8**)((char*)lbl_8031FD48 + idx * 8);
    }
    *((u8*)obj + 0xaf) = (u8)(*((u8*)obj + 0xaf) | 0x8);
    if ((*(u32*)((char*)st + 0x2dc) & 0x40000000) != 0) {
        s16 a = *(s16*)((char*)obj + 0xa0);
        if (a == 7) {
            *((u8*)st + 0x33a) = 1;
        } else if (a != 0) {
            *((u8*)st + 0x33a) = 0;
        }
        {
            u8 *bbase = t1;
            f32 *fbase = (f32*)t1;
            u32 idx2 = *((u8*)st + 0x33a);
            u32 off = idx2 * 0xc;
            fn_8014D08C(obj, st, bbase[off + 8],
                        *(f32*)((char*)fbase + off), 0, 0);
        }
    }
    smallbasket_playReactionEffects(obj, st);
}
#pragma peephole reset
#pragma scheduling reset

/* Plays reaction SFX/particles selected by the object reaction state. */
#pragma scheduling off
#pragma peephole off
void smallbasket_playReactionEffects(int *obj, int *st) {
    u16 flag = 0;
    switch (*(s16*)((char*)obj + 0xa0)) {
    case 2:
        if (*(u16*)((char*)st + 0x2f8) != 0) {
            Sfx_PlayFromObjectLimited((int*)obj, 0x49b, 2);
        }
        flag = 1;
        break;
    case 3:
        if (*(u16*)((char*)st + 0x2f8) != 0) {
            Sfx_PlayFromObject((int)obj, 0x498);
        }
        break;
    case 4:
        if (*(u16*)((char*)st + 0x2f8) != 0) {
            if (*(f32*)((char*)obj + 0x98) < lbl_803E2CBC) {
                Sfx_PlayFromObject((int)obj, 0x499);
            } else {
                Sfx_PlayFromObject((int)obj, SFXfox_fightbreath4);
            }
        }
        break;
    case 5:
        if (*(u16*)((char*)st + 0x2f8) != 0) {
            Sfx_PlayFromObject((int)obj, 0x49d);
        }
        break;
    case 6:
        if (*(u16*)((char*)st + 0x2f8) != 0) {
            Sfx_PlayFromObject((int)obj, 0x49d);
        }
        break;
    case 7:
        if (*(u16*)((char*)st + 0x2f8) != 0) {
            Sfx_PlayFromObjectLimited((int*)obj, 0x49c, 2);
        }
        flag = 1;
        break;
    case 9:
        if (*(u16*)((char*)st + 0x2f8) != 0) {
            Sfx_PlayFromObject((int)obj, 0x49a);
        }
        break;
    }
    if (flag != 0) {
        if (*(u16*)((char*)st + 0x338) != 0) {
            (*(void (**)(int*, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x802, 0, 2, -1, 0);
        } else {
            (*(void (**)(int*, int, int, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x809, 0, 2, -1, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

/* Initializes the tail-model variant state. */
#pragma scheduling off
#pragma peephole off
void smallbasket_initTailModelState(int *obj, int *st) {
    u8 *tab;
    *(f32*)((char*)st + 0x2ac) = lbl_803E2C7C;
    *(u32*)((char*)st + 0x2e4) = 0x405009;
    *(f32*)((char*)st + 0x304) = lbl_803E2C80;
    *((u8*)st + 0x320) = 0;
    {
        f32 d1 = lbl_803E2C84;
        *(f32*)((char*)st + 0x314) = d1;
        *((u8*)st + 0x321) = 0;
        *(f32*)((char*)st + 0x318) = lbl_803E2C3C;
        *((u8*)st + 0x322) = 0;
        *(f32*)((char*)st + 0x31c) = d1;
    }
    *(f32*)((char*)st + 0x2fc) = *(f32*)((char*)st + 0x2fc) * lbl_803E2C88;
    {
        f32 *fbase = (f32*)lbl_8031FB70;
        u8 *bbase = lbl_8031FB70;
        u32 idx = *((u8*)st + 0x33a);
        u32 off = idx * 0xc;
        fn_8014D08C(obj, st, bbase[off + 8],
                    *(f32*)((char*)fbase + off), 0, 0);
    }
    *(f32*)((char*)st + 0x328) = lbl_803E2C58;
    ObjHits_SetHitVolumeMasks(obj, 0xe, 1, 0xfff);
    *(int**)((char*)st + 0x36c) = allocModelStruct2((int)lbl_8031FC2C, 5);
    tailFn_80026c38(*(int**)((char*)st + 0x36c), lbl_803E2C8C, lbl_803E2C90, lbl_803E2C94);
    *(u32*)((char*)st + 0x2e8) = *(u32*)((char*)st + 0x2e8) | 0x100;
    *(int*)((char*)obj + 0x108) = (int)&baddieAfterUpdateBonesCb;
}
#pragma peephole reset
#pragma scheduling reset

/* Initializes a scaled smallbasket variant from placement params. */
#pragma scheduling off
#pragma peephole off
void smallbasket_initScaledVariantState(int *obj, int *st) {
    f32 ratio;
    f32 base_v;
    u32 v;
    u32 amt;
    amt = *((u8*)((int*)obj[0x4c/4]) + 0x2f);
    ratio = (f32)amt;
    if (lbl_803E2B18 == (f32)amt) {
        ratio = lbl_803E2B38;
    }
    ratio = ratio / lbl_803E2B38;
    *(f32*)((char*)st + 0x2ac) = lbl_803E2B64;
    *(u32*)((char*)st + 0x2e4) = 0x8b;
    v = *(u32*)((char*)st + 0x2e4);
    *(u32*)((char*)st + 0x2e4) = v | 0x20;
    *(f32*)((char*)st + 0x308) = lbl_803E2B68 * ratio;
    base_v = lbl_803E2B40;
    *(f32*)((char*)st + 0x300) = base_v;
    *(f32*)((char*)st + 0x304) = lbl_803E2B6C;
    *((u8*)st + 0x320) = 0;
    *(f32*)((char*)st + 0x314) = lbl_803E2B70;
    *((u8*)st + 0x321) = 3;
    {
        f32 d2 = lbl_803E2B4C;
        *(f32*)((char*)st + 0x318) = d2;
        *((u8*)st + 0x322) = 5;
        *(f32*)((char*)st + 0x31c) = d2;
    }
    *(u16*)((char*)st + 0x338) = 0;
    *(f32*)((char*)st + 0x324) = lbl_803E2B74;
    *(f32*)((char*)st + 0x328) = base_v;
    *((u8*)obj + 0x36) = 0;
    *(f32*)((char*)st + 0x2fc) = lbl_803E2B78 * ratio;
    *(u32*)((char*)st + 0x2e8) = 0;
    ObjHits_EnableObject((int)obj);
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E2C1C;
extern f32 lbl_803E2C20;
extern f32 lbl_803E2C24;
extern f64 lbl_803E2C28;
extern f32 fn_802943F4(f32 a);
extern void PSMTXRotRad(f32 *mtx, int axis, f32 angle);
extern void PSMTXMultVecSR(f32 *mtx, f32 *in, f32 *out);

/* Rotates a vector around the Y axis by an integer-degree value. */
#pragma scheduling off
#pragma peephole off
void smallbasket_rotateVectorYaw(int p1, int p2, f32 *vec, f32 f1, int p5, u32 int_deg) {
    f32 mtx[12];
    f32 a;
    a = lbl_803E2C20 * f1 - lbl_803E2C24 * (f32)(s32)int_deg;
    a = fn_802943F4(a);
    a = lbl_803E2C1C * a;
    PSMTXRotRad(mtx, 0x79, a);
    PSMTXMultVecSR(mtx, vec, vec);
}
#pragma peephole reset
#pragma scheduling reset

/* Handles hit-state events and restarts the impact SFX. */
#pragma scheduling off
#pragma peephole off
void smallbasket_handleHitStateEvent(int obj, int *st, int p3, int cmd) {
    if (cmd == 0x11) {
        /* fall through */
    } else if (cmd == 0x10) {
        *(u32*)((char*)st + 0x2e8) |= 0x20;
    } else {
        *(u32*)((char*)st + 0x2e8) |= 0x8;
        Sfx_StopFromObject(obj, 0x3e8);
        Sfx_PlayFromObject(obj, 0x3ea);
        *(s16*)((char*)st + 0x2b0) = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* Initializes the state used by the alternate smallbasket variant. */
#pragma scheduling off
#pragma peephole off
void smallbasket_initVariantState(int *obj, int *st) {
    *(f32*)((char*)st + 0x2ac) = lbl_803E2CC0;
    *((u8*)st + 0x33b) = *(f32*)((char*)st + 0x2a8);
    *(f32*)((char*)st + 0x2a8) = lbl_803E2CC4;
    *(u32*)((char*)st + 0x2e4) = 0x42003;
    *(f32*)((char*)st + 0x308) = lbl_803E2CC8;
    *(f32*)((char*)st + 0x300) = lbl_803E2CCC;
    *(f32*)((char*)st + 0x304) = lbl_803E2CD0;
    *((u8*)st + 0x320) = 0;
    {
        f32 d = lbl_803E2CD4;
        *(f32*)((char*)st + 0x314) = d;
        *((u8*)st + 0x321) = 0xa;
        *(f32*)((char*)st + 0x318) = d;
        *((u8*)st + 0x322) = 7;
        *(f32*)((char*)st + 0x31c) = d;
    }
    *((u8*)st + 0x33a) = 1;
    *(u16*)((char*)st + 0x338) = (u16)(*(s16*)((char*)obj + 0x46) == 0x84b);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80157CDC(int obj, int p2)
{
  extern void CameraShake_ApplyRadial(int, f32, f32, f32, f32);
  extern void *Obj_GetPlayerObject(void);
  extern f32 Vec_distance(int, int);
  extern void doRumble(f32);
  extern void smallbasket_spawnLinkedFirepipe(int, int);
  extern void fn_80157B58(int, int);
  extern void firepipe_setLinkedUpdateFlag(int);
  extern void firepipe_clearLinkedUpdateFlag(int);
  extern char lbl_8031FAE8[];
  extern f32 lbl_803DDA70;
  extern f32 timeDelta;
  extern f32 lbl_803E2B80;
  extern f32 lbl_803E2BA0;
  extern f32 lbl_803E2BA4;
  char *entry = (char *)*(int *)(lbl_8031FAE8 + (u32)*(u8 *)(p2 + 0x33b) * 32 + 28);
  u8 i;

  lbl_803DDA70 = lbl_803DDA70 - timeDelta;

  i = 0;
  do {
    if ((*(u16 *)(p2 + 0x2f8) & (1U << i)) != 0) {
      char *sub = entry + (u32)i * 12;
      if (*(u16 *)(sub + 4) != 0) {
        Sfx_PlayFromObject(obj, *(u16 *)(sub + 4));
      }
      if (*(u8 *)(sub + 9) != 0) {
        CameraShake_ApplyRadial(obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14), (f32)(u32)*(u8 *)(sub + 9) * lbl_803E2BA0);
      }
      if (*(u8 *)(sub + 10) != 0) {
        void *player = Obj_GetPlayerObject();
        if ((*(u16 *)((char *)player + 0xb0) & 0x1000) == 0) {
          f32 dist = Vec_distance(obj + 0x18, (int)player + 0x18);
          if (dist < lbl_803E2B80) {
            doRumble((lbl_803E2BA4 - dist / lbl_803E2BA4) * (f32)(u32)*(u8 *)(sub + 10));
          }
        }
      }
      if (*(u8 *)(sub + 11) != 0) {
        if ((*(u8 *)(sub + 11) & 1) != 0) {
          *(u8 *)(p2 + 0x33d) = (u8)(*(u8 *)(p2 + 0x33d) ^ 0x40);
          if ((*(u8 *)(p2 + 0x33d) & 0x40) != 0) {
            if (*(int *)(obj + 0xc8) == 0) {
              smallbasket_spawnLinkedFirepipe(obj, p2);
            } else {
              firepipe_setLinkedUpdateFlag(*(int *)(obj + 0xc8));
            }
          } else if (*(int *)(obj + 0xc8) != 0) {
            firepipe_clearLinkedUpdateFlag(*(int *)(obj + 0xc8));
          }
        }
        if ((*(u8 *)(sub + 11) & 2) != 0) {
          fn_80157B58(obj, p2);
        }
      }
    }
    i++;
  } while ((u32)i <= 12);
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E2B98;
extern f32 lbl_803E2BB8;
extern f32 lbl_803E2BD4;
extern f32 lbl_803E2BE4;
extern f32 lbl_803E2BE8;
extern f32 lbl_803E2BEC;
extern f32 lbl_803E2BF0;
extern f32 lbl_803E2BF4;
extern f32 lbl_803E2BF8;
extern f32 lbl_803E2BFC;
extern f32 lbl_803E2C00;
extern f32 lbl_803E2C04;
extern f32 lbl_803E2C08;
extern f32 lbl_803E2C0C;

/* smallbasket_initModelVariantState: smallbasket variant init. Dispatches on obj->modelType
 * (offset 0x46): values 0x6a2/0x6a3/0x6a4 each pick a different float +
 * byte tuple to seed state[0x2a8..0x322]. The trailing block sets
 * shared state floats and computes obj[0x8] from (s8)params[0x28]. */
#pragma scheduling off
#pragma peephole off
void smallbasket_initModelVariantState(s16* obj, u8* state) {
    u8* params = *(u8**)((u8*)obj + 0x4c);
    *(u32*)(state + 0x2e4) = 0xb;
    *(u32*)(state + 0x2e4) |= 0x400b0;
    *(u32*)(state + 0x2e4) |= 0x40001040;
    switch ((s16)obj[0x46/2]) {
    case 0x6a3:
        *(f32*)(state + 0x2ac) = lbl_803E2BE4;
        *(f32*)(state + 0x2a8) = lbl_803E2BB8;
        *(u16*)(state + 0x2b0) = 0x1e;
        state[0x33b] = 0;
        state[0x320] = 9;
        *(f32*)(state + 0x314) = lbl_803E2BE8;
        state[0x321] = 0xc;
        *(f32*)(state + 0x318) = lbl_803E2BEC;
        state[0x322] = 9;
        *(f32*)(state + 0x31c) = lbl_803E2BE8;
        *(u32*)(state + 0x2e4) |= 0x400;
        break;
    case 0x6a2:
        *(f32*)(state + 0x2ac) = lbl_803E2BF0;
        *(f32*)(state + 0x2a8) = lbl_803E2BB8;
        *(u16*)(state + 0x2b0) = 0x32;
        state[0x33b] = 1;
        state[0x320] = 0xe;
        *(f32*)(state + 0x314) = lbl_803E2BE8;
        state[0x321] = 0xd;
        *(f32*)(state + 0x318) = lbl_803E2BEC;
        state[0x322] = 0xe;
        *(f32*)(state + 0x31c) = lbl_803E2BE8;
        *(u32*)(state + 0x2e4) |= 0xc00;
        break;
    case 0x6a4:
        *(f32*)(state + 0x2ac) = lbl_803E2BF4;
        *(f32*)(state + 0x2a8) = lbl_803E2BF8;
        *(u16*)(state + 0x2b0) = 0xf;
        state[0x33b] = 2;
        state[0x320] = 0xd;
        *(f32*)(state + 0x314) = lbl_803E2BE8;
        state[0x321] = 0x10;
        *(f32*)(state + 0x318) = lbl_803E2BEC;
        state[0x322] = 0xd;
        *(f32*)(state + 0x31c) = lbl_803E2BE8;
        *(u32*)(state + 0x2e4) |= 0xc00;
        break;
    }
    *(f32*)(state + 0x308) = lbl_803E2BD4;
    *(f32*)(state + 0x300) = lbl_803E2BFC;
    *(f32*)(state + 0x304) = lbl_803E2C00;
    *(f32*)(state + 0x2fc) = *(f32*)(state + 0x2fc) * lbl_803E2C04;
    if ((s8)params[0x2e] != -1) {
        *(u32*)(state + 0x2dc) |= 1;
    }
    *(f32*)((u8*)obj + 0x8) = lbl_803E2C08 + ((f32)(s32)(s8)params[0x28] / lbl_803E2C0C);
}
#pragma peephole reset
#pragma scheduling reset

extern u8 fn_8014C11C(int obj, f32 dist, u8 flag, int maxCount, void* buf);
extern int lbl_803AC4A8[];
extern void* gCameraInterface;
extern f32 lbl_803E2B80;

/* Nearby-object scan. Asks fn_8014C11C for up to 40 objects
 * within lbl_803E2B80, walks the result array of (obj, ?) pairs, and if
 * any entry's modelType is 0x6a3 with state[0x2dc] bit 0x20000000 set
 * AND bits 0x1800 clear, latches "found" and exits. If nothing matched,
 * fires gCameraInterface vtable[0x24/4] with (0, 0, 0). */
#pragma scheduling off
#pragma peephole off
void smallbasket_checkNearbyActiveBasket(int obj) {
    u8 count = (u8)fn_8014C11C(obj, lbl_803E2B80, 0, 0x28, lbl_803AC4A8);
    u8 noMatch = 1;
    if (count >= 1) {
        u8 i;
        for (i = 0; (u32)i < (u32)count; i++) {
            u32 objectIndex = (u8)i;
            int e = lbl_803AC4A8[objectIndex * 2];
            if (*(s16*)((char*)e + 0x46) == 0x6a3) {
                u32 flags = *(u32*)((char*)*(int**)((char*)e + 0xb8) + 0x2dc);
                if ((flags & 0x20000000) != 0 && (flags & 0x1800) == 0) {
                    i = count;
                    noMatch = 0;
                }
            }
        }
    }
    if (noMatch != 0) {
        ((void(*)(int, int, int))((int*)*(int*)gCameraInterface)[0x24/4])(0, 0, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern f32 lbl_803E2C98;
extern f32 lbl_803E2C9C;
extern f32 lbl_803E2CA0;
extern f32 lbl_803E2CA4;
extern f32 lbl_803E2CA8;

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_8015A52C(s16* obj)
{
    u8 locked = Obj_IsLoadingLocked();
    if (locked != 0) {
        int* setup = Obj_AllocObjectSetup(0x24, 0x51b);
        *(f32*)((char*)setup + 8) = *(f32*)((char*)obj + 0xc);
        *(f32*)((char*)setup + 0xc) = lbl_803E2C98 + *(f32*)((char*)obj + 0x10);
        *(f32*)((char*)setup + 0x10) = *(f32*)((char*)obj + 0x14);
        *(u8*)((char*)setup + 4) = 1;
        *(u8*)((char*)setup + 5) = 4;
        *(u8*)((char*)setup + 7) = 0xff;
        setup = Obj_SetupObject(setup, 5, -1, -1, 0);
        if (setup != NULL) {
            *(f32*)((char*)setup + 0x24) = lbl_803E2C9C * -fn_80293E80((lbl_803E2CA0 * (f32)*(s16*)obj) / lbl_803E2CA4);
            *(f32*)((char*)setup + 0x28) = lbl_803E2CA8;
            *(f32*)((char*)setup + 0x2c) = lbl_803E2C9C * -sin((lbl_803E2CA0 * (f32)*(s16*)obj) / lbl_803E2CA4);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

extern f32 lbl_803E2B84;
extern f32 lbl_803E2B88;

#pragma scheduling off
#pragma peephole off
void fn_80157B58(int* obj, u8* state)
{
    u8 locked = Obj_IsLoadingLocked();
    if (locked != 0) {
        int child;
        int setup = (int)Obj_AllocObjectSetup(0x24, 0x869);
        ObjPath_GetPointWorldPosition(obj, 0, setup + 8, setup + 0xc, setup + 0x10, 0);
        *(u8*)(setup + 4) = 1;
        *(u8*)(setup + 5) = 4;
        *(u8*)(setup + 6) = 0xff;
        *(u8*)(setup + 7) = 0xff;
        child = (int)Obj_SetupObject((int*)setup, 5, -1, -1, 0);
        if (child != 0) {
            f32 dur = lbl_803E2B84 * ((f32)*(u16*)(state + 0x2a4) / *(f32*)(state + 0x2a8));
            *(f32*)(child + 0x24) =
                (*(f32*)(*(int*)(state + 0x29c) + 0xc) - *(f32*)(setup + 8)) / dur;
            *(f32*)(child + 0x28) =
                ((lbl_803E2B88 + *(f32*)(*(int*)(state + 0x29c) + 0x10) + (f32)(int)randomGetRange(-10, 10))
                 - *(f32*)(setup + 0xc)) / dur;
            *(f32*)(child + 0x2c) =
                (*(f32*)(*(int*)(state + 0x29c) + 0x14) - *(f32*)(setup + 0x10)) / dur;
        }
        Sfx_PlayFromObject((int)obj, 0x4ae);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_8014CF7C(int* obj, u8* state, f32 x, f32 z, int p5, int p6);
extern u8 lbl_803DBD28[4];
extern u8 lbl_803DBD2C[4];
extern u8 lbl_803DBD30[4];
extern f32 lbl_803E2CA0;
extern f32 lbl_803E2CA4;

#pragma scheduling off
#pragma peephole off
void fn_8015A924(int* obj, u8* state)
{
    u8* tbl = *(u8**)((char*)lbl_8031FD48 + *(u16*)(state + 0x338) * 8);
    int i;

    *(u8*)(*(int*)((char*)obj + 0x54) + 0x6e) = 10;
    *(u8*)(*(int*)((char*)obj + 0x54) + 0x6f) = 1;
    if (*(s16*)((char*)obj + 0xa0) == 0) {
        *(u8*)((char*)obj + 0xaf) = *(u8*)((char*)obj + 0xaf) | 8;
        ObjHits_DisableObject(obj);
    } else {
        *(u8*)((char*)obj + 0xaf) = *(u8*)((char*)obj + 0xaf) & ~8;
        ObjHits_EnableObject(obj);
    }

    if ((*(u32*)(state + 0x2dc) & 0x80000000) != 0 && *(u8*)(state + 0x33a) <= 1) {
        if (*(u16*)(state + 0x338) != 0 || (int)randomGetRange(0, 0x14) < 10) {
            *(u8*)(state + 0x33a) = 1;
        } else {
            *(u8*)(state + 0x33a) = 7;
        }
        *(u32*)(state + 0x2dc) = *(u32*)(state + 0x2dc) | 0x40000000;
    }

    if ((*(u32*)(state + 0x2dc) & 0x40000000) != 0) {
        *(char*)(state + 0x33a) += 1;
        if (*(u8*)(state + 0x33a) > lbl_803DBD2C[*(u16*)(state + 0x338)]) {
            *(u8*)(state + 0x33a) = lbl_803DBD28[*(u16*)(state + 0x338)];
        }
        if (*(u16*)(state + 0x2a0) < 4) {
            i = *(u8*)(state + 0x33a) * 0xc;
            fn_8014D08C(obj, (int*)state, *(u8*)(tbl + i + 8), *(f32*)((int)tbl + i), 0, 0);
        } else {
            i = *(u8*)(state + 0x33a) * 0xc;
            fn_8014D08C(obj, (int*)state, *(u8*)(tbl + i + 9), *(f32*)((int)tbl + i), 0, 0);
        }
        if (*(s16*)((char*)obj + 0xa0) == 9) {
            fn_8015A52C((s16*)obj);
        } else if (*(s16*)((char*)obj + 0xa0) == 1) {
            int r = randomGetRange(0, *(u8*)(state + 0x33b));
            s16 a = randomGetRange(-0x8000, 0x7fff);
            f32 angle = (lbl_803E2CA0 * (f32)a) / lbl_803E2CA4;
            *(f32*)((char*)obj + 0xc) = (f32)r * fn_80293E80(angle) + *(f32*)(*(int*)((char*)obj + 0x4c) + 8);
            *(f32*)((char*)obj + 0x14) = (f32)r * sin(angle) + *(f32*)(*(int*)((char*)obj + 0x4c) + 0x10);
            fn_8014CF7C(obj, state, *(f32*)(*(int*)(state + 0x29c) + 0xc),
                        *(f32*)(*(int*)(state + 0x29c) + 0x14), 1, 0);
        }
    }

    fn_8014CF7C(obj, state, *(f32*)(*(int*)(state + 0x29c) + 0xc),
                *(f32*)(*(int*)(state + 0x29c) + 0x14), lbl_803DBD30[*(u16*)(state + 0x338)], 0);
    smallbasket_playReactionEffects(obj, (int*)state);
}
#pragma peephole reset
#pragma scheduling reset

extern u32 getAngle(f32 dx, f32 dz);
extern f32 timeDelta;
extern f32 lbl_803E2B2C;
extern f32 lbl_803E2B28;
extern f32 lbl_803E2B34;
extern f32 lbl_803E2B30;
extern f32 lbl_803E2B44;
extern f32 lbl_803E2B60;
extern f32 lbl_803DBCE0;
extern f32 lbl_803DBCE4;
extern f32 lbl_803DBCEC;

#pragma scheduling off
#pragma peephole off
void fn_80157558(s16* obj, u8* state)
{
    int moved;
    int turnRaw;
    u32 mag;
    u32 grabbed;

    *(f32*)(state + 0x324) = *(f32*)(state + 0x324) - timeDelta;
    if (*(f32*)(state + 0x324) <= lbl_803E2B18) {
        *(f32*)(state + 0x324) = (f32)(int)randomGetRange(0x3c, 0x78);
    }

    if (lbl_803E2B18 != *(f32*)(state + 0x328)) {
        ObjHits_DisableObject(obj);
        if (*(s16*)((char*)obj + 0xa0) != 5) {
            fn_8014D08C((int*)obj, (int*)state, 5, lbl_803DBCEC, 0, 0);
        } else if ((*(u32*)(state + 0x2dc) & 0x40000000) != 0) {
            ObjHits_EnableObject(obj);
            *(f32*)(state + 0x328) = lbl_803E2B18;
        }
        *(u8*)((char*)obj + 0x36) = 0xff;
        moved = 1;
    } else {
        moved = 0;
    }

    if (moved == 0) {
        f32 diff;
        f32 z;
        u32 ang;
        *(s16*)obj = (f32)*(u16*)(state + 0x338) * timeDelta + (f32)(int)*(s16*)obj;
        z = lbl_803E2B18;
        *(f32*)((char*)obj + 0x24) = z;
        *(f32*)((char*)obj + 0x28) = z;
        *(f32*)((char*)obj + 0x2c) = z;
        ObjHits_SetHitVolumeSlot(obj, 9, 1, -1);
        ang = getAngle(*(f32*)((char*)obj + 0xc) - *(f32*)(*(int*)(state + 0x29c) + 0xc),
                       *(f32*)((char*)obj + 0x14) - *(f32*)(*(int*)(state + 0x29c) + 0x14)) & 0xffff;
        diff = (f32)(int)(ang - ((int)*(s16*)obj & 0xffffu));
        if (diff > lbl_803E2B2C) {
            diff = lbl_803E2B28 + diff;
        }
        if (diff < lbl_803E2B34) {
            diff = lbl_803E2B30 + diff;
        }
        turnRaw = (int)diff;
        {
            int t = (s16)turnRaw;
            mag = (u16)(t >= 0 ? t : -t);
        }
        ObjHits_EnableObject(obj);
        grabbed = *(u32*)(state + 0x2dc) & 0x40000000;
        if (grabbed != 0 && *(s16*)((char*)obj + 0xa0) == 6) {
            fn_8014D08C((int*)obj, (int*)state, 4, lbl_803DBCE0, 0, 1);
        } else {
            if (grabbed != 0
                || (mag < 1000
                    && *(s16*)((char*)obj + 0xa0) != 2
                    && *(s16*)((char*)obj + 0xa0) != 4
                    && *(s16*)((char*)obj + 0xa0) != 6)) {
                if (mag < 1000) {
                    if (*(f32*)(state + 0x2ac) < lbl_803E2B60) {
                        fn_8014D08C((int*)obj, (int*)state, 2, lbl_803E2B44, 0, 0);
                    } else {
                        fn_8014D08C((int*)obj, (int*)state, 6, lbl_803DBCE4, 0, 0);
                    }
                    *(u16*)(state + 0x338) = 0;
                } else {
                    fn_8014D08C((int*)obj, (int*)state, 1, lbl_803E2B44, 0, 0);
                    if ((s16)turnRaw < 0) {
                        *(u16*)(state + 0x338) = 0xfed4;
                    } else {
                        *(u16*)(state + 0x338) = 300;
                    }
                }
            }
            *(s16*)((char*)obj + 2) = *(s16*)(state + 0x19c);
            *(s16*)((char*)obj + 4) = *(s16*)(state + 0x19e);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_8001FE90(void);
extern f32 lbl_803E2BA8;

typedef struct {
    f32 spd;    // 0x0
    u32 mask;   // 0x4
    u8 moveId;  // 0x8
    u8 next;    // 0x9
    u8 mode;    // 0xa
    u8 pad;
} BasketSeq12;

typedef struct {
    f32 spd;    // 0x0
    u32 mask;   // 0x4
    u8 moveId;  // 0x8
    u8 next9;   // 0x9
    u8 nextA;   // 0xa
    u8 pad;
    int flagC;  // 0xc
} BasketSeq16;

#pragma scheduling off
#pragma peephole off
void fn_80159284(int* obj, u8* state)
{
    extern void firepipe_clearLinkedUpdateFlag(int);
    extern char lbl_8031FAE8[];
    char* base = (char*)((int)lbl_8031FAE8 + *(u8*)(state + 0x33b) * 32);
    u8* t9 = *(u8**)(base + 0x10);
    u8* t8 = *(u8**)(base + 0x18);
    u8* t7 = *(u8**)(base + 0xc);
    BasketSeq16* t6 = *(BasketSeq16**)(base + 0x14);
    f32 cap;
    int i;
    u8* p;
    int j;
    int n;

    if (*(void**)(state + 0x29c) != NULL && *(s16*)(*(int*)(state + 0x29c) + 0x44) == 1) {
        fn_8001FE90();
    }

    if ((*(u32*)(state + 0x2dc) & 0x80000000) != 0) {
        if (*(u8*)(state + 0x33b) == 0) {
            ((void(*)(int,int,int))((int*)*(int*)gCameraInterface)[0x24/4])(0, 0x6c, 0);
        }
        if (*(s16*)((char*)obj + 0x46) == 0x6a2 && *(void**)((char*)obj + 0xc8) != NULL) {
            firepipe_clearLinkedUpdateFlag(*(int*)((char*)obj + 0xc8));
        }
        *(u8*)(state + 0x33d) = *(u8*)(state + 0x33d) | 0x10;
    }

    if (*(f32*)(state + 0x328) != lbl_803E2BA8 && *(u8*)(state + 0x33f) != 0) {
        cap = lbl_803E2BA8;
        *(f32*)(state + 0x328) -= timeDelta;
        if (*(f32*)(state + 0x328) <= cap) {
            *(f32*)(state + 0x328) = cap;
            *(u32*)(state + 0x2dc) = *(u32*)(state + 0x2dc) | 0x40000000;
            *(u8*)(state + 0x33c) = t6[*(u8*)(state + 0x33f)].flagC;
            *(u8*)((char*)obj + 0xe4) = *(u8*)(state + 0x33c) & 1;
            *(u8*)(state + 0x33f) = t6[*(u8*)(state + 0x33f)].nextA;
        }
    }

    if ((*(u32*)(state + 0x2dc) & 0x40000000) != 0) {
        *(u8*)(state + 0x33d) = *(u8*)(state + 0x33d) & ~0x30;
        if (*(s16*)((char*)obj + 0x46) == 0x6a2 && *(void**)((char*)obj + 0xc8) != NULL) {
            firepipe_clearLinkedUpdateFlag(*(int*)((char*)obj + 0xc8));
        }
        if (*(u8*)(state + 0x33f) != 0) {
            i = *(u8*)(state + 0x33f) * 0x10;
            fn_8014D08C(obj, (int*)state, *(u8*)((char*)t6 + i + 8), *(f32*)((int)t6 + i), 0,
                        *(int*)((char*)t6 + i + 4) & 0xff);
            *(u8*)(state + 0x33c) = t6[*(u8*)(state + 0x33f)].flagC;
            *(u8*)((char*)obj + 0xe4) = *(u8*)(state + 0x33c) & 1;
            *(u8*)(state + 0x33f) = t6[*(u8*)(state + 0x33f)].next9;
        } else {
            i = *(u16*)(state + 0x2a0) * 0xc;
            if (*(u8*)(t7 + i + 8) == 0) {
                if (*(u16*)(state + 0x2a4) >= 0x50) {
                    *(u8*)(state + 0x33a) = 0;
                }
                fn_8014C11C((int)obj, lbl_803E2BB8, 6, 0x28, lbl_803AC4A8);
                i = *(u8*)(state + 0x33a) * 0xc;
                if ((*(u32*)(state + 0x2dc) & *(u32*)(t9 + i + 4)) == 0
                    && *(u8*)(t9 + i + 9) != 0) {
                    *(u8*)(state + 0x33a) = *(u8*)(t9 + i + 9);
                }
                i = *(u8*)(state + 0x33a) * 0xc;
                fn_8014D08C(obj, (int*)state, *(u8*)(t9 + i + 8), *(f32*)((int)t9 + i), 0,
                            *(u8*)(t9 + i + 0xa));
                i = *(u8*)(state + 0x33a) * 0xc;
                *(u8*)(state + 0x33a) = *(u8*)(t9 + i + 9);
            } else {
                fn_8014D08C(obj, (int*)state, *(u8*)(t7 + i + 8), *(f32*)((int)t7 + i), 0,
                            *(u8*)(t7 + i + 0xa));
            }
        }
    }

    *(u8*)(*(int*)((char*)obj + 0x54) + 0x6e) = 0;
    *(u8*)(*(int*)((char*)obj + 0x54) + 0x6f) = 0;
    j = 1;
    p = t8 + 0xc;
    n = *(u8*)(t8 + 8);
    for (; j <= n; j++) {
        if (*(s16*)((char*)obj + 0xa0) == *(u8*)(p + 8)) {
            *(s8*)(*(int*)((char*)obj + 0x54) + 0x6e) = (s8)*(int*)(t8 + j * 0xc + 4);
            *(s8*)(*(int*)((char*)obj + 0x54) + 0x6f) = (s8)*(u8*)(t8 + j * 0xc + 9);
            if (*(s8*)(*(int*)((char*)obj + 0x54) + 0x6e) == 0x1f) {
                *(u32*)(state + 0x2e8) = *(u32*)(state + 0x2e8) | 0x40;
            } else {
                *(u32*)(state + 0x2e8) = *(u32*)(state + 0x2e8) & -65;
            }
            break;
        }
        p += 0xc;
    }

    if ((*(u8*)(state + 0x323) & 8) == 0 && (*(u8*)(state + 0x33d) & 0x10) == 0) {
        fn_8014CF7C(obj, state, *(f32*)(*(int*)(state + 0x29c) + 0xc),
                    *(f32*)(*(int*)(state + 0x29c) + 0x14), 0x1e, 0);
    }
    fn_80157CDC((int)obj, (int)state);
}
#pragma peephole reset
#pragma scheduling reset

extern int objCreateLight(int a, int b);
extern void modelLightStruct_setField50();
extern void lightVecFn_8001dd88();
extern void modelLightStruct_setColorsA8AC();
extern void modelLightStruct_setColors100104();
extern void lightDistAttenFn_8001dc38();
extern void lightSetField4D();
extern void lightFn_8001db6c();
extern void lightFn_8001d620();
extern void lightSetField2FB();
extern void sidekickToy_accelerateTowardTarget3D(s16* obj, f32 x, f32 y, f32 z, f32 a, f32 b, f32 c, f32 spd);
extern f32 powfBitEstimate(f32 base, f32 exp);
extern f32 sqrtf(f32 x);
extern void Sfx_SetObjectSfxVolume(f32 ratio, s16* obj, int sfx, int vol);
extern f32 lbl_803E2C74;
extern f32 lbl_803E2C30;
extern f32 lbl_803E2C34;
extern f32 lbl_803E2C24;
extern f32 lbl_803E2C10;
extern f32 lbl_803E2C14;
extern f32 lbl_803E2C18;
extern f32 lbl_803E2C48;
extern f32 lbl_803E2C78;
extern f32 lbl_803E2C50;
extern f32 lbl_803E2C70;
extern f32 lbl_803E2C54;
extern f32 lbl_803E2C38;
extern f32 lbl_803E2C40;
extern f32 lbl_803E2C6C;

typedef struct {
    u8 pad[6];
    u16 sfxId;  // 0x6
    f32 vol;    // 0x8
    f32 x;      // 0xc
    f32 y;      // 0x10
    f32 z;      // 0x14
} BasketSfxParams;

typedef struct {
    f32 x;
    f32 y;
    f32 z;
} BasketVec3;

#pragma scheduling off
#pragma peephole off
void fn_80159FCC(s16* obj, u8* state)
{
    int base = *(int*)state;
    BasketVec3 d;
    BasketSfxParams sp;
    int i;
    f32 pw;

    if (*(void**)(state + 0x340) != NULL && *(void**)(state + 0x340) == *(void**)(state + 0x29c)) {
        *(u32*)(state + 0x2e4) = *(u32*)(state + 0x2e4) | 0x10000;
        *(f32*)(state + 0x330) = lbl_803E2C74;
    }
    *(u32*)(state + 0x2e8) = *(u32*)(state + 0x2e8) | 0x100;
    sp.x = lbl_803E2C30;
    sp.y = lbl_803E2C34;
    sp.z = lbl_803E2C30;
    sp.vol = lbl_803E2C24;
    sp.sfxId = 0x605;
    if ((*(u16*)((char*)obj + 0xb0) & 0x800) != 0) {
        ((void(*)(s16*,int,void*,int,int,int))((void**)*gPartfxInterface)[2])(obj, 1999, &sp, 2, -1, 0);
        if (*(void**)(state + 0x368) == NULL) {
            if (*(void**)(state + 0x368) == NULL) {
                *(int*)(state + 0x368) = objCreateLight(0, 1);
            }
            if (*(void**)(state + 0x368) != NULL) {
                modelLightStruct_setField50(*(int*)(state + 0x368), 2);
                lightVecFn_8001dd88(*(int*)(state + 0x368), *(f32*)((char*)obj + 0xc), *(f32*)((char*)obj + 0x10), *(f32*)((char*)obj + 0x14));
                modelLightStruct_setColorsA8AC(*(int*)(state + 0x368), 0xc0, 0x40, 0xff, 0xff);
                modelLightStruct_setColors100104(*(int*)(state + 0x368), 0xc0, 0x40, 0xff, 0xff);
                lightDistAttenFn_8001dc38(*(int*)(state + 0x368), lbl_803E2C10, lbl_803E2C14);
                lightSetField4D(*(int*)(state + 0x368), 1);
                lightFn_8001db6c(*(int*)(state + 0x368), 1, lbl_803E2C18);
                lightFn_8001d620(*(int*)(state + 0x368), 0, 0);
                lightSetField2FB(*(int*)(state + 0x368), 0);
            }
        } else {
            lightVecFn_8001dd88(*(f32*)((char*)obj + 0xc), *(f32*)((char*)obj + 0x10), *(f32*)((char*)obj + 0x14));
        }
    }
    if ((*(u32*)(state + 0x2dc) & 0x80000000) != 0) {
        *(u8*)(state + 0x33a) = 3;
        *(u32*)(state + 0x2dc) = *(u32*)(state + 0x2dc) | 0x40000000;
    }
    sidekickToy_accelerateTowardTarget3D(obj, *(f32*)(*(int*)(state + 0x29c) + 0x18),
        lbl_803E2C48 + *(f32*)(*(int*)(state + 0x29c) + 0x1c),
        *(f32*)(*(int*)(state + 0x29c) + 0x20),
        lbl_803E2C48, lbl_803E2C78, lbl_803E2C50, *(f32*)(state + 0x304));
    if ((*(u32*)(state + 0x2dc) & 0x40000000) != 0) {
        i = *(u8*)(state + 0x33a) * 0xc;
        fn_8014D08C((int*)obj, (int*)state, *(u8*)(lbl_8031FB70 + i + 8), *(f32*)((int)lbl_8031FB70 + i), 0, 0);
        *(u8*)(state + 0x33a) = *(u8*)(lbl_8031FB70 + *(u8*)(state + 0x33a) * 0xc + 9);
    }
    pw = powfBitEstimate(*(f32*)(state + 0x304), timeDelta);
    *(s16*)((char*)obj + 2) = (f32)*(s16*)((char*)obj + 2) * pw;
    pw = powfBitEstimate(*(f32*)(state + 0x304), timeDelta);
    *(s16*)((char*)obj + 4) = (f32)*(s16*)((char*)obj + 4) * pw;
    if (*(f32*)(state + 0x324) < lbl_803E2C70) {
        *(f32*)(state + 0x324) = lbl_803E2C54 * timeDelta + *(f32*)(state + 0x324);
    } else {
        *(f32*)(state + 0x324) = lbl_803E2C70;
    }
    *(s16*)obj = *(f32*)(state + 0x324) * timeDelta + (f32)(int)*(s16*)obj;
    *(f32*)(state + 0x328) = lbl_803E2C38;
    if ((*(u32*)(state + 0x2dc) & 0x2000) != 0) {
        d.x = *(f32*)(base + 0x68) - *(f32*)((char*)obj + 0xc);
        d.y = *(f32*)(base + 0x6c) - *(f32*)((char*)obj + 0x10);
        d.z = *(f32*)(base + 0x70) - *(f32*)((char*)obj + 0x14);
        *(f32*)(state + 0x32c) = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
        if (*(f32*)(state + 0x32c) > lbl_803E2C40) {
            *(u32*)(state + 0x2e4) = *(u32*)(state + 0x2e4) | 0x10000;
            *(f32*)(state + 0x330) = lbl_803E2C30;
        }
    }
    if (*(f32*)(state + 0x324) <= lbl_803E2C30) {
        Sfx_StopFromObject((int)obj, 0x3e8);
    } else {
        Sfx_PlayFromObject((int)obj, 0x3e8);
        i = (int)((lbl_803E2C6C * *(f32*)(state + 0x324)) / lbl_803E2C70);
        Sfx_SetObjectSfxVolume(*(f32*)(state + 0x324) / lbl_803E2C70, obj, 0x3e8, i);
    }
    if (*(void**)(state + 0x340) != NULL
        && (*(s16*)(*(int*)(state + 0x340) + 0x46) == 0x1f || *(s16*)(*(int*)(state + 0x340) + 0x46) == 0)) {
        Sfx_PlayFromObject((int)obj, 0x23d);
    }
}
#pragma peephole reset
#pragma scheduling reset
