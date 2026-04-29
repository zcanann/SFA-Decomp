#include "ghidra_import.h"
#include "main/dll/collectable.h"

extern undefined4 FUN_800067e8();
extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined8 FUN_80006824();
extern undefined8 FUN_800068cc();
extern undefined8 FUN_800068d0();
extern char FUN_80006a64();
extern undefined4 FUN_80006a68();
extern void* FUN_80017624();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern double FUN_80017708();
extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern undefined8 FUN_800178ec();
extern undefined4 FUN_80017a28();
extern undefined4 FUN_80017a30();
extern undefined4 FUN_80017a3c();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined8 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern undefined4 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305c4();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_SyncObjectPosition();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined8 ObjLink_AttachChild();
extern undefined4 ObjPath_GetPointWorldPositionArray();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80038f38();
extern undefined8 FUN_80039468();
extern int FUN_8003964c();
extern undefined4 FUN_8003a1c4();
extern undefined4 fn_8003A328();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80046f44();
extern undefined4 FUN_80046f84();
extern undefined8 FUN_800571f8();
extern int FUN_800575b4();
extern int FUN_800620e8();
extern undefined4 FUN_8006dca8();
extern undefined4 FUN_8006ef38();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_80081120();
extern undefined4 FUN_800da700();
extern undefined8 FUN_800da850();
extern undefined4 FUN_800db47c();
extern ushort FUN_800db690();
extern undefined4 FUN_800dbc68();
extern undefined8 FUN_800dd3dc();
extern undefined4 FUN_800dd3e0();
extern undefined8 FUN_80135d54();
extern undefined4 FUN_80135f38();
extern undefined4 FUN_80136310();
extern undefined4 FUN_8013651c();
extern int FUN_801365c4();
extern undefined4 FUN_801367b4();
extern int FUN_80136870();
extern undefined4 FUN_8013939c();
extern undefined4 FUN_80139a4c();
extern undefined4 FUN_8013a408();
extern int FUN_8013b368();
extern int FUN_8013dc88();
extern int FUN_801451dc();
extern undefined4 FUN_8014a9f0();
extern undefined4 FUN_8014fef8();
extern byte FUN_80150620();
extern undefined4 FUN_801523bc();
extern undefined4 FUN_80152b8c();
extern undefined4 FUN_80152f54();
extern undefined4 FUN_80153440();
extern undefined4 FUN_80153db4();
extern undefined4 FUN_80154108();
extern undefined4 FUN_80154cc8();
extern undefined4 FUN_80155b08();
extern undefined4 FUN_801564ec();
extern undefined4 FUN_80156e48();
extern undefined4 FUN_801578c4();
extern undefined4 FUN_80157168();
extern undefined4 FUN_80158540();
extern undefined4 FUN_80159c60();
extern undefined4 FUN_8015a4c4();
extern undefined4 FUN_8015b2cc();
extern undefined4 FUN_801778d0();
extern double FUN_80194a70();
extern undefined4 FUN_8020a568();
extern undefined4 FUN_80247eb8();
extern double FUN_80247f54();
extern undefined4 FUN_80286830();
extern uint FUN_80286834();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028fa2c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294c68();
extern int FUN_80294c80();
extern undefined4 FUN_80294ca8();
extern undefined4 FUN_80294dc4();

extern undefined4 DAT_802c2948;
extern undefined4 DAT_802c294c;
extern undefined4 DAT_802c2950;
extern undefined4 DAT_802c2954;
extern undefined4 DAT_802c2958;
extern undefined4 DAT_802c2970;
extern undefined4 DAT_802c2974;
extern undefined4 DAT_802c2978;
extern undefined4 DAT_802c297c;
extern undefined4 DAT_802c2980;
extern undefined4 DAT_802c2984;
extern undefined4 DAT_802c2988;
extern undefined4 DAT_802c298c;
extern undefined4 DAT_8031df38;
extern undefined4 DAT_8031df50;
extern undefined4 DAT_803dc8a8;
extern undefined4 DAT_803dc8b0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd734;
extern undefined4 DAT_803de6c8;
extern undefined4* DAT_803de6d0;
extern undefined4 DAT_803de6d4;
extern undefined4 DAT_803e3050;
extern undefined4 DAT_803e3054;
extern undefined4 DAT_803e3058;
extern undefined4 DAT_803e31e8;
extern undefined4 DAT_803e31ec;
extern undefined4 DAT_803e31f0;
extern undefined4 DAT_803e31f4;
extern undefined4 DAT_803e31f8;
extern f64 DOUBLE_803e30f0;
extern f64 DOUBLE_803e3218;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e3078;
extern f32 FLOAT_803e307c;
extern f32 FLOAT_803e3098;
extern f32 FLOAT_803e30a0;
extern f32 FLOAT_803e30a4;
extern f32 FLOAT_803e30a8;
extern f32 FLOAT_803e30cc;
extern f32 FLOAT_803e30d0;
extern f32 FLOAT_803e30d4;
extern f32 FLOAT_803e30e4;
extern f32 FLOAT_803e310c;
extern f32 FLOAT_803e3138;
extern f32 FLOAT_803e3148;
extern f32 FLOAT_803e3158;
extern f32 FLOAT_803e3168;
extern f32 FLOAT_803e317c;
extern f32 FLOAT_803e3188;
extern f32 FLOAT_803e3190;
extern f32 FLOAT_803e31c4;
extern f32 FLOAT_803e31c8;
extern f32 FLOAT_803e31cc;
extern f32 FLOAT_803e31d0;
extern f32 FLOAT_803e31d4;
extern f32 FLOAT_803e31d8;
extern f32 FLOAT_803e31dc;
extern f32 FLOAT_803e31e0;
extern f32 FLOAT_803e31fc;
extern f32 FLOAT_803e3200;
extern f32 FLOAT_803e3204;
extern f32 FLOAT_803e3208;
extern f32 FLOAT_803e320c;
extern f32 FLOAT_803e3210;
extern f32 FLOAT_803e3220;
extern f32 FLOAT_803e3224;
extern f32 FLOAT_803e3228;
extern f32 FLOAT_803e322c;
extern f32 FLOAT_803e3234;
extern f32 FLOAT_803e3238;
extern f32 FLOAT_803e323c;
extern f32 FLOAT_803e3240;
extern f32 FLOAT_803e3244;
extern f32 FLOAT_803e3250;
extern f32 FLOAT_803e3254;

/*
 * --INFO--
 *
 * Function: FUN_80144e40
 * EN v1.0 Address: 0x80144E40
 * EN v1.0 Size: 736b
 * EN v1.1 Address: 0x80144ED8
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80144e40(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  bool bVar4;
  uint uVar3;
  int local_18 [3];
  
  *(float *)(param_2 + 0x720) = *(float *)(param_2 + 0x720) - FLOAT_803dc074;
  if (*(float *)(param_2 + 0x720) < FLOAT_803e306c) {
    *(float *)(param_2 + 0x720) = FLOAT_803e306c;
  }
  iVar2 = ObjHits_GetPriorityHit(param_1,local_18,(int *)0x0,(uint *)0x0);
  if (((iVar2 != 0) && (*(int *)(local_18[0] + 0xc4) != 0)) &&
     (*(short *)(*(int *)(local_18[0] + 0xc4) + 0x44) == 1)) {
    fVar1 = *(float *)(param_2 + 0x720);
    if (FLOAT_803e306c < fVar1) {
      *(float *)(param_2 + 0x720) = fVar1 + FLOAT_803e30d0;
      if (*(char *)(param_2 + 10) != '\v') {
        if ((*(uint *)(param_2 + 0x54) & 0x10) == 0) {
          iVar2 = *(int *)(param_1 + 0xb8);
          if ((((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
              ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
             (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)) {
            FUN_80039468(param_1,iVar2 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
          *(undefined *)(param_2 + 10) = 10;
          *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) | 0x10;
        }
        else if (*(float *)(param_2 + 0x720) <= FLOAT_803e31c4) {
          iVar2 = *(int *)(param_1 + 0xb8);
          if ((((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
              ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
             (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)) {
            FUN_80039468(param_1,iVar2 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
        }
        else {
          *(float *)(param_2 + 0x720) = *(float *)(param_2 + 0x720) * FLOAT_803e3138;
          uVar3 = FUN_80017690(0x245);
          if (uVar3 != 0) {
            if (FLOAT_803e306c == *(float *)(param_2 + 0x2ac)) {
              bVar4 = false;
            }
            else if (FLOAT_803e30a0 == *(float *)(param_2 + 0x2b0)) {
              bVar4 = true;
            }
            else if (*(float *)(param_2 + 0x2b4) - *(float *)(param_2 + 0x2b0) <= FLOAT_803e30a4) {
              bVar4 = false;
            }
            else {
              bVar4 = true;
            }
            if (!bVar4) {
              *(undefined *)(param_2 + 10) = 0xb;
              return;
            }
          }
          iVar2 = *(int *)(param_1 + 0xb8);
          if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
             (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
              (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)))) {
            FUN_80039468(param_1,iVar2 + 0x3a8,0x350,0x500,0xffffffff,0);
          }
        }
      }
    }
    else {
      *(float *)(param_2 + 0x720) = fVar1 + FLOAT_803e317c;
      iVar2 = *(int *)(param_1 + 0xb8);
      if ((((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
         (bVar4 = FUN_800067f0(param_1,0x10), !bVar4)) {
        FUN_80039468(param_1,iVar2 + 0x3a8,0x34f,0x500,0xffffffff,0);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80145120
 * EN v1.0 Address: 0x80145120
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801451C8
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80145120(int param_1,int param_2)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  int local_38 [2];
  
  iVar3 = 0;
  piVar1 = ObjGroup_GetObjects(0x4b,local_38);
  dVar4 = FUN_80017708((float *)(*(int *)(param_2 + 4) + 0x18),(float *)(param_1 + 0x18));
  if ((((double)FLOAT_803e31c8 <= dVar4) || (FLOAT_803e306c < *(float *)(param_2 + 0x71c))) &&
     (iVar2 = FUN_800575b4((double)FLOAT_803e3190,(float *)(param_1 + 0xc)), iVar2 == 0)) {
    dVar6 = (double)FLOAT_803e30a8;
    for (iVar2 = 0; iVar2 < local_38[0]; iVar2 = iVar2 + 1) {
      dVar5 = FUN_80017708((float *)(*(int *)(param_2 + 4) + 0x18),(float *)(*piVar1 + 0x18));
      if ((dVar5 < dVar4) && (dVar5 < dVar6)) {
        iVar3 = *piVar1;
        dVar6 = dVar5;
      }
      piVar1 = piVar1 + 1;
    }
  }
  return iVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_80145230
 * EN v1.0 Address: 0x80145230
 * EN v1.0 Size: 952b
 * EN v1.1 Address: 0x801452D8
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80145230(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int *param_10,int param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  double dVar5;
  double dVar6;
  
  iVar2 = FUN_801451dc(param_9,param_10);
  if (iVar2 == 0) {
    dVar5 = (double)FUN_80293f90();
    param_10[0x1cb] = (int)(float)((double)*(float *)(param_9 + 0x18) - dVar5);
    param_10[0x1cc] = *(int *)(param_9 + 0x1c);
    dVar6 = (double)FLOAT_803e30e4;
    dVar5 = (double)FUN_80294964();
    param_10[0x1cd] = (int)(float)((double)*(float *)(param_9 + 0x20) - dVar5);
    iVar2 = FUN_8013b368((double)FLOAT_803e310c,dVar6,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,param_11,param_12,param_13,param_14,param_15,
                         param_16);
    if (iVar2 != 1) {
      param_10[0x1d0] = (int)((float)param_10[0x1d0] - FLOAT_803dc074);
      if ((float)param_10[0x1d0] <= FLOAT_803e306c) {
        uVar3 = FUN_80017760(500,0x2ee);
        param_10[0x1d0] =
             (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e30f0);
        iVar2 = *(int *)(param_9 + 0xb8);
        if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
            (bVar4 = FUN_800067f0(param_9,0x10), !bVar4)))) {
          FUN_80039468(param_9,iVar2 + 0x3a8,0x360,0x500,0xffffffff,0);
        }
      }
      if (FLOAT_803e306c == (float)param_10[0xab]) {
        bVar4 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
        bVar4 = true;
      }
      else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
        bVar4 = false;
      }
      else {
        bVar4 = true;
      }
      if (bVar4) {
        FUN_80139a4c((double)FLOAT_803e30cc,param_9,8,0);
        param_10[0x1e7] = (int)FLOAT_803e30d0;
        param_10[0x20e] = (int)FLOAT_803e306c;
        FUN_80146fa0();
      }
      else {
        sVar1 = *(short *)(param_9 + 0xa0);
        if (sVar1 != 0x31) {
          if ((sVar1 < 0x31) && (sVar1 == 0xd)) {
            if ((param_10[0x15] & 0x8000000U) != 0) {
              FUN_80139a4c((double)FLOAT_803e30cc,param_9,0x31,0);
            }
          }
          else {
            FUN_80139a4c((double)FLOAT_803e30d4,param_9,0xd,0);
          }
        }
        FUN_80146fa0();
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801455e8
 * EN v1.0 Address: 0x801455E8
 * EN v1.0 Size: 444b
 * EN v1.1 Address: 0x80145560
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801455e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  float fVar1;
  ushort uVar3;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar4;
  byte local_18 [16];
  
  local_18[0] = FUN_800db47c((float *)(param_9 + 0x18),(undefined *)0x0);
  uVar4 = extraout_f1;
  if ((local_18[0] == 0) && (uVar3 = FUN_800db690((float *)(param_9 + 0x18)), uVar3 != 0)) {
    uVar4 = FUN_800da850((uint)uVar3,local_18);
  }
  if (local_18[0] != 0) {
    *(ushort *)(param_10 + 0x532) = (ushort)local_18[0];
    *(undefined *)(param_10 + 8) = 1;
    *(undefined *)(param_10 + 10) = 0;
    fVar1 = FLOAT_803e306c;
    *(float *)(param_10 + 0x71c) = FLOAT_803e306c;
    *(float *)(param_10 + 0x720) = fVar1;
    *(uint *)(param_10 + 0x54) = *(uint *)(param_10 + 0x54) & 0xffffffef;
    *(uint *)(param_10 + 0x54) = *(uint *)(param_10 + 0x54) & 0xfffeffff;
    *(uint *)(param_10 + 0x54) = *(uint *)(param_10 + 0x54) & 0xfffdffff;
    *(uint *)(param_10 + 0x54) = *(uint *)(param_10 + 0x54) & 0xfffbffff;
    *(undefined *)(param_10 + 0xd) = 0xff;
  }
  if (DAT_803de6c8 == 0) {
    puVar2 = FUN_80017aa4(0x18,0x25);
    DAT_803de6c8 = FUN_80017ae4(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2
                                ,4,0xff,0xffffffff,*(uint **)(param_9 + 0x30),in_r8,in_r9,in_r10);
  }
  *(byte *)(param_10 + 0x58) = *(byte *)(param_10 + 0x58) & 0x7f | 0x80;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801457a4
 * EN v1.0 Address: 0x801457A4
 * EN v1.0 Size: 1792b
 * EN v1.1 Address: 0x8014568C
 * EN v1.1 Size: 1328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801457a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  float fVar2;
  uint uVar3;
  bool bVar9;
  int *piVar4;
  int iVar5;
  uint uVar6;
  undefined2 *puVar7;
  int iVar8;
  int iVar10;
  int *piVar11;
  undefined8 extraout_f1;
  undefined8 uVar12;
  undefined8 extraout_f1_00;
  undefined auStack_98 [13];
  char local_8b;
  
  uVar3 = FUN_80286834();
  piVar11 = *(int **)(uVar3 + 0xb8);
  uVar12 = extraout_f1;
  if ((piVar11[0x15] & 0x200U) == 0) {
    ObjHits_DisableObject(uVar3);
    FUN_8000680c(uVar3,0x7f);
    if ((piVar11[0x15] & 0x800U) != 0) {
      piVar11[0x15] = piVar11[0x15] & 0xfffff7ff;
      piVar11[0x15] = piVar11[0x15] | 0x1000;
      iVar10 = 0;
      piVar4 = piVar11;
      do {
        FUN_801778d0(piVar4[0x1c0]);
        piVar4 = piVar4 + 1;
        iVar10 = iVar10 + 1;
      } while (iVar10 < 7);
      FUN_800068cc();
      iVar10 = *(int *)(uVar3 + 0xb8);
      if (((*(byte *)(iVar10 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(uVar3 + 0xa0) || (*(short *)(uVar3 + 0xa0) < 0x29)) &&
          (bVar9 = FUN_800067f0(uVar3,0x10), !bVar9)))) {
        param_14 = 0;
        FUN_80039468(uVar3,iVar10 + 0x3a8,0x29d,0,0xffffffff,0);
      }
    }
    uVar12 = FUN_800068cc();
    piVar11[0x15] = piVar11[0x15] | 0x200;
    if ((*(ushort *)(param_11 + 0x6e) & 3) == 0) {
      piVar11[0x15] = piVar11[0x15] | 0x4000;
    }
    if ((*(byte *)((int)piVar11 + 0x82e) >> 5 & 1) == 0) {
      piVar4 = (int *)FUN_80017a54(uVar3);
      uVar12 = FUN_800178ec(piVar4);
      *(byte *)((int)piVar11 + 0x82e) = *(byte *)((int)piVar11 + 0x82e) & 0xbf;
    }
  }
  if (((piVar11[0x15] & 0x4000U) != 0) && ((*(ushort *)(piVar11[9] + 0xb0) & 0x40) != 0)) {
    *(undefined *)(piVar11 + 2) = 1;
    *(undefined *)((int)piVar11 + 10) = 0;
    fVar2 = FLOAT_803e306c;
    piVar11[0x1c7] = (int)FLOAT_803e306c;
    piVar11[0x1c8] = (int)fVar2;
    piVar11[0x15] = piVar11[0x15] & 0xffffffef;
    piVar11[0x15] = piVar11[0x15] & 0xfffeffff;
    piVar11[0x15] = piVar11[0x15] & 0xfffdffff;
    piVar11[0x15] = piVar11[0x15] & 0xfffbffff;
    *(undefined *)((int)piVar11 + 0xd) = 0xff;
    *(undefined *)((int)piVar11 + 9) = 0;
    piVar11[4] = (int)fVar2;
    piVar11[5] = (int)fVar2;
  }
  for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar10 = iVar10 + 1) {
    bVar1 = *(byte *)(param_11 + iVar10 + 0x81);
    if (bVar1 == 3) {
      *(undefined *)*piVar11 = *(undefined *)((int)piVar11 + 0x82d);
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        if ((piVar11[0x15] & 0x800U) == 0) {
          uVar6 = FUN_80017ae8();
          if ((uVar6 & 0xff) != 0) {
            piVar11[0x15] = piVar11[0x15] | 0x800;
            iVar8 = 0;
            piVar4 = piVar11;
            do {
              puVar7 = FUN_80017aa4(0x24,0x4f0);
              *(undefined *)(puVar7 + 2) = 2;
              *(undefined *)((int)puVar7 + 5) = 1;
              puVar7[0xd] = (short)iVar8;
              iVar5 = FUN_80017ae4(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                   puVar7,5,*(undefined *)(uVar3 + 0xac),0xffffffff,
                                   *(uint **)(uVar3 + 0x30),param_14,param_15,param_16);
              piVar4[0x1c0] = iVar5;
              piVar4 = piVar4 + 1;
              iVar8 = iVar8 + 1;
              uVar12 = extraout_f1_00;
            } while (iVar8 < 7);
            FUN_80006824(uVar3,0x3db);
            uVar12 = FUN_800068d0(uVar3,0x3dc);
          }
        }
        else {
          piVar11[0x15] = piVar11[0x15] & 0xfffff7ff;
          piVar11[0x15] = piVar11[0x15] | 0x1000;
          iVar8 = 0;
          piVar4 = piVar11;
          do {
            FUN_801778d0(piVar4[0x1c0]);
            piVar4 = piVar4 + 1;
            iVar8 = iVar8 + 1;
          } while (iVar8 < 7);
          uVar12 = FUN_800068cc();
          iVar8 = *(int *)(uVar3 + 0xb8);
          if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
             (((0x2f < *(short *)(uVar3 + 0xa0) || (*(short *)(uVar3 + 0xa0) < 0x29)) &&
              (bVar9 = FUN_800067f0(uVar3,0x10), !bVar9)))) {
            param_14 = 0;
            uVar12 = FUN_80039468(uVar3,iVar8 + 0x3a8,0x29d,0,0xffffffff,0);
          }
        }
      }
      else if (bVar1 != 0) {
        uVar12 = FUN_80017698(0x186,1);
        uVar6 = FUN_80017690(0x186);
        if (((uVar6 != 0) && (piVar11[499] == 0)) && (uVar6 = FUN_80017ae8(), (uVar6 & 0xff) != 0))
        {
          uVar12 = FUN_800571f8(auStack_98);
          if (local_8b == '\0') {
            puVar7 = FUN_80017aa4(0x20,0x254);
          }
          else {
            puVar7 = FUN_80017aa4(0x20,0x244);
          }
          iVar8 = FUN_80017ae4(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar7
                               ,4,0xff,0xffffffff,*(uint **)(uVar3 + 0x30),param_14,param_15,
                               param_16);
          piVar11[499] = iVar8;
          uVar12 = ObjLink_AttachChild(uVar3,piVar11[499],3);
        }
      }
    }
    else if (bVar1 == 0x2c) {
      *(uint *)(*(int *)(uVar3 + 100) + 0x30) = *(uint *)(*(int *)(uVar3 + 100) + 0x30) | 4;
    }
    else if ((bVar1 < 0x2c) && (0x2a < bVar1)) {
      *(uint *)(*(int *)(uVar3 + 100) + 0x30) = *(uint *)(*(int *)(uVar3 + 100) + 0x30) & 0xfffffffb
      ;
    }
  }
  uVar12 = FUN_80135d54(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,
                        (int)piVar11,piVar11 + 0x1ea);
  uVar12 = FUN_80135d54(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,
                        (int)piVar11,piVar11 + 0x1ec);
  FUN_80135d54(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,(int)piVar11,
               piVar11 + 0x1ee);
  FUN_80136310(uVar3,piVar11);
  FUN_80135f38(uVar3,piVar11);
  FUN_8006ef38((double)FLOAT_803e3078,(double)FLOAT_803e3078,uVar3,param_11 + 0xf0,1,
               (int)(piVar11 + 0x1f6),(int)(piVar11 + 0x3e));
  if ((piVar11[0x15] & 1U) != 0) {
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xffbf;
    FUN_8003b280(uVar3,(int)(piVar11 + 0xde));
    (**(code **)(*DAT_803dd6d4 + 0x78))(uVar3,param_11,1,0xf,0x1e,0,0);
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80145ea4
 * EN v1.0 Address: 0x80145EA4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x80145BBC
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80145ea4(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80017690(0x4e4);
  if (uVar1 != 0) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x10000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80145ee8
 * EN v1.0 Address: 0x80145EE8
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x80145CE4
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80145ee8(int param_1,int param_2,int param_3)
{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (param_2 == 0) {
    *(uint *)(iVar4 + 0x54) = *(uint *)(iVar4 + 0x54) | 0x10000;
  }
  else if (*(char *)(iVar4 + 8) == '\x05') {
    if (*(char *)(iVar4 + 10) != '\0') {
      *(int *)(iVar4 + 0x24) = param_3;
    }
  }
  else if ((*(uint *)(iVar4 + 0x54) & 0x10) == 0) {
    uVar1 = FUN_800da700(param_3 + 0x18,0xffffffff,3);
    *(undefined4 *)(iVar4 + 0x700) = uVar1;
    uVar2 = FUN_80017760(0x168,0x28);
    *(float *)(iVar4 + 0x710) =
         (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e30f0);
    *(undefined *)(iVar4 + 8) = 5;
    *(int *)(iVar4 + 0x24) = param_3;
    iVar3 = *(int *)(iVar4 + 0x700) + 8;
    if (*(int *)(iVar4 + 0x28) != iVar3) {
      *(int *)(iVar4 + 0x28) = iVar3;
      *(uint *)(iVar4 + 0x54) = *(uint *)(iVar4 + 0x54) & 0xfffffbff;
      *(undefined2 *)(iVar4 + 0xd2) = 0;
    }
    *(undefined *)(iVar4 + 10) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80145fdc
 * EN v1.0 Address: 0x80145FDC
 * EN v1.0 Size: 220b
 * EN v1.1 Address: 0x80145E08
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80145fdc(int param_1,int param_2,undefined param_3,int param_4)
{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar1 + 0x798) == '\n') {
    FUN_80146f9c();
  }
  else {
    *(byte *)(iVar1 + 0xb) = *(byte *)(iVar1 + 0xb) | (byte)(1 << param_4);
    iVar3 = 0;
    iVar2 = iVar1;
    for (uVar4 = (uint)*(byte *)(iVar1 + 0x798); uVar4 != 0; uVar4 = uVar4 - 1) {
      if (*(int *)(iVar2 + 0x748) == param_2) {
        *(undefined *)(iVar1 + iVar3 * 8 + 0x74e) = 3;
        return;
      }
      iVar2 = iVar2 + 8;
      iVar3 = iVar3 + 1;
    }
    *(int *)(iVar1 + (uint)*(byte *)(iVar1 + 0x798) * 8 + 0x748) = param_2;
    *(undefined *)(iVar1 + (uint)*(byte *)(iVar1 + 0x798) * 8 + 0x74c) = param_3;
    *(char *)(iVar1 + (uint)*(byte *)(iVar1 + 0x798) * 8 + 0x74d) = (char)param_4;
    *(undefined *)(iVar1 + (uint)*(byte *)(iVar1 + 0x798) * 8 + 0x74e) = 3;
    *(char *)(iVar1 + 0x798) = *(char *)(iVar1 + 0x798) + '\x01';
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801460b8
 * EN v1.0 Address: 0x801460B8
 * EN v1.0 Size: 1980b
 * EN v1.1 Address: 0x80145F10
 * EN v1.1 Size: 1648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801460b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  char cVar1;
  ushort uVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  bool bVar11;
  undefined2 *puVar9;
  undefined4 uVar10;
  byte bVar12;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar13;
  double extraout_f1;
  double extraout_f1_00;
  double dVar14;
  char local_38 [4];
  char local_34 [4];
  undefined4 local_30 [12];
  
  iVar6 = FUN_80286834();
  iVar13 = *(int *)(iVar6 + 0xb8);
  bVar11 = false;
  bVar3 = false;
  bVar4 = false;
  bVar5 = false;
  local_30[0] = DAT_803e3058;
  dVar14 = extraout_f1;
  uVar7 = FUN_80017690(0x4e4);
  if (uVar7 != 0) {
    if ((*(uint *)(iVar13 + 0x54) & 0x10) != 0) {
      *(undefined *)(iVar13 + 0xb) = 0;
    }
    cVar1 = *(char *)(iVar13 + 8);
    if (((cVar1 == '\b') || (cVar1 == '\r')) ||
       ((cVar1 == '\x0e' && (*(char *)(iVar13 + 10) == '\x01')))) {
      bVar3 = true;
    }
    else {
      iVar8 = FUN_801365c4();
      dVar14 = extraout_f1_00;
      if (iVar8 != 0) {
        bVar3 = true;
        bVar5 = true;
      }
    }
    if (*(char *)(iVar13 + 0xb) != '\0') {
      for (bVar12 = 0; bVar12 < *(byte *)(iVar13 + 0x798); bVar12 = bVar12 + 1) {
        iVar8 = iVar13 + (uint)bVar12 * 8;
        cVar1 = *(char *)(iVar8 + 0x74c);
        if (cVar1 == '\0') {
          if (*(short *)(*(int *)(iVar8 + 0x748) + 0x46) == 0x6a) {
            bVar4 = true;
          }
          bVar3 = true;
        }
        else if (cVar1 == '\x01') {
          bVar11 = true;
        }
      }
    }
    if (((*(uint *)(iVar13 + 0x54) & 0x10) == 0) && (uVar7 = FUN_80017690(0x3f8), uVar7 != 0)) {
      iVar8 = FUN_80017a98();
      iVar8 = FUN_80294c80(iVar8);
      if ((iVar8 != 0) && (uVar7 = FUN_80017690(0xd00), uVar7 == 0)) {
        FUN_80294ca8(*(int *)(iVar13 + 4));
      }
    }
    FUN_80017690(0xdd);
    FUN_80017690(0x9e);
    FUN_80017690(0x245);
    *(undefined *)(iVar13 + 0xb) = 0;
    if ((bVar11) && ((*(uint *)(iVar13 + 0x54) & 0x200) == 0)) {
      *(float *)(iVar13 + 0x7b4) = FLOAT_803e3188;
      if ((*(int *)(iVar13 + 0x7b0) == 0) && (uVar7 = FUN_80017ae8(), (uVar7 & 0xff) != 0)) {
        uVar7 = FUN_80017760(0,1);
        uVar2 = *(ushort *)((int)local_30 + uVar7 * 2);
        iVar8 = *(int *)(iVar6 + 0xb8);
        if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < *(short *)(iVar6 + 0xa0) || (*(short *)(iVar6 + 0xa0) < 0x29)) &&
            (bVar11 = FUN_800067f0(iVar6,0x10), !bVar11)))) {
          in_r8 = 0;
          dVar14 = (double)FUN_80039468(iVar6,iVar8 + 0x3a8,uVar2,0x500,0xffffffff,0);
        }
        puVar9 = FUN_80017aa4(0x20,0x17c);
        local_34[0] = -1;
        local_34[1] = -1;
        local_34[2] = -1;
        if (*(int *)(iVar13 + 0x7a8) != 0) {
          local_34[*(byte *)(iVar13 + 0x7bc) >> 6] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b0) != 0) {
          local_34[*(byte *)(iVar13 + 0x7bc) >> 4 & 3] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b8) != 0) {
          local_34[*(byte *)(iVar13 + 0x7bc) >> 2 & 3] = '\x01';
        }
        if (local_34[0] == -1) {
          uVar7 = 0;
        }
        else if (local_34[1] == -1) {
          uVar7 = 1;
        }
        else if (local_34[2] == -1) {
          uVar7 = 2;
        }
        else if (local_34[3] == -1) {
          uVar7 = 3;
        }
        else {
          uVar7 = 0xffffffff;
        }
        *(byte *)(iVar13 + 0x7bc) =
             (byte)((uVar7 & 0xff) << 4) & 0x30 | *(byte *)(iVar13 + 0x7bc) & 0xcf;
        uVar10 = FUN_80017ae4(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar9,
                              4,0xff,0xffffffff,*(uint **)(iVar6 + 0x30),in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar13 + 0x7b0) = uVar10;
        dVar14 = (double)ObjLink_AttachChild(iVar6,*(int *)(iVar13 + 0x7b0),
                                      *(byte *)(iVar13 + 0x7bc) >> 4 & 3);
      }
    }
    else if (*(int *)(iVar13 + 0x7b0) != 0) {
      *(float *)(iVar13 + 0x7b4) = *(float *)(iVar13 + 0x7b4) - FLOAT_803dc074;
      dVar14 = (double)*(float *)(iVar13 + 0x7b4);
      if (dVar14 <= (double)FLOAT_803e306c) {
        dVar14 = (double)FUN_80135d54(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,iVar6,iVar13,(int *)(iVar13 + 0x7b0));
      }
    }
    if ((bVar3) && ((*(uint *)(iVar13 + 0x54) & 0x200) == 0)) {
      *(float *)(iVar13 + 0x7ac) = FLOAT_803e3188;
      if ((*(int *)(iVar13 + 0x7a8) == 0) && (uVar7 = FUN_80017ae8(), (uVar7 & 0xff) != 0)) {
        uVar7 = FUN_80017760(0,3);
        if (uVar7 == 0) {
          if (bVar4) {
            iVar8 = *(int *)(iVar6 + 0xb8);
            if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
               (((0x2f < *(short *)(iVar6 + 0xa0) || (*(short *)(iVar6 + 0xa0) < 0x29)) &&
                (bVar11 = FUN_800067f0(iVar6,0x10), !bVar11)))) {
              in_r8 = 0;
              dVar14 = (double)FUN_80039468(iVar6,iVar8 + 0x3a8,0x359,0x500,0xffffffff,0);
            }
          }
          else if ((((bVar5) &&
                    (iVar8 = *(int *)(iVar6 + 0xb8), (*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0)) &&
                   ((0x2f < *(short *)(iVar6 + 0xa0) || (*(short *)(iVar6 + 0xa0) < 0x29)))) &&
                  (bVar11 = FUN_800067f0(iVar6,0x10), !bVar11)) {
            in_r8 = 0;
            dVar14 = (double)FUN_80039468(iVar6,iVar8 + 0x3a8,0x358,0x500,0xffffffff,0);
          }
        }
        puVar9 = FUN_80017aa4(0x20,0x175);
        local_38[0] = -1;
        local_38[1] = -1;
        local_38[2] = -1;
        if (*(int *)(iVar13 + 0x7a8) != 0) {
          local_38[*(byte *)(iVar13 + 0x7bc) >> 6] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b0) != 0) {
          local_38[*(byte *)(iVar13 + 0x7bc) >> 4 & 3] = '\x01';
        }
        if (*(int *)(iVar13 + 0x7b8) != 0) {
          local_38[*(byte *)(iVar13 + 0x7bc) >> 2 & 3] = '\x01';
        }
        if (local_38[0] == -1) {
          uVar7 = 0;
        }
        else if (local_38[1] == -1) {
          uVar7 = 1;
        }
        else if (local_38[2] == -1) {
          uVar7 = 2;
        }
        else if (local_38[3] == -1) {
          uVar7 = 3;
        }
        else {
          uVar7 = 0xffffffff;
        }
        *(byte *)(iVar13 + 0x7bc) = (byte)((uVar7 & 0xff) << 6) | *(byte *)(iVar13 + 0x7bc) & 0x3f;
        uVar10 = FUN_80017ae4(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar9,
                              4,0xff,0xffffffff,*(uint **)(iVar6 + 0x30),in_r8,in_r9,in_r10);
        *(undefined4 *)(iVar13 + 0x7a8) = uVar10;
        ObjLink_AttachChild(iVar6,*(int *)(iVar13 + 0x7a8),(ushort)(*(byte *)(iVar13 + 0x7bc) >> 6));
      }
    }
    else if (*(int *)(iVar13 + 0x7a8) != 0) {
      *(float *)(iVar13 + 0x7ac) = *(float *)(iVar13 + 0x7ac) - FLOAT_803dc074;
      if ((double)*(float *)(iVar13 + 0x7ac) <= (double)FLOAT_803e306c) {
        FUN_80135d54((double)*(float *)(iVar13 + 0x7ac),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,iVar6,iVar13,(int *)(iVar13 + 0x7a8));
      }
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80146874
 * EN v1.0 Address: 0x80146874
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x80146580
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80146874(void)
{
  uint uVar1;
  uint uVar2;
  
  uVar2 = 0;
  uVar1 = FUN_80017690(0x4e4);
  if (uVar1 != 0) {
    uVar2 = 10;
    uVar1 = FUN_80017690(0xdd);
    if (uVar1 != 0) {
      uVar2 = 0xb;
    }
    uVar1 = FUN_80017690(0x25);
    if (uVar1 != 0) {
      uVar2 = uVar2 | 0x20;
    }
    uVar1 = FUN_80017690(0x245);
    if (uVar1 != 0) {
      uVar2 = uVar2 | 0x10;
    }
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801468f0
 * EN v1.0 Address: 0x801468F0
 * EN v1.0 Size: 804b
 * EN v1.1 Address: 0x80146604
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801468f0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  FUN_80046f44((uint *)(iVar2 + 0x538));
  FUN_80046f44((uint *)(iVar2 + 0x568));
  FUN_80046f44((uint *)(iVar2 + 0x598));
  FUN_80046f44((uint *)(iVar2 + 0x5c8));
  FUN_80046f44((uint *)(iVar2 + 0x5f8));
  FUN_80046f44((uint *)(iVar2 + 0x628));
  FUN_80046f44((uint *)(iVar2 + 0x658));
  FUN_80046f44((uint *)(iVar2 + 0x688));
  FUN_80046f44((uint *)(iVar2 + 0x6b8));
  ObjGroup_RemoveObject(param_9,1);
  (**(code **)(*DAT_803dd6f8 + 0x14))(param_9);
  if ((param_10 == 0) && ((*(uint *)(iVar2 + 0x54) & 0x800) != 0)) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) & 0xfffff7ff;
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x1000;
    iVar4 = 0;
    iVar3 = iVar2;
    do {
      FUN_801778d0(*(int *)(iVar3 + 0x700));
      iVar3 = iVar3 + 4;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 7);
    FUN_800068cc();
    iVar3 = *(int *)(param_9 + 0xb8);
    if (((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
        (bVar1 = FUN_800067f0(param_9,0x10), !bVar1)))) {
      FUN_80039468(param_9,iVar3 + 0x3a8,0x29d,0,0xffffffff,0);
    }
  }
  uVar5 = FUN_800dd3dc();
  uVar5 = FUN_80135d54(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar2,
                       (int *)(iVar2 + 0x7a8));
  uVar5 = FUN_80135d54(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar2,
                       (int *)(iVar2 + 0x7b0));
  uVar5 = FUN_80135d54(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar2,
                       (int *)(iVar2 + 0x7b8));
  if (*(int *)(iVar2 + 0x7cc) != 0) {
    uVar5 = ObjLink_DetachChild(param_9,*(int *)(iVar2 + 0x7cc));
    uVar5 = FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         *(int *)(iVar2 + 0x7cc));
  }
  if ((*(char *)(iVar2 + 0x58) < '\0') && (DAT_803de6c8 != 0)) {
    FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803de6c8);
    DAT_803de6c8 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80146c14
 * EN v1.0 Address: 0x80146C14
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x801467E4
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146c14(void)
{
  byte bVar1;
  undefined2 *puVar2;
  char in_r8;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  puVar2 = (undefined2 *)FUN_80286830();
  if (in_r8 != '\0') {
    iVar6 = *(int *)(puVar2 + 0x5c);
    FUN_8003b818((int)puVar2);
    iVar4 = *(int *)(puVar2 + 0x5c);
    iVar5 = 0;
    iVar3 = iVar4;
    do {
      ObjPath_GetPointWorldPosition(puVar2,iVar5 + 4,(float *)(iVar3 + 0x3d8),(undefined4 *)(iVar3 + 0x3dc),
                   (float *)(iVar3 + 0x3e0),0);
      iVar3 = iVar3 + 0xc;
      iVar5 = iVar5 + 1;
    } while (iVar5 < 4);
    ObjPath_GetPointWorldPosition(puVar2,8,(float *)(iVar4 + 0x408),(undefined4 *)(iVar4 + 0x40c),
                 (float *)(iVar4 + 0x410),0);
    iVar3 = FUN_8003964c((int)puVar2,0);
    *(undefined2 *)(iVar4 + 0x414) = *(undefined2 *)(iVar3 + 2);
    if ((*(uint *)(iVar6 + 0x54) & 0x10) != 0) {
      bVar1 = *(byte *)(iVar6 + 8);
      if (bVar1 == 3) {
        if (*(char *)(iVar6 + 10) == '\x04') {
          FUN_8013a408(puVar2);
        }
      }
      else if ((bVar1 < 3) && (1 < bVar1)) {
        FUN_8013a408(puVar2);
      }
      if ((((*(uint *)(iVar6 + 0x54) & 0x200) == 0) && (*(char *)(iVar6 + 8) == '\v')) &&
         (2 < *(byte *)(iVar6 + 10))) {
        if (*(byte *)(iVar6 + 10) != 3) {
          *(undefined4 *)(*(int *)(iVar6 + 0x700) + 0xc) = *(undefined4 *)(iVar6 + 0x408);
          *(undefined4 *)(*(int *)(iVar6 + 0x700) + 0x10) = *(undefined4 *)(iVar6 + 0x40c);
          *(undefined4 *)(*(int *)(iVar6 + 0x700) + 0x14) = *(undefined4 *)(iVar6 + 0x410);
        }
        FUN_8003b818(*(int *)(iVar6 + 0x700));
      }
    }
    FUN_801367b4(puVar2,iVar6);
    ObjPath_GetPointWorldPositionArray(puVar2,4,4,(float *)(iVar6 + 0x7d8));
    *(float *)(iVar6 + 0x838) = *(float *)(iVar6 + 0x838) - FLOAT_803dc074;
    if (FLOAT_803e306c < *(float *)(iVar6 + 0x838)) {
      FUN_8008111c((double)FLOAT_803e31cc,(double)FLOAT_803e3078,puVar2,6,(int *)0x0);
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80146db8
 * EN v1.0 Address: 0x80146DB8
 * EN v1.0 Size: 476b
 * EN v1.1 Address: 0x801469B4
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146db8(int param_1)
{
  float fVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  int local_18 [2];
  
  iVar4 = *(int *)(param_1 + 0xb8);
  fVar1 = *(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x84);
  if (fVar1 < FLOAT_803e306c) {
    fVar1 = -fVar1;
  }
  if (FLOAT_803e3078 == fVar1) {
    if (*(float *)(param_1 + 0x10) == *(float *)(param_1 + 0x1c)) {
      *(byte *)(iVar4 + 0x58) = *(byte *)(iVar4 + 0x58) & 0xdf | 0x20;
      *(undefined4 *)(iVar4 + 0x5c) = 0xffffffff;
      *(float *)(iVar4 + 0x60) = FLOAT_803e306c;
    }
  }
  else {
    iVar3 = FUN_80017af8(0x46406);
    if ((iVar3 != 0) &&
       (dVar5 = FUN_80017708((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18)),
       dVar5 < (double)FLOAT_803e31d0)) {
      *(byte *)(iVar4 + 0x58) = *(byte *)(iVar4 + 0x58) & 0xdf | 0x20;
      *(undefined4 *)(iVar4 + 0x5c) = 0x46406;
      *(float *)(iVar4 + 0x60) = FLOAT_803e306c;
    }
  }
  if ((*(byte *)(iVar4 + 0x58) >> 5 & 1) != 0) {
    piVar2 = ObjGroup_GetObjects(0x51,local_18);
    for (iVar3 = 0; iVar3 < local_18[0]; iVar3 = iVar3 + 1) {
      dVar5 = FUN_80194a70(*piVar2,3);
      if (*(int *)(iVar4 + 0x5c) == -1) {
        fVar1 = (float)(dVar5 - (double)*(float *)(param_1 + 0x10));
        if (fVar1 < FLOAT_803e306c) {
          fVar1 = -fVar1;
        }
        if (fVar1 < FLOAT_803e3148) {
          *(undefined4 *)(iVar4 + 0x5c) = *(undefined4 *)(*(int *)(*piVar2 + 0x4c) + 0x14);
        }
      }
      if (*(int *)(iVar4 + 0x5c) == *(int *)(*(int *)(*piVar2 + 0x4c) + 0x14)) {
        if (((double)*(float *)(iVar4 + 0x60) == (double)FLOAT_803e306c) ||
           ((double)*(float *)(iVar4 + 0x60) != dVar5)) {
          *(float *)(param_1 + 0x10) = (float)dVar5;
          *(float *)(iVar4 + 0x60) = (float)dVar5;
        }
        else {
          *(byte *)(iVar4 + 0x58) = *(byte *)(iVar4 + 0x58) & 0xdf;
        }
        break;
      }
      piVar2 = piVar2 + 1;
    }
    if (iVar3 == local_18[0]) {
      *(byte *)(iVar4 + 0x58) = *(byte *)(iVar4 + 0x58) & 0xdf;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80146f94
 * EN v1.0 Address: 0x80146F94
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80146BA8
 * EN v1.1 Size: 8672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146f94(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80146f98
 * EN v1.0 Address: 0x80146F98
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80148D88
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146f98(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80146f9c
 * EN v1.0 Address: 0x80146F9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80148FA0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146f9c(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80146fa0
 * EN v1.0 Address: 0x80146FA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80148FF0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146fa0(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80146fa4
 * EN v1.0 Address: 0x80146FA4
 * EN v1.0 Size: 628b
 * EN v1.1 Address: 0x80149040
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80146fa4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  *(undefined *)(param_10 + 0x2ef) = 1;
  if (((*(uint *)(param_10 + 0x2dc) & 0x1000) != 0) && ((*(uint *)(param_10 + 0x2e0) & 0x1000) == 0)
     ) {
    *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) & 0xbfff;
    param_2 = (double)*(float *)(param_10 + 0x314);
    if ((double)FLOAT_803e31fc == param_2) {
      *(float *)(param_10 + 0x308) = FLOAT_803e3208;
    }
    else {
      *(float *)(param_10 + 0x308) = FLOAT_803e3200 / (float)((double)FLOAT_803e3204 * param_2);
    }
    *(undefined *)(param_10 + 0x323) = 1;
    FUN_800305f8((double)FLOAT_803e31fc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(uint)*(byte *)(param_10 + 800),0x10,param_12,param_13,param_14,param_15,
                 param_16);
    if (*(int *)(param_9 + 0x54) != 0) {
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
    }
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 4;
    FUN_800067e8(param_9,1099,2);
    ObjHits_EnableObject(param_9);
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) == 0) {
    *(char *)(param_9 + 0x36) = (char)(int)(FLOAT_803e3210 * *(float *)(param_9 + 0x98));
    *(undefined4 *)(param_10 + 0x30c) = *(undefined4 *)(param_9 + 0x98);
  }
  else {
    *(float *)(param_10 + 0x308) = FLOAT_803e320c;
    *(undefined *)(param_10 + 0x323) = 0;
    FUN_800305f8((double)FLOAT_803e31fc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    if (*(int *)(param_9 + 0x54) != 0) {
      *(undefined *)(*(int *)(param_9 + 0x54) + 0x70) = 0;
    }
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xffffef7f;
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) & 0xfffffffb;
    *(float *)(param_10 + 0x30c) = FLOAT_803e31fc;
    *(undefined *)(param_9 + 0x36) = 0xff;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80147218
 * EN v1.0 Address: 0x80147218
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801491D4
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147218(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8014721c
 * EN v1.0 Address: 0x8014721C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80149528
 * EN v1.1 Size: 2796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014721c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80147220
 * EN v1.0 Address: 0x80147220
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x8014A014
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147220(double param_1,int param_2,uint param_3,undefined2 param_4)
{
  *(undefined *)(param_2 + 0x2f1) = 0;
  if ((param_3 & 2) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 0x20;
  }
  if ((param_3 & 1) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 0x40;
  }
  if ((param_3 & 4) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 1;
  }
  if ((param_3 & 8) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 2;
  }
  if ((param_3 & 0x10) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 4;
  }
  if ((double)FLOAT_803e3238 == param_1) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 8;
  }
  else if ((double)FLOAT_803e3228 == param_1) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 0x10;
  }
  if ((param_3 & 0x80) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 0x80;
  }
  if ((param_3 & 0x100) == 0) {
    if ((param_3 & 0x200) == 0) {
      if ((param_3 & 0x400) != 0) {
        *(undefined *)(param_2 + 0x2f5) = 3;
      }
    }
    else {
      *(undefined *)(param_2 + 0x2f5) = 2;
    }
  }
  else {
    *(undefined *)(param_2 + 0x2f5) = 1;
  }
  *(undefined2 *)(param_2 + 0x2ec) = param_4;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80147314
 * EN v1.0 Address: 0x80147314
 * EN v1.0 Size: 952b
 * EN v1.1 Address: 0x8014A14C
 * EN v1.1 Size: 876b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147314(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined2 *unaff_r30;
  int iVar6;
  double dVar7;
  double in_f29;
  double in_f30;
  double dVar8;
  double in_f31;
  double dVar9;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined2 local_5c;
  undefined4 local_58;
  undefined4 local_54;
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
  iVar4 = FUN_8028683c();
  iVar6 = *(int *)(iVar4 + 0x4c);
  local_58 = DAT_803e31e8;
  local_54 = DAT_803e31ec;
  local_68 = DAT_803e31f0;
  local_60 = DAT_803e31f4;
  local_5c = DAT_803e31f8;
  if ((param_11 == 0) || (uVar5 = FUN_80017ae8(), (uVar5 & 0xff) == 0)) goto LAB_8014a488;
  uVar5 = param_13 & 0xff;
  if (uVar5 == 1) {
    iVar3 = ((int)(param_11 & 0xf00) >> 8) + -1;
    if (3 < iVar3) {
      iVar3 = 3;
    }
    unaff_r30 = FUN_80017aa4(0x30,*(undefined2 *)((int)&local_58 + iVar3 * 2));
  }
  else if (uVar5 == 2) {
    iVar3 = ((int)(param_11 & 0xf000) >> 0xc) + -1;
    if (1 < iVar3) {
      iVar3 = 1;
    }
    unaff_r30 = FUN_80017aa4(0x30,*(undefined2 *)((int)&local_68 + iVar3 * 2));
  }
  else if (uVar5 == 3) {
    if (param_11 == 3) {
      unaff_r30 = FUN_80017aa4(0x30,0xb);
    }
    else if ((int)param_11 < 3) {
      if (param_11 != 1) goto LAB_8014a488;
      unaff_r30 = FUN_80017aa4(0x30,0x2cd);
    }
    else {
      if (param_11 == 5) {
        dVar9 = (double)*(float *)(iVar4 + 0x18);
        dVar8 = (double)*(float *)(iVar4 + 0x1c);
        dVar7 = (double)*(float *)(iVar4 + 0x20);
        iVar6 = *(int *)(iVar4 + 0x4c);
        if (iVar6 != 0) {
          *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(iVar6 + 8);
          *(undefined4 *)(iVar4 + 0x1c) = *(undefined4 *)(iVar6 + 0xc);
          *(undefined4 *)(iVar4 + 0x20) = *(undefined4 *)(iVar6 + 0x10);
        }
        local_64 = FLOAT_803e323c;
        DAT_803de6d4 = ObjGroup_FindNearestObject(4,iVar4,(float *)&local_64);
        *(float *)(iVar4 + 0x18) = (float)dVar9;
        *(float *)(iVar4 + 0x1c) = (float)dVar8;
        *(float *)(iVar4 + 0x20) = (float)dVar7;
        if (DAT_803de6d4 != 0) {
          uVar1 = *(undefined4 *)(iVar4 + 0xc);
          *(undefined4 *)(DAT_803de6d4 + 0x18) = uVar1;
          *(undefined4 *)(DAT_803de6d4 + 0xc) = uVar1;
          fVar2 = FLOAT_803e3240 + *(float *)(iVar4 + 0x10);
          *(float *)(DAT_803de6d4 + 0x1c) = fVar2;
          *(float *)(DAT_803de6d4 + 0x10) = fVar2;
          uVar1 = *(undefined4 *)(iVar4 + 0x14);
          *(undefined4 *)(DAT_803de6d4 + 0x20) = uVar1;
          *(undefined4 *)(DAT_803de6d4 + 0x14) = uVar1;
        }
        goto LAB_8014a488;
      }
      if (4 < (int)param_11) goto LAB_8014a488;
      unaff_r30 = FUN_80017aa4(0x30,0x2cd);
    }
  }
  else if (uVar5 == 4) {
    if (3 < (int)param_11) {
      param_11 = 3;
    }
    if ((int)param_11 < 1) goto LAB_8014a488;
    unaff_r30 = FUN_80017aa4(0x30,*(undefined2 *)((int)&local_64 + param_11 * 2 + 2));
  }
  *(undefined *)(unaff_r30 + 0xd) = 0x14;
  unaff_r30[0x16] = 0xffff;
  unaff_r30[0xe] = 0xffff;
  unaff_r30[0x12] = 0xffff;
  *(undefined4 *)(unaff_r30 + 4) = *(undefined4 *)(iVar4 + 0xc);
  dVar7 = (double)FLOAT_803e322c;
  *(float *)(unaff_r30 + 6) = (float)(dVar7 + (double)*(float *)(iVar4 + 0x10));
  *(undefined4 *)(unaff_r30 + 8) = *(undefined4 *)(iVar4 + 0x14);
  if ((param_12 & 0xff) == 0) {
    unaff_r30[0x17] = 1;
  }
  else {
    unaff_r30[0x17] = 2;
  }
  *(undefined *)(unaff_r30 + 2) = *(undefined *)(iVar6 + 4);
  *(undefined *)(unaff_r30 + 3) = *(undefined *)(iVar6 + 6);
  *(undefined *)((int)unaff_r30 + 5) = *(undefined *)(iVar6 + 5);
  *(undefined *)((int)unaff_r30 + 7) = *(undefined *)(iVar6 + 7);
  DAT_803de6d4 = FUN_80017ae4(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              unaff_r30,5,*(undefined *)(iVar4 + 0xac),0xffffffff,
                              *(uint **)(iVar4 + 0x30),param_14,param_15,param_16);
  if ((*(short *)(DAT_803de6d4 + 0x46) == 0x3cd) || (*(short *)(DAT_803de6d4 + 0x46) == 0xb)) {
    (**(code **)(**(int **)(DAT_803de6d4 + 0x68) + 0x2c))
              ((double)FLOAT_803e31fc,(double)FLOAT_803e3200,(double)FLOAT_803e31fc);
  }
LAB_8014a488:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801476cc
 * EN v1.0 Address: 0x801476CC
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x8014A4B8
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801476cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  iVar3 = *(int *)(param_9 + 0x4c);
  if ((*(short *)(param_10 + 0x2b4) != *(short *)(param_10 + 0x2b6)) &&
     (*(char *)(param_9 + 0x36) != '\0')) {
    iVar4 = *(int *)(param_9 + 200);
    if (iVar4 != 0) {
      uVar5 = ObjLink_DetachChild(param_9,iVar4);
      param_1 = FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
    }
    uVar1 = FUN_80017ae8();
    if ((uVar1 & 0xff) == 0) {
      *(undefined2 *)(param_10 + 0x2b4) = 0;
    }
    else if (0 < *(short *)(param_10 + 0x2b6)) {
      puVar2 = FUN_80017aa4(0x20,*(short *)(param_10 + 0x2b6));
      *(byte *)((int)puVar2 + 5) = *(byte *)((int)puVar2 + 5) | *(byte *)(iVar3 + 5) & 0x18;
      iVar3 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,4,
                           *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),
                           in_r8,in_r9,in_r10);
      ObjLink_AttachChild(param_9,iVar3,0);
      *(undefined2 *)(param_10 + 0x2b4) = *(undefined2 *)(param_10 + 0x2b6);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80147884
 * EN v1.0 Address: 0x80147884
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x8014A5B0
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147884(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,float *param_11,float *param_12)
{
  short sVar1;
  bool bVar2;
  int *piVar3;
  char cVar4;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  char local_a0 [4];
  short asStack_9c [4];
  short asStack_94 [4];
  float afStack_8c [3];
  float local_80;
  float local_7c;
  float local_78;
  int aiStack_74 [29];
  
  uVar7 = FUN_8028683c();
  piVar3 = (int *)((ulonglong)uVar7 >> 0x20);
  iVar5 = (int)uVar7;
  local_a0[0] = '\0';
  cVar4 = '\0';
  if (*(int *)(iVar5 + 0x29c) != 0) {
    local_80 = *param_11;
    local_7c = param_11[1];
    local_78 = param_11[2];
    bVar2 = true;
    sVar1 = *(short *)((int)piVar3 + 0x46);
    if (((((sVar1 != 0x613) && (sVar1 != 0x642)) && (sVar1 != 0x3fe)) &&
        ((sVar1 != 0x7c6 && (sVar1 != 0x7c8)))) && ((sVar1 != 0x251 && (sVar1 != 0x851)))) {
      local_7c = local_7c + FLOAT_803e3234;
      bVar2 = false;
    }
    FUN_80006a68(&local_80,asStack_9c);
    local_80 = *param_12;
    local_7c = FLOAT_803e3234 + param_12[1];
    local_78 = param_12[2];
    FUN_80006a68(&local_80,asStack_94);
    FUN_80247eb8(param_11,&local_80,afStack_8c);
    dVar6 = FUN_80247f54(afStack_8c);
    if (dVar6 < (double)FLOAT_803e3244) {
      if (piVar3[0xc] == 0) {
        cVar4 = FUN_80006a64(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             asStack_94,asStack_9c,(undefined4 *)0x0,local_a0,0);
      }
      if ((!bVar2) && (local_a0[0] == '\x01')) {
        cVar4 = '\x01';
      }
    }
  }
  if ((cVar4 != '\0') && ((*(uint *)(iVar5 + 0x2e4) & 8) != 0)) {
    FUN_800620e8(param_11,&local_80,(float *)0x0,aiStack_74,piVar3,(uint)*(byte *)(iVar5 + 0x261),
                 0xffffffff,0,0);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80147a70
 * EN v1.0 Address: 0x80147A70
 * EN v1.0 Size: 700b
 * EN v1.1 Address: 0x8014A764
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147a70(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  short sVar2;
  int *piVar3;
  char cVar5;
  int iVar4;
  int iVar6;
  ushort uVar7;
  double extraout_f1;
  double dVar8;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  char local_110 [4];
  short asStack_10c [4];
  short asStack_104 [4];
  float afStack_fc [3];
  uint local_f0 [4];
  float local_e0;
  float local_dc;
  float local_d8;
  int aiStack_d4 [21];
  undefined4 local_80;
  uint uStack_7c;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
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
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  uVar11 = FUN_8028683c();
  piVar3 = (int *)((ulonglong)uVar11 >> 0x20);
  iVar6 = (int)uVar11;
  local_f0[0] = DAT_802c2970;
  local_f0[1] = DAT_802c2974;
  local_f0[2] = DAT_802c2978;
  local_f0[3] = DAT_802c297c;
  local_e0 = (float)piVar3[3];
  local_dc = FLOAT_803e3234 + (float)piVar3[4];
  local_d8 = (float)piVar3[5];
  dVar10 = extraout_f1;
  FUN_80006a68(&local_e0,asStack_10c);
  if ((short *)piVar3[0xc] == (short *)0x0) {
    sVar2 = *(short *)piVar3;
  }
  else {
    sVar2 = *(short *)piVar3 + *(short *)piVar3[0xc];
  }
  dVar9 = (double)FLOAT_803e3244;
  for (uVar7 = 0; uVar7 < 4; uVar7 = uVar7 + 1) {
    uStack_7c = (int)sVar2 + (uint)uVar7 * 0x4000 ^ 0x80000000;
    local_80 = 0x43300000;
    dVar8 = (double)FUN_80293f90();
    local_e0 = -(float)(dVar10 * dVar8 - (double)(float)piVar3[6]);
    local_dc = (float)piVar3[7];
    dVar8 = (double)FUN_80294964();
    local_d8 = -(float)(dVar10 * dVar8 - (double)(float)piVar3[8]);
    sVar1 = *(short *)((int)piVar3 + 0x46);
    if (((((sVar1 != 0x613) && (sVar1 != 0x642)) && (sVar1 != 0x3fe)) &&
        ((sVar1 != 0x7c6 && (sVar1 != 0x7c8)))) && ((sVar1 != 0x251 && (sVar1 != 0x851)))) {
      local_dc = local_dc + FLOAT_803e3234;
    }
    FUN_80006a68(&local_e0,asStack_104);
    FUN_80247eb8((float *)(piVar3 + 6),&local_e0,afStack_fc);
    dVar8 = FUN_80247f54(afStack_fc);
    if (dVar9 <= dVar8) {
      cVar5 = '\0';
    }
    else if (piVar3[0xc] == 0) {
      cVar5 = FUN_80006a64(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,asStack_104
                           ,asStack_10c,(undefined4 *)0x0,local_110,0);
      if (local_110[0] == '\x01') {
        cVar5 = '\x01';
      }
    }
    else {
      cVar5 = '\x01';
    }
    if ((cVar5 != '\0') && ((*(uint *)(iVar6 + 0x2e4) & 8) != 0)) {
      iVar4 = FUN_800620e8(piVar3 + 6,&local_e0,(float *)0x0,aiStack_d4,piVar3,
                           (uint)*(byte *)(iVar6 + 0x261),0xffffffff,0,0);
      if (iVar4 != 0) {
        cVar5 = '\0';
      }
    }
    if (cVar5 == '\0') {
      *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) & ~local_f0[uVar7];
    }
    else {
      *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) | local_f0[uVar7];
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80147d2c
 * EN v1.0 Address: 0x80147D2C
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x8014AA5C
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80147d2c(int param_1,int param_2)
{
  float local_28;
  float local_24;
  float afStack_20 [6];
  
  *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xf7efffff;
  if ((*(uint *)(param_2 + 0x2e4) & 0x28000002) == 0) {
    if ((*(uint *)(param_2 + 0x2e4) & 0xc) == 0) {
      *(undefined *)(param_2 + 0x25f) = 0;
    }
    else {
      *(undefined *)(param_2 + 0x25f) = 1;
    }
  }
  else {
    FUN_8014a9f0(param_1,param_2,&local_24,&local_28);
    if ((*(uint *)(param_2 + 0x2e4) & 0x8000000) == 0) {
      if ((*(uint *)(param_2 + 0x2e4) & 0x20000000) == 0) {
        local_24 = local_24 - *(float *)(param_1 + 0x10);
        if ((FLOAT_803e3250 < local_24) && (local_24 < FLOAT_803e3234)) {
          *(float *)(param_1 + 0x28) = local_24 * FLOAT_803dc078;
          *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x100000;
        }
      }
      else {
        local_24 = local_24 - *(float *)(param_1 + 0x10);
        if ((FLOAT_803e3250 < local_24) && (local_24 < FLOAT_803e3234)) {
          *(float *)(param_1 + 0x28) = (FLOAT_803e3254 + local_24) * FLOAT_803dc078;
          *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x8000000;
        }
      }
    }
    else {
      *(float *)(param_1 + 0x28) = (local_28 - *(float *)(param_1 + 0x10)) * FLOAT_803dc078;
    }
    if ((*(uint *)(param_2 + 0x2e4) & 8) == 0) {
      *(undefined *)(param_2 + 0x25f) = 0;
    }
  }
  (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_1,param_2 + 4);
  if ((*(uint *)(param_2 + 0x2e4) & 4) != 0) {
    (**(code **)(*DAT_803dd728 + 0x14))(param_1,param_2 + 4);
  }
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_1,param_2 + 4);
  if (((*(char *)(param_2 + 0x25f) != '\0') && ((*(uint *)(param_2 + 0x2e4) & 0x28000002) == 0)) &&
     ((*(byte *)(param_2 + 0x264) & 0x10) != 0)) {
    *(float *)(param_1 + 0x28) = FLOAT_803e31fc;
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x100000;
  }
  if ((*(uint *)(param_2 + 0x2e4) & 0x200000) != 0) {
    ObjPath_GetPointWorldPositionArray(param_1,2,2,afStack_20);
    FUN_8006dca8((double)*(float *)(param_2 + 0x310),(double)FLOAT_803e3200,param_1,
                 (uint)*(ushort *)(param_2 + 0x2f8),7,(int)afStack_20,param_2 + 4);
  }
  return;
}

/* 8b "li r3, N; blr" returners. */
int fn_801461D4(void) { return 0x83c; }

/* misc 16b 4-insn patterns. */
#pragma scheduling off
u8 fn_801459C0(int *obj) { return *((u8*)((int**)obj)[0xb8/4][0x0/4] + 0x1); }
u8 fn_801459D0(int *obj) { return *((u8*)((int**)obj)[0xb8/4][0x0/4] + 0x0); }
#pragma scheduling reset
