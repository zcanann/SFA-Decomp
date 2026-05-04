#include "ghidra_import.h"
#include "main/dll/mediumbasket.h"

extern undefined8 FUN_80003494();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_80006a54();
extern undefined4 FUN_80017698();
extern uint FUN_80017760();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017964();
extern int FUN_80017a54();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjMsg_SendToObjects();
extern uint ObjPath_GetPointModelMtx();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8006fb00();
extern undefined4 FUN_8014d3d0();
extern undefined8 FUN_8014d4c8();
extern undefined4 FUN_8015a320();
extern undefined4 FUN_8015a6c0();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint countLeadingZeros();

extern undefined4 DAT_803209d0;
extern undefined4 DAT_803209e0;
extern undefined DAT_80320a88;
extern undefined4 DAT_80320a98;
extern undefined4 DAT_803ad188;
extern undefined4 DAT_803ad1a8;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc990;
extern undefined4 DAT_803dc994;
extern undefined4 DAT_803dc998;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de6f8;
extern undefined4 DAT_803de6f9;
extern f64 DOUBLE_803e3948;
extern f64 DOUBLE_803e3978;
extern f64 DOUBLE_803e39a0;
extern f64 DOUBLE_803e3a00;
extern f32 lbl_803DC074;
extern f32 lbl_803E3958;
extern f32 lbl_803E395C;
extern f32 lbl_803E3960;
extern f32 lbl_803E3964;
extern f32 lbl_803E3968;
extern f32 lbl_803E396C;
extern f32 lbl_803E3970;
extern f32 lbl_803E3980;
extern f32 lbl_803E3984;
extern f32 lbl_803E3988;
extern f32 lbl_803E398C;
extern f32 lbl_803E3990;
extern f32 lbl_803E3994;
extern f32 lbl_803E3998;
extern f32 lbl_803E39A8;
extern f32 lbl_803E39AC;
extern f32 lbl_803E39B0;
extern f32 lbl_803E39B4;
extern f32 lbl_803E39B8;
extern f32 lbl_803E39BC;
extern f32 lbl_803E39C0;
extern f32 lbl_803E39C4;
extern f32 lbl_803E39C8;
extern f32 lbl_803E39CC;
extern f32 lbl_803E39D0;
extern f32 lbl_803E39D4;
extern f32 lbl_803E39D8;
extern f32 lbl_803E39DC;
extern f32 lbl_803E39E0;
extern f32 lbl_803E39E4;
extern f32 lbl_803E39E8;
extern f32 lbl_803E39EC;
extern f32 lbl_803E39F0;
extern f32 lbl_803E39F4;
extern f32 lbl_803E39F8;
extern f32 lbl_803E3A08;
extern f32 lbl_803E3A0C;
extern f32 lbl_803E3A10;
extern f32 lbl_803E3A14;
extern f32 lbl_803E3A18;
extern f32 lbl_803E3A1C;
extern f32 lbl_803E3A20;
extern f32 lbl_803E3A24;
extern f32 lbl_803E3A28;
extern f32 lbl_803E3A2C;
extern f32 lbl_803E3A38;
extern f32 lbl_803E3A3C;
extern f32 lbl_803E3A40;
extern f32 lbl_803E3A44;
extern f32 lbl_803E3A48;
extern void* PTR_DAT_80320998;

/*
 * --INFO--
 *
 * Function: FUN_8015ad60
 * EN v1.0 Address: 0x8015AD60
 * EN v1.0 Size: 940b
 * EN v1.1 Address: 0x8015ADD0
 * EN v1.1 Size: 728b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015ad60(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)
{
  int iVar1;
  uint uVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar3;
  undefined8 uVar4;
  double dVar5;
  
  puVar3 = (&PTR_DAT_80320998)[(uint)*(ushort *)(param_10 + 0x338) * 2];
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6f) = 1;
  if (param_9[0x50] == 0) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    ObjHits_DisableObject((int)param_9);
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    ObjHits_EnableObject((int)param_9);
  }
  if (((*(uint *)(param_10 + 0x2dc) & 0x80000000) != 0) && (*(byte *)(param_10 + 0x33a) < 2)) {
    if ((*(short *)(param_10 + 0x338) == 0) && (uVar2 = FUN_80017760(0,0x14), 9 < (int)uVar2)) {
      *(undefined *)(param_10 + 0x33a) = 7;
    }
    else {
      *(undefined *)(param_10 + 0x33a) = 1;
    }
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x40000000;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    *(char *)(param_10 + 0x33a) = *(char *)(param_10 + 0x33a) + '\x01';
    if ((byte)(&DAT_803dc994)[*(ushort *)(param_10 + 0x338)] < *(byte *)(param_10 + 0x33a)) {
      *(undefined *)(param_10 + 0x33a) = (&DAT_803dc990)[*(ushort *)(param_10 + 0x338)];
    }
    if (*(ushort *)(param_10 + 0x2a0) < 4) {
      iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      uVar4 = FUN_8014d4c8((double)*(float *)(puVar3 + iVar1),param_2,param_3,param_4,param_5,
                           param_6,param_7,param_8,(int)param_9,param_10,
                           (uint)(byte)puVar3[iVar1 + 8],0,0,in_r8,in_r9,in_r10);
    }
    else {
      iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      uVar4 = FUN_8014d4c8((double)*(float *)(puVar3 + iVar1),param_2,param_3,param_4,param_5,
                           param_6,param_7,param_8,(int)param_9,param_10,
                           (uint)(byte)puVar3[iVar1 + 9],0,0,in_r8,in_r9,in_r10);
    }
    if (param_9[0x50] == 9) {
      FUN_8015a320(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
    else if (param_9[0x50] == 1) {
      uVar2 = FUN_80017760(0,(uint)*(byte *)(param_10 + 0x33b));
      FUN_80017760(0xffff8000,0x7fff);
      dVar5 = (double)FUN_80293f90();
      *(float *)(param_9 + 6) =
           (float)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3948
                                  ) * dVar5 + (double)*(float *)(*(int *)(param_9 + 0x26) + 8));
      dVar5 = (double)FUN_80294964();
      *(float *)(param_9 + 10) =
           (float)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3948
                                  ) * dVar5 + (double)*(float *)(*(int *)(param_9 + 0x26) + 0x10));
      FUN_8014d3d0(param_9,param_10,1,0);
    }
  }
  FUN_8014d3d0(param_9,param_10,(uint)(byte)(&DAT_803dc998)[*(ushort *)(param_10 + 0x338)],0);
  FUN_8015a6c0((uint)param_9,param_10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b10c
 * EN v1.0 Address: 0x8015B10C
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x8015B0A8
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015b10c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  int iVar1;
  undefined *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  puVar2 = (&PTR_DAT_80320998)[(uint)*(ushort *)(param_10 + 0x338) * 2];
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    if (*(short *)(param_9 + 0xa0) == 7) {
      *(undefined *)(param_10 + 0x33a) = 1;
    }
    else if (*(short *)(param_9 + 0xa0) != 0) {
      *(undefined *)(param_10 + 0x33a) = 0;
    }
    iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
    FUN_8014d4c8((double)*(float *)(puVar2 + iVar1),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,param_10,(uint)(byte)puVar2[iVar1 + 8],0,0,in_r8,in_r9,in_r10);
  }
  FUN_8015a6c0(param_9,param_10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b218
 * EN v1.0 Address: 0x8015B218
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x8015B16C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015b218(int param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E3958;
  *(char *)(param_2 + 0x33b) = (char)(int)*(float *)(param_2 + 0x2a8);
  *(float *)(param_2 + 0x2a8) = lbl_803E395C;
  *(undefined4 *)(param_2 + 0x2e4) = 0x42003;
  *(float *)(param_2 + 0x308) = lbl_803E3960;
  *(float *)(param_2 + 0x300) = lbl_803E3964;
  *(float *)(param_2 + 0x304) = lbl_803E3968;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = lbl_803E396C;
  *(float *)(param_2 + 0x314) = lbl_803E396C;
  *(undefined *)(param_2 + 0x321) = 10;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 7;
  *(float *)(param_2 + 0x31c) = fVar1;
  *(undefined *)(param_2 + 0x33a) = 1;
  uVar2 = countLeadingZeros(0x84b - *(short *)(param_1 + 0x46));
  *(short *)(param_2 + 0x338) = (short)(uVar2 >> 5);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b2cc
 * EN v1.0 Address: 0x8015B2CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8015B208
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015b2cc(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b2d0
 * EN v1.0 Address: 0x8015B2D0
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x8015B20C
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015b2d0(short *param_1,int param_2)
{
  if (*(char *)(param_2 + 0x33b) == '\0') {
    ObjGroup_AddObject((int)param_1,0x50);
    *(undefined *)(param_2 + 0x33b) = 1;
  }
  ObjHits_SetHitVolumeSlot((int)param_1,10,1,0);
  *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 0;
  *param_1 = *param_1 + -0x100;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b34c
 * EN v1.0 Address: 0x8015B34C
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x8015B288
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015b34c(short *param_1,int param_2)
{
  if (*(char *)(param_2 + 0x33b) != '\0') {
    ObjGroup_RemoveObject((int)param_1,0x50);
    *(undefined *)(param_2 + 0x33b) = 0;
  }
  *param_1 = (short)(int)-(lbl_803E3970 * lbl_803DC074 -
                          (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                 DOUBLE_803e3978));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b3d4
 * EN v1.0 Address: 0x8015B3D4
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x8015B314
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015b3d4(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E3980;
  *(char *)(param_2 + 0x33b) = (char)(int)*(float *)(param_2 + 0x2a8);
  *(float *)(param_2 + 0x2a8) = lbl_803E3984;
  *(undefined4 *)(param_2 + 0x2e4) = 0x42001;
  *(float *)(param_2 + 0x308) = lbl_803E3988;
  *(float *)(param_2 + 0x300) = lbl_803E398C;
  *(float *)(param_2 + 0x304) = lbl_803E3990;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = lbl_803E3994;
  *(float *)(param_2 + 0x314) = lbl_803E3994;
  *(undefined *)(param_2 + 0x321) = 5;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 7;
  *(float *)(param_2 + 0x31c) = fVar1;
  *(undefined *)(param_2 + 0x33a) = 1;
  *(undefined *)(param_2 + 0x33b) = 0;
  iVar2 = FUN_80017a54(param_1);
  FUN_80017964(iVar2,FUN_8006fb00);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b47c
 * EN v1.0 Address: 0x8015B47C
 * EN v1.0 Size: 884b
 * EN v1.1 Address: 0x8015B3BC
 * EN v1.1 Size: 912b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015b47c(int param_1,int param_2)
{
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined8 local_18;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (*(char *)(param_2 + 0x346) == '\0') {
      if ((*(short *)(param_2 + 0x274) == 7) && ((int)*(float *)(param_2 + 0x2c0) < 0x37)) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
      }
    }
    else {
      uVar2 = (**(code **)(*DAT_803dd738 + 0x18))((double)lbl_803E3998);
      if ((uVar2 & 1) == 0) {
        return 5;
      }
      local_18 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x3fe));
      iVar4 = (**(code **)(*DAT_803dd738 + 0x44))
                        ((double)(float)(local_18 - DOUBLE_803e39a0),param_1,param_2,1);
      if (iVar4 != 0) {
        return 5;
      }
      if ((int)*(float *)(param_2 + 0x2c0) < 0x38) {
        if (*(short *)(param_2 + 0x274) == 6) {
          (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,5);
        }
        else {
          (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
        }
      }
      else if ((*(byte *)(iVar3 + 0x404) & 2) == 0) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,7);
      }
      else {
        iVar4 = *(int *)(iVar3 + 0x40c);
        if ((*(byte *)(iVar3 + 0x404) & 0x10) == 0) {
          sVar1 = *(short *)(iVar4 + 4);
          *(short *)(iVar4 + 4) = sVar1 + 1;
          (**(code **)(*DAT_803dd70c + 0x14))
                    (param_1,param_2,(int)*(short *)(&DAT_803209d0 + sVar1 * 2));
        }
        else {
          sVar1 = *(short *)(iVar4 + 4);
          *(short *)(iVar4 + 4) = sVar1 + 1;
          (**(code **)(*DAT_803dd70c + 0x14))
                    (param_1,param_2,(int)*(short *)(&DAT_803209e0 + sVar1 * 2));
        }
        if (6 < *(short *)(iVar4 + 4)) {
          *(undefined2 *)(iVar4 + 4) = 0;
        }
      }
    }
  }
  else if ((int)*(float *)(param_2 + 0x2c0) < 0x38) {
    if (*(short *)(param_2 + 0x274) == 6) {
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,5);
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
    }
  }
  else if ((*(byte *)(iVar3 + 0x404) & 2) == 0) {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,7);
  }
  else {
    iVar4 = *(int *)(iVar3 + 0x40c);
    if ((*(byte *)(iVar3 + 0x404) & 0x10) == 0) {
      sVar1 = *(short *)(iVar4 + 4);
      *(short *)(iVar4 + 4) = sVar1 + 1;
      (**(code **)(*DAT_803dd70c + 0x14))
                (param_1,param_2,(int)*(short *)(&DAT_803209d0 + sVar1 * 2));
    }
    else {
      sVar1 = *(short *)(iVar4 + 4);
      *(short *)(iVar4 + 4) = sVar1 + 1;
      (**(code **)(*DAT_803dd70c + 0x14))
                (param_1,param_2,(int)*(short *)(&DAT_803209e0 + sVar1 * 2));
    }
    if (6 < *(short *)(iVar4 + 4)) {
      *(undefined2 *)(iVar4 + 4) = 0;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b7f0
 * EN v1.0 Address: 0x8015B7F0
 * EN v1.0 Size: 748b
 * EN v1.1 Address: 0x8015B74C
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015b7f0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10)
{
  short sVar1;
  float fVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined8 uVar6;
  
  iVar5 = *(int *)(param_9 + 0xb8);
  if ((*(char *)(param_10 + 0x346) == '\0') ||
     (uVar3 = (**(code **)(*DAT_803dd738 + 0x18))((double)lbl_803E3998), (uVar3 & 1) != 0)) {
    if (*(char *)(param_10 + 0x27b) == '\0') {
      sVar1 = *(short *)(iVar5 + 0x402);
      if (sVar1 == 3) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,4);
      }
      else if (sVar1 == 4) {
        if ((*(float *)(param_10 + 0x2c0) < lbl_803E39A8) && (*(char *)(param_10 + 0x346) != '\0')
           ) {
          if (*(byte *)(iVar5 + 0x406) < 0x33) {
            (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,1);
          }
          else {
            (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,0);
          }
        }
      }
      else if (sVar1 == 1) {
        return 8;
      }
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,0xb);
    }
    fVar2 = lbl_803E39AC;
    *(float *)(param_10 + 0x290) = lbl_803E39AC;
    *(float *)(param_10 + 0x28c) = fVar2;
    FUN_80003494(iVar5 + 0x35c,param_9 + 0xc,0xc);
    uVar6 = FUN_80003494(iVar5 + 0x368,*(int *)(param_10 + 0x2d0) + 0xc,0xc);
    FUN_80006a54(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (*(char *)(iVar5 + 0x381) == '\0') {
      (**(code **)(*DAT_803dd70c + 0x1c))
                ((double)*(float *)(iVar5 + 0x374),(double)*(float *)(iVar5 + 0x37c),
                 (double)lbl_803E39AC,(double)lbl_803E39AC,(double)lbl_803E39B0,param_9,
                 param_10);
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x1c))
                ((double)*(float *)(iVar5 + 0x374),(double)*(float *)(iVar5 + 0x37c),
                 (double)lbl_803E39B4,(double)lbl_803E39B8,(double)lbl_803E39B0,param_9,
                 param_10);
    }
    if ((0x78 < *(short *)(param_10 + 0x32e)) &&
       (iVar5 = (**(code **)(*DAT_803dd738 + 0x44))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar5 + 0x3fe)) -
                                          DOUBLE_803e39a0),param_9,param_10,1), iVar5 != 0)) {
      return 5;
    }
    uVar4 = 0;
  }
  else {
    uVar4 = 5;
  }
  return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_8015badc
 * EN v1.0 Address: 0x8015BADC
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x8015B9D0
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015badc(undefined4 param_1,int param_2)
{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,3);
  }
  if (*(char *)(param_2 + 0x346) != '\0') {
    if (*(short *)(param_2 + 0x274) != 3) {
      return 8;
    }
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015bb80
 * EN v1.0 Address: 0x8015BB80
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8015BA78
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015bb80(undefined4 param_1,int param_2)
{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,2);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015bbc8
 * EN v1.0 Address: 0x8015BBC8
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x8015BAC0
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015bbc8(int param_1,int param_2)
{
  int iVar1;
  
  if (*(char *)(param_2 + 0x27b) != '\0') {
    iVar1 = *(int *)(param_1 + 0xb8);
    *(undefined *)(iVar1 + 0x405) = 0;
    FUN_80017698((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_80017698((int)*(short *)(iVar1 + 0x3f2),1);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015bc20
 * EN v1.0 Address: 0x8015BC20
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x8015BB1C
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015bc20(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10)
{
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar1;
  
  if (*(char *)(param_10 + 0x27b) == '\0') {
    if (*(char *)(param_10 + 0x346) != '\0') {
      uVar1 = ObjMsg_SendToObjects(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,3,
                           param_9,0xe0000,param_9,in_r8,in_r9,in_r10);
      if (*(int *)(param_9 + 0x4c) == 0) {
        FUN_80017ac8(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
        return 0;
      }
      return 4;
    }
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,0xd);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    ObjHits_DisableObject(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015bd9c
 * EN v1.0 Address: 0x8015BD9C
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x8015BBF4
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015bd9c(int param_1,int param_2)
{
  undefined4 uVar1;
  
  if (*(char *)(param_2 + 0x354) < '\x01') {
    uVar1 = 3;
  }
  else {
    if (*(char *)(param_2 + 0x346) != '\0') {
      if (*(short *)(param_2 + 0x274) != 0xc) {
        return 8;
      }
      if (*(byte *)(*(int *)(param_1 + 0xb8) + 0x406) < 0x33) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
      }
      else {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
      }
    }
    uVar1 = 0;
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_8015be40
 * EN v1.0 Address: 0x8015BE40
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x8015BC98
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015be40(int param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  fVar1 = lbl_803E39AC;
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(int *)(param_2 + 0x2d0) != 0) {
    if (*(char *)(param_2 + 0x27b) != '\0') {
      *(float *)(param_2 + 0x284) = lbl_803E39AC;
      *(float *)(param_2 + 0x280) = fVar1;
      if (*(byte *)(iVar3 + 0x406) < 0x33) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
      }
      else if ((*(float *)(param_2 + 0x2c0) <
                lbl_803E39BC *
                (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x3fe)) -
                       DOUBLE_803e39a0)) || ((*(byte *)(iVar3 + 0x404) & 2) != 0)) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
      }
      else {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
      }
    }
    if (*(char *)(param_2 + 0x346) != '\0') {
      (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_1,param_2,4);
      uVar2 = (**(code **)(*DAT_803dd738 + 0x18))((double)lbl_803E3998,param_1,param_2);
      if ((uVar2 & 1) == 0) {
        return 5;
      }
      if ((lbl_803E39BC *
           (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x3fe)) - DOUBLE_803e39a0)
           <= *(float *)(param_2 + 0x2c0)) && ((*(byte *)(iVar3 + 0x404) & 2) == 0)) {
        return 7;
      }
      return 8;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c00c
 * EN v1.0 Address: 0x8015C00C
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8015BE64
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c00c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = lbl_803E39C0;
  fVar1 = lbl_803E39AC;
  dVar4 = (double)lbl_803E39AC;
  *(float *)(param_10 + 0x280) = lbl_803E39AC;
  *(float *)(param_10 + 0x284) = fVar1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,0,param_12,
                 param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if ((*(byte *)(param_10 + 0x356) & 1) == 0) {
    iVar2 = FUN_80017a98();
    if (*(short *)(iVar2 + 0x46) == 0) {
      FUN_80006824(param_9,0x239);
    }
    else {
      FUN_80006824(param_9,0x1f2);
    }
    FUN_80006824(param_9,0x232);
    FUN_80006824(param_9,0x26f);
    *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 1;
  }
  if (((*(byte *)(param_10 + 0x356) & 2) == 0) && (lbl_803E39C4 < *(float *)(param_9 + 0x98))) {
    FUN_80006824(param_9,0x233);
    *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 2;
    (**(code **)(*DAT_803dd738 + 0x4c))(param_9,(int)*(short *)(iVar3 + 0x3f0),0xffffffff,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c1b4
 * EN v1.0 Address: 0x8015C1B4
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x8015BFAC
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c1b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  if (*(byte *)(iVar2 + 0x406) < 0x33) {
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xe,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
  }
  else if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,4,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = lbl_803E39C0;
  *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) | 0xc;
  fVar1 = lbl_803E39AC;
  *(float *)(param_10 + 0x280) = lbl_803E39AC;
  *(float *)(param_10 + 0x284) = fVar1;
  if ((*(byte *)(iVar2 + 0x404) & 2) == 0) {
    *(float *)(param_10 + 0x280) = lbl_803E39C8 + *(float *)(param_9 + 0x98);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c3b4
 * EN v1.0 Address: 0x8015C3B4
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x8015C0C4
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c3b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) == '\0') {
    if (*(char *)(param_10 + 0x346) != '\0') {
      *(undefined2 *)(iVar1 + 0x402) = 3;
    }
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,2,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined2 *)(iVar1 + 0x402) = 2;
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) = lbl_803E39CC;
  }
  iVar1 = *(int *)(iVar1 + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0x10;
  }
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0xc;
  *(undefined4 *)(param_10 + 0x280) = *(undefined4 *)(param_9 + 0x98);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c514
 * EN v1.0 Address: 0x8015C514
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x8015C1D8
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c514(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80017a98();
    iVar1 = FUN_80017a98();
    if (*(short *)(iVar1 + 0x46) == 0) {
      FUN_80006824(param_9,0x239);
    }
    else {
      FUN_80006824(param_9,0x1f2);
    }
    FUN_80006824(param_9,0x26e);
  }
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = lbl_803E39CC;
  *(float *)(param_10 + 0x280) = lbl_803E39AC;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c654
 * EN v1.0 Address: 0x8015C654
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x8015C2B4
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c654(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  *(float *)(param_10 + 0x2a0) = lbl_803E39D0;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,10,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    iVar1 = *(int *)(iVar2 + 0x40c);
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffffe;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 2;
    FUN_80006824(param_9,0xcf);
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c7a0
 * EN v1.0 Address: 0x8015C7A0
 * EN v1.0 Size: 284b
 * EN v1.1 Address: 0x8015C3A0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c7a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  *(float *)(param_10 + 0x2a0) = lbl_803E39D0;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,5,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c8bc
 * EN v1.0 Address: 0x8015C8BC
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x8015C44C
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c8bc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(byte *)(iVar3 + 0x44) = *(byte *)(iVar3 + 0x44) | 0xc;
  bVar1 = *(char *)(param_10 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xf,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(param_10 + 0x34d) = 1;
  }
  *(float *)(param_10 + 0x2a0) = *(float *)(param_10 + 0x2c0) / lbl_803E39D4;
  if (*(float *)(param_10 + 0x2a0) <= lbl_803E39D8) {
    if (*(float *)(param_10 + 0x2a0) < lbl_803E39D0) {
      *(float *)(param_10 + 0x2a0) = lbl_803E39D0;
    }
  }
  else {
    *(float *)(param_10 + 0x2a0) = lbl_803E39D8;
  }
  fVar2 = *(float *)(param_9 + 0x98);
  if (lbl_803E39BC <= fVar2) {
    *(float *)(param_10 + 0x280) = lbl_803E39DC * (lbl_803E39E0 - fVar2);
  }
  else {
    *(float *)(param_10 + 0x280) = lbl_803E39DC * fVar2;
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015ca54
 * EN v1.0 Address: 0x8015CA54
 * EN v1.0 Size: 728b
 * EN v1.1 Address: 0x8015C560
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015ca54(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) | 4;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    uVar1 = FUN_80017760(0,2);
    DAT_803de6f9 = (undefined)uVar1;
    uVar1 = FUN_80017760(0,1);
    if (uVar1 == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,3,0,param_12,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,7,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         lbl_803E39E4 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         lbl_803E39E8;
  }
  if ((*(byte *)(iVar2 + 0x406) < 0x33) || ((*(byte *)(iVar2 + 0x404) & 2) != 0)) {
    *(float *)(param_10 + 0x280) = lbl_803E39AC;
  }
  else if ((*(float *)(param_10 + 0x2c0) <= lbl_803E39EC) || (*(char *)(param_10 + 0x346) != '\0')
          ) {
    *(float *)(param_10 + 0x280) = lbl_803E39AC;
  }
  else {
    *(float *)(param_10 + 0x280) = *(float *)(param_10 + 0x2c0) / lbl_803E39EC - lbl_803E39E0;
    *(float *)(param_10 + 0x280) =
         *(float *)(param_10 + 0x280) *
         ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         lbl_803E39F0);
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015cd2c
 * EN v1.0 Address: 0x8015CD2C
 * EN v1.0 Size: 736b
 * EN v1.1 Address: 0x8015C758
 * EN v1.1 Size: 512b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015cd2c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) | 4;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    uVar1 = FUN_80017760(0,1);
    if (uVar1 == 0) {
      DAT_803de6f8 = 3;
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,10,0,param_12,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else {
      uVar1 = FUN_80017760(0,2);
      DAT_803de6f8 = (undefined)uVar1;
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,6,0,param_12,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         lbl_803E39E4 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         lbl_803E39E8;
  }
  if ((*(byte *)(iVar2 + 0x406) < 0x33) || ((*(byte *)(iVar2 + 0x404) & 2) != 0)) {
    *(float *)(param_10 + 0x280) = lbl_803E39AC;
  }
  else if ((*(float *)(param_10 + 0x2c0) <= lbl_803E39EC) || (*(char *)(param_10 + 0x346) != '\0')
          ) {
    *(float *)(param_10 + 0x280) = lbl_803E39AC;
  }
  else {
    *(float *)(param_10 + 0x280) = *(float *)(param_10 + 0x2c0) / lbl_803E39EC - lbl_803E39E0;
    *(float *)(param_10 + 0x280) =
         *(float *)(param_10 + 0x280) *
         ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         lbl_803E39F0);
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015d00c
 * EN v1.0 Address: 0x8015D00C
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x8015C958
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015d00c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0x5c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,9,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  iVar1 = *(int *)(iVar2 + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0xc;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    *(undefined2 *)(iVar2 + 0x402) = 4;
  }
  *param_9 = (short)(int)(lbl_803E39F4 *
                          (((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_10 + 0x336) ^ 0x80000000)
                                   - DOUBLE_803e3a00) * lbl_803DC074) / lbl_803E39F8) +
                         (float)((double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000) -
                                DOUBLE_803e3a00));
  *(float *)(param_10 + 0x2a0) = lbl_803E39D0;
  *(float *)(param_10 + 0x280) = lbl_803E39E0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015d19c
 * EN v1.0 Address: 0x8015D19C
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x8015CA70
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015d19c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,4,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = lbl_803E39C0;
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0x10;
  }
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0xc;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015d324
 * EN v1.0 Address: 0x8015D324
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x8015CB60
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015d324(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if ((*(short *)(param_10 + 0x276) != 4) && (*(char *)(param_10 + 0x27a) != '\0')) {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xe,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(byte *)(*(int *)(iVar1 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar1 + 0x40c) + 0x44) | 0xc;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
    *(float *)(param_10 + 0x2a0) = lbl_803E39D0;
    *(float *)(param_10 + 0x280) = lbl_803E39AC;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    FUN_80017698((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,8,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    *(undefined2 *)(iVar1 + 0x402) = 0;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015d518
 * EN v1.0 Address: 0x8015D518
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x8015CC74
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015d518(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) | 1;
  *(undefined *)(param_10 + 0x25f) = 1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xb,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80017698((int)*(short *)(iVar2 + 0x3f4),1);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    *(undefined *)(param_9 + 0x36) = 0xff;
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         lbl_803E3A08 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         lbl_803E3A0C;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined2 *)(iVar2 + 0x402) = 1;
  }
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0x20;
  }
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  if (*(float *)(param_9 + 0x98) < lbl_803E3A10) {
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 8;
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015d6ec
 * EN v1.0 Address: 0x8015D6EC
 * EN v1.0 Size: 560b
 * EN v1.1 Address: 0x8015CE08
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015d6ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) | 1;
  *(undefined *)(param_10 + 0x25f) = 1;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 9;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,8,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80017698((int)*(short *)(iVar2 + 0x3f4),1);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    *(undefined *)(param_9 + 0x36) = 0xff;
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         lbl_803E3A14 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         lbl_803E3A18;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined2 *)(iVar2 + 0x402) = 1;
  }
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0x20;
  }
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  if (*(float *)(param_9 + 0x98) < lbl_803E3A10) {
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 8;
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015d91c
 * EN v1.0 Address: 0x8015D91C
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x8015CFB8
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015d91c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,int param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_80017aa4(0x24,100);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_10 + 0x14);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_10 + 0x18);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_10 + 0x1c);
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 1;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    puVar2[0xf] = 0xffff;
    puVar2[0x10] = 0xffff;
    iVar3 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                         0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar3 != 0) {
      *(undefined4 *)(iVar3 + 0x24) = *(undefined4 *)(param_10 + 0x38);
      *(undefined4 *)(iVar3 + 0x28) = *(undefined4 *)(param_10 + 0x3c);
      *(undefined4 *)(iVar3 + 0x2c) = *(undefined4 *)(param_10 + 0x40);
      *(undefined4 *)(iVar3 + 0xc4) = param_9;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015da7c
 * EN v1.0 Address: 0x8015DA7C
 * EN v1.0 Size: 964b
 * EN v1.1 Address: 0x8015D07C
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015da7c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined *puVar6;
  int iVar7;
  undefined8 extraout_f1;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  fVar1 = lbl_803E39E0;
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  iVar7 = *(int *)(iVar5 + 0x40c);
  if (*(short *)(iVar2 + 0x46) == 99) {
    *(float *)(iVar7 + 0x28) = lbl_803E3A1C;
    fVar1 = lbl_803E3A20;
  }
  else {
    *(float *)(iVar7 + 0x28) = lbl_803E39E0;
  }
  dVar8 = (double)fVar1;
  uVar3 = 0;
  if ((*(char *)(iVar5 + 0x25f) != '\0') &&
     (uVar3 = (uint)(byte)(&DAT_80320a98)[*(char *)(iVar5 + 0xbc)], 0x1e < uVar3)) {
    uVar3 = 0;
  }
  puVar6 = &DAT_80320a88 + uVar3 * 3;
  if ((*(byte *)(iVar7 + 0x44) & 1) != 0) {
    FUN_8015d91c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,iVar7);
    *(byte *)(iVar7 + 0x44) = *(byte *)(iVar7 + 0x44) & 0xfe;
  }
  if (((*(byte *)(iVar7 + 0x44) & 4) != 0) && ((*(byte *)(iVar5 + 0x404) & 0x40) == 0)) {
    iVar4 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar2,0x56,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
      iVar4 = iVar4 + 1;
    } while (iVar4 < 4);
  }
  if (((*(byte *)(iVar7 + 0x44) & 8) != 0) && ((*(byte *)(iVar5 + 0x404) & 0x40) == 0)) {
    (**(code **)(*DAT_803dd708 + 8))(iVar2,0x57,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
  }
  if ((*(byte *)(iVar7 + 0x44) & 0x10) != 0) {
    FUN_800069bc();
    FUN_80006920((double)(float)((double)lbl_803E3A20 * dVar8));
    iVar5 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar2,0x57,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x28);
  }
  if ((*(byte *)(iVar7 + 0x44) & 0x20) != 0) {
    FUN_800069bc();
    FUN_80006920((double)(float)((double)lbl_803E3A24 * dVar8));
    iVar5 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar2,0x57,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x28);
    iVar5 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar2,0x58,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 10);
  }
  *(undefined *)(iVar7 + 0x44) = 0;
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015de40
 * EN v1.0 Address: 0x8015DE40
 * EN v1.0 Size: 504b
 * EN v1.1 Address: 0x8015D314
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015de40(short *param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  float local_98;
  float local_94;
  float local_90;
  undefined auStack_8c [12];
  float local_80;
  float local_7c;
  float local_78;
  float afStack_74 [12];
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  iVar3 = *(int *)(param_2 + 0x40c);
  uVar2 = ObjPath_GetPointModelMtx((int)param_1,1);
  FUN_80003494((uint)afStack_74,uVar2,0x40);
  local_3c = lbl_803E39AC;
  local_40 = lbl_803E39AC;
  local_44 = lbl_803E39AC;
  fVar1 = lbl_803E39C4;
  if (param_1[0x23] == 99) {
    fVar1 = lbl_803E39E0;
  }
  dVar4 = (double)*(float *)(param_2 + 0x280);
  if (dVar4 < (double)fVar1) {
    dVar4 = (double)fVar1;
  }
  if (*(short *)(param_2 + 0x274) == 4) {
    ObjPath_GetPointWorldPosition(param_1,0,(float *)(iVar3 + 0x2c),(undefined4 *)(iVar3 + 0x30),
                 (float *)(iVar3 + 0x34),0);
  }
  else {
    ObjPath_GetPointWorldPosition(param_1,2,(float *)(iVar3 + 0x2c),(undefined4 *)(iVar3 + 0x30),
                 (float *)(iVar3 + 0x34),0);
  }
  *(float *)(iVar3 + 0x30) = lbl_803E3A28 + *(float *)(param_1 + 8);
  uStack_2c = (int)*param_1 ^ 0x80000000;
  local_30 = 0x43300000;
  dVar5 = (double)FUN_80293f90();
  *(float *)(iVar3 + 0x2c) =
       -(float)(dVar4 * (double)(float)((double)lbl_803E3A2C * dVar5) -
               (double)*(float *)(iVar3 + 0x2c));
  uStack_24 = (int)*param_1 ^ 0x80000000;
  local_28 = 0x43300000;
  dVar5 = (double)FUN_80294964();
  *(float *)(iVar3 + 0x34) =
       -(float)(dVar4 * (double)(float)((double)lbl_803E3A2C * dVar5) -
               (double)*(float *)(iVar3 + 0x34));
  local_80 = lbl_803E39AC;
  local_7c = lbl_803E3A38;
  local_78 = lbl_803E3A3C;
  ObjPath_GetPointWorldPosition(param_1,0,&local_80,&local_7c,&local_78,1);
  if ((*(byte *)(iVar3 + 0x44) & 2) != 0) {
    local_98 = lbl_803E3A40;
    local_94 = lbl_803E3A44;
    local_90 = lbl_803E3A3C;
    FUN_80017778((double)lbl_803E3A40,(double)lbl_803E3A44,(double)lbl_803E3A3C,afStack_74,
                 &local_98,&local_94,&local_90);
    FUN_80003494(iVar3 + 0x38,(uint)&local_98,0xc);
    FUN_80003494(iVar3 + 8,(uint)auStack_8c,0x18);
    *(byte *)(iVar3 + 0x44) = *(byte *)(iVar3 + 0x44) | 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e038
 * EN v1.0 Address: 0x8015E038
 * EN v1.0 Size: 484b
 * EN v1.1 Address: 0x8015D544
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015e038(int param_1,int param_2,int param_3)
{
  int iVar1;
  uint uVar2;
  
  ObjHits_DisableObject(param_1);
  if ((*(byte *)(param_2 + 0x404) & 4) == 0) {
    if ((*(byte *)(param_2 + 0x404) & 8) == 0) {
      iVar1 = (**(code **)(*DAT_803dd738 + 0x48))
                        ((double)(float)((double)CONCAT44(0x43300000,
                                                          (uint)*(ushort *)(param_2 + 0x3fe)) -
                                        DOUBLE_803e39a0),param_1,param_3,0x8000);
    }
    else {
      iVar1 = (**(code **)(*DAT_803dd738 + 0x48))
                        ((double)(lbl_803E39BC *
                                 (float)((double)CONCAT44(0x43300000,
                                                          (uint)*(ushort *)(param_2 + 0x3fe)) -
                                        DOUBLE_803e39a0)),param_1,param_3,0x8000);
    }
  }
  else {
    iVar1 = (**(code **)(*DAT_803dd738 + 0x48))((double)lbl_803E39EC,param_1,param_3,0x8000);
  }
  if (iVar1 != 0) {
    (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_1,param_3,4);
    uVar2 = (**(code **)(*DAT_803dd738 + 0x18))((double)lbl_803E3998,param_1,param_3);
    if ((uVar2 & 1) == 0) {
      iVar1 = 0;
    }
  }
  if (iVar1 != 0) {
    (**(code **)(*DAT_803dd738 + 0x28))
              (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),0,0,0,8,0xffffffff);
    *(int *)(param_3 + 0x2d0) = iVar1;
    *(undefined *)(param_3 + 0x349) = 0;
    *(undefined2 *)(param_2 + 0x402) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e21c
 * EN v1.0 Address: 0x8015E21C
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x8015D728
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015e21c(uint param_1,int param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_2 + 0x40c);
  *(ushort *)(iVar2 + 0x46) = *(short *)(iVar2 + 0x46) + (ushort)DAT_803dc070;
  if (299 < *(ushort *)(iVar2 + 0x46)) {
    uVar1 = FUN_80017760(0,200);
    *(short *)(iVar2 + 0x46) = (short)uVar1;
    if ((*(short *)(param_3 + 0x274) == 7) || (*(short *)(param_3 + 0x274) == 8)) {
      FUN_80006824(param_1,0x26c);
    }
  }
  if ((*(byte *)(param_2 + 0x404) & 2) == 0) {
    (**(code **)(*DAT_803dd738 + 0x2c))((double)lbl_803E3A48,param_1,param_3,0xffffffff);
  }
  else {
    (**(code **)(*DAT_803dd738 + 0x2c))((double)lbl_803E39AC,param_1,param_3,0xffffffff);
  }
  *(undefined4 *)(param_2 + 0x3e0) = *(undefined4 *)(param_1 + 0xc0);
  *(undefined4 *)(param_1 + 0xc0) = 0;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)lbl_803DC074,(double)lbl_803DC074,param_1,param_3,&DAT_803ad1a8,
             &DAT_803ad188);
  *(undefined4 *)(param_1 + 0xc0) = *(undefined4 *)(param_2 + 0x3e0);
  return;
}

/* 8b "li r3, N; blr" returners. */
int fn_8015D628(void) { return 0x458; }
int fn_8015D630(void) { return 0x49; }

/* Pattern wrappers. */
s16 fn_8015D61C(int *obj) { return *(s16*)((char*)((int**)obj)[0xb8/4] + 0x274); }
