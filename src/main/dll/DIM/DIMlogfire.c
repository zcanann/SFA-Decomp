#include "ghidra_import.h"
#include "main/dll/DIM/DIMlogfire.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern undefined4 FUN_80017a7c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern undefined4 FUN_80017b00();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 FUN_8003b56c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810f4();
extern undefined4 ccqueen_render();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803ad590;
extern undefined4 DAT_803ad598;
extern undefined4 DAT_803ad59c;
extern undefined4 DAT_803ad5a0;
extern undefined4 DAT_803ad5a4;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f4;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e5250;
extern f64 DOUBLE_803e5268;
extern f64 DOUBLE_803e5280;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5248;
extern f32 FLOAT_803e524c;
extern f32 FLOAT_803e5260;
extern f32 FLOAT_803e5270;
extern f32 FLOAT_803e5274;
extern f32 FLOAT_803e5288;
extern f32 FLOAT_803e528c;
extern f32 FLOAT_803e5290;
extern f32 FLOAT_803e5294;
extern f32 FLOAT_803e5298;
extern f32 FLOAT_803e529c;
extern f32 FLOAT_803e52a0;
extern f32 FLOAT_803e52a8;
extern f32 FLOAT_803e52ac;

/*
 * --INFO--
 *
 * Function: FUN_801a8f88
 * EN v1.0 Address: 0x801A8F88
 * EN v1.0 Size: 836b
 * EN v1.1 Address: 0x801A9044
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8f88(void)
{
  int iVar1;
  uint uVar2;
  short *psVar3;
  
  iVar1 = FUN_80286840();
  psVar3 = *(short **)(iVar1 + 0xb8);
  if (((int)*psVar3 == 0xffffffff) || (uVar2 = FUN_80017690((int)*psVar3), uVar2 != 0)) {
    *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) - FLOAT_803dc074;
    if (*(float *)(psVar3 + 0x14) < FLOAT_803e5248) {
      *(float *)(psVar3 + 0xc) = FLOAT_803e524c;
      uVar2 = FUN_80017760(-(uint)(ushort)psVar3[1],(uint)(ushort)psVar3[1]);
      *(float *)(psVar3 + 0xe) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
      uVar2 = FUN_80017760(-(uint)(ushort)psVar3[3],(uint)(ushort)psVar3[3]);
      *(float *)(psVar3 + 0x10) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
      uVar2 = FUN_80017760(-(uint)(ushort)psVar3[2],(uint)(ushort)psVar3[2]);
      *(float *)(psVar3 + 0x12) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
      FUN_80017748((ushort *)(psVar3 + 4),(float *)(psVar3 + 0xe));
      *(float *)(psVar3 + 0xe) = *(float *)(psVar3 + 0xe) + *(float *)(iVar1 + 0xc);
      *(float *)(psVar3 + 0x10) = *(float *)(psVar3 + 0x10) + *(float *)(iVar1 + 0x10);
      *(float *)(psVar3 + 0x12) = *(float *)(psVar3 + 0x12) + *(float *)(iVar1 + 0x14);
      uVar2 = FUN_80017760(100,200);
      *(float *)(psVar3 + 0x14) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
      uVar2 = FUN_80017760(0x32,100);
      *(float *)(psVar3 + 0x16) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
    }
    *(float *)(psVar3 + 0x16) = *(float *)(psVar3 + 0x16) - FLOAT_803dc074;
    if (FLOAT_803e5248 < *(float *)(psVar3 + 0x16)) {
      (**(code **)(*DAT_803dd708 + 8))(iVar1,0x71f,psVar3 + 8,0x200001,0xffffffff,0);
    }
    DAT_803ad598 = FLOAT_803e524c;
    uVar2 = FUN_80017760(-(uint)(ushort)psVar3[1],(uint)(ushort)psVar3[1]);
    DAT_803ad59c = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
    uVar2 = FUN_80017760(-(uint)(ushort)psVar3[3],(uint)(ushort)psVar3[3]);
    DAT_803ad5a0 = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
    uVar2 = FUN_80017760(-(uint)(ushort)psVar3[2],(uint)(ushort)psVar3[2]);
    DAT_803ad5a4 = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5250);
    FUN_80017748((ushort *)(psVar3 + 4),&DAT_803ad59c);
    DAT_803ad59c = DAT_803ad59c + *(float *)(iVar1 + 0xc);
    DAT_803ad5a0 = DAT_803ad5a0 + *(float *)(iVar1 + 0x10);
    DAT_803ad5a4 = DAT_803ad5a4 + *(float *)(iVar1 + 0x14);
    (**(code **)(*DAT_803dd708 + 8))(iVar1,0x720,&DAT_803ad590,0x200001,0xffffffff,0);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a92cc
 * EN v1.0 Address: 0x801A92CC
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x801A93F4
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a92cc(uint param_1)
{
  uint uVar1;
  
  uVar1 = FUN_80017690((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e));
  if (uVar1 == 0) {
    *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803dc070;
    if (*(int *)(param_1 + 0xf4) < 0) {
      uVar1 = FUN_80017760(0x46,0xf0);
      *(uint *)(param_1 + 0xf4) = uVar1;
      uVar1 = FUN_80017760(0x1e,0x3c);
      *(uint *)(param_1 + 0xf8) = uVar1;
    }
    if (*(int *)(param_1 + 0xf8) != 0) {
      *(uint *)(param_1 + 0xf8) = *(int *)(param_1 + 0xf8) - (uint)DAT_803dc070;
      if (*(int *)(param_1 + 0xf8) < 1) {
        *(undefined4 *)(param_1 + 0xf8) = 0;
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x724,0,2,0xffffffff,0);
        FUN_800068c4(param_1,0x450);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a93b0
 * EN v1.0 Address: 0x801A93B0
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801A94D4
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a93b0(int param_1)
{
  uint uVar1;
  
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  uVar1 = FUN_80017760(10,200);
  *(uint *)(param_1 + 0xf4) = uVar1;
  *(undefined *)(param_1 + 0x36) = 0;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a9408
 * EN v1.0 Address: 0x801A9408
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x801A953C
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801a9408(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10)
{
  byte bVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_10 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_10 + iVar3 + 0x81);
    if (bVar1 == 2) {
      iVar4 = *(int *)(param_9 + 200);
      if (iVar4 != 0) {
        uVar5 = ObjLink_DetachChild(param_9,iVar4);
        param_1 = FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
      }
      *(undefined4 *)(param_9 + 0xf8) = 0xffffffff;
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      *(undefined4 *)(param_9 + 0xf8) = 0x30b;
      iVar4 = *(int *)(param_9 + 200);
      if (iVar4 != 0) {
        uVar5 = ObjLink_DetachChild(param_9,iVar4);
        param_1 = FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
      }
      puVar2 = FUN_80017aa4(0x20,(short)*(undefined4 *)(param_9 + 0xf8));
      iVar4 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,4,
                           *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),
                           in_r8,in_r9,in_r10);
      param_1 = ObjLink_AttachChild(param_9,iVar4,0);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801a9614
 * EN v1.0 Address: 0x801A9614
 * EN v1.0 Size: 284b
 * EN v1.1 Address: 0x801A9654
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a9614(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  
  uVar2 = *(undefined4 *)(param_9 + 0xb8);
  iVar1 = *(int *)(param_9 + 200);
  if (iVar1 != 0) {
    uVar3 = ObjLink_DetachChild(param_9,iVar1);
    FUN_80017ac8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
  }
  (**(code **)(*DAT_803dd6d4 + 0x24))(uVar2);
  (**(code **)(*DAT_803dd6f4 + 8))(param_9,0xffff,0,0,0);
  FUN_8000680c(param_9,0x7f);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a9730
 * EN v1.0 Address: 0x801A9730
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A96FC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a9730(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a9758
 * EN v1.0 Address: 0x801A9758
 * EN v1.0 Size: 860b
 * EN v1.1 Address: 0x801A9730
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a9758(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 extraout_f1;
  int local_28;
  int local_24 [6];
  
  iVar4 = *(int *)(param_9 + 0xb8);
  if ((*(int *)(param_9 + 0x4c) != 0) && (*(short *)(*(int *)(param_9 + 0x4c) + 0x18) != -1)) {
    local_24[2] = (int)DAT_803dc070;
    local_24[1] = 0x43300000;
    local_24[0] = (**(code **)(*DAT_803dd6d4 + 0x14))
                            ((double)(float)((double)CONCAT44(0x43300000,local_24[2]) -
                                            DOUBLE_803e5268));
    FUN_801a9408(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar4);
    if ((local_24[0] != 0) && (*(short *)(param_9 + 0xb4) == -2)) {
      iVar5 = (int)*(char *)(iVar4 + 0x57);
      iVar4 = 0;
      piVar1 = (int *)FUN_80017b00(local_24,&local_28);
      iVar3 = 0;
      for (local_24[0] = 0; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
        iVar2 = *piVar1;
        if (*(short *)(iVar2 + 0xb4) == iVar5) {
          iVar4 = iVar2;
        }
        if (((*(short *)(iVar2 + 0xb4) == -2) && (*(short *)(iVar2 + 0x44) == 0x10)) &&
           (iVar5 == *(char *)(*(int *)(iVar2 + 0xb8) + 0x57))) {
          iVar3 = iVar3 + 1;
        }
        piVar1 = piVar1 + 1;
      }
      if (((iVar3 < 2) && (iVar4 != 0)) && (*(short *)(iVar4 + 0xb4) != -1)) {
        *(undefined2 *)(iVar4 + 0xb4) = 0xffff;
        (**(code **)(*DAT_803dd6d4 + 0x4c))(iVar5);
      }
      *(undefined2 *)(param_9 + 0xb4) = 0xffff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a9ab4
 * EN v1.0 Address: 0x801A9AB4
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x801A98AC
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a9ab4(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  
  *(undefined4 *)(param_1 + 0xbc) = 0;
  FUN_80017a7c(param_1,'d');
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(iVar2 + 0x6a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x6e) = 0xffff;
  *(float *)(iVar2 + 0x24) =
       FLOAT_803e5260 /
       (FLOAT_803e5260 +
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - DOUBLE_803e5268));
  *(undefined4 *)(iVar2 + 0x28) = 0xffffffff;
  *(undefined4 *)(iVar2 + 0x98) = 0;
  *(undefined4 *)(iVar2 + 0x94) = 0;
  *(undefined4 *)(param_1 + 0xf8) = 0xffffffff;
  iVar1 = *(int *)(param_1 + 0xf4);
  if ((iVar1 == 0) && (*(short *)(param_2 + 0x18) != 1)) {
    (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar2,param_2);
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  else if ((iVar1 != 0) && ((int)*(short *)(param_2 + 0x18) != iVar1 + -1)) {
    (**(code **)(*DAT_803dd6d4 + 0x24))(iVar2);
    if (*(short *)(param_2 + 0x18) != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x1c))(iVar2,param_2);
    }
    *(int *)(param_1 + 0xf4) = *(short *)(param_2 + 0x18) + 1;
  }
  if (*(int *)(param_1 + 100) != 0) {
    *(undefined *)(*(int *)(param_1 + 100) + 0x3a) = 100;
    *(undefined *)(*(int *)(param_1 + 100) + 0x3b) = 0x96;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a9c3c
 * EN v1.0 Address: 0x801A9C3C
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x801A9A50
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801a9c3c(int param_1,int param_2)
{
  uint uVar1;
  undefined4 uVar2;
  char *pcVar3;
  undefined *puVar4;
  int iVar5;
  
  pcVar3 = *(char **)(param_1 + 0xb8);
  uVar2 = 0;
  if (param_2 == 0) {
    if ((pcVar3[1] & 2U) != 0) {
      *pcVar3 = '\x03';
      pcVar3[0xc] = '\0';
      pcVar3[0xd] = '\0';
    }
    uVar2 = 1;
  }
  else if ((param_2 == 1) && (*pcVar3 == '\x03')) {
    uVar2 = 1;
    uVar1 = FUN_80017690((int)*(short *)(pcVar3 + 8));
    if ((uVar1 != 0) && (uVar1 = FUN_80017690((int)*(short *)(pcVar3 + 10)), uVar1 == 0)) {
      puVar4 = *(undefined **)(param_1 + 0xb8);
      iVar5 = *(int *)(param_1 + 0x4c);
      uVar1 = FUN_80017690((int)*(short *)(puVar4 + 8));
      if (uVar1 != 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        FUN_80017698((int)*(short *)(puVar4 + 10),1);
        *puVar4 = 4;
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
      }
    }
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801a9d30
 * EN v1.0 Address: 0x801A9D30
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801A9B58
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a9d30(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x2e);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a9d54
 * EN v1.0 Address: 0x801A9D54
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x801A9B7C
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a9d54(void)
{
  int iVar1;
  char *pcVar2;
  char in_r8;
  double dVar3;
  
  iVar1 = FUN_80286840();
  pcVar2 = *(char **)(iVar1 + 0xb8);
  if (in_r8 != '\0') {
    if (*pcVar2 == '\x02') {
      if ((pcVar2[1] & 2U) != 0) {
        *(short *)(pcVar2 + 0xc) = *(short *)(pcVar2 + 0xc) + 0x1000;
        dVar3 = (double)FUN_80293f90();
        FUN_8003b56c((short)(int)(FLOAT_803e5270 * (float)((double)FLOAT_803e5274 + dVar3)) + 0x7fU
                     & 0xff,0xff,0xff);
      }
    }
    else if (*pcVar2 == '\x03') {
      if (*(short *)(pcVar2 + 0xc) < 32000) {
        *(short *)(pcVar2 + 0xc) = *(short *)(pcVar2 + 0xc) + 0xff;
      }
      FUN_8003b56c(*(short *)(pcVar2 + 0xc) >> 7,0xff,0xff);
    }
    else {
      FUN_8003b56c(0xff,0xff,0xff);
    }
    FUN_8003b818(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a9e5c
 * EN v1.0 Address: 0x801A9E5C
 * EN v1.0 Size: 1308b
 * EN v1.1 Address: 0x801A9CC4
 * EN v1.1 Size: 1388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a9e5c(uint param_1)
{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined *puVar5;
  byte *pbVar6;
  double dVar7;
  
  pbVar6 = *(byte **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((pbVar6[1] & 1) != 0) {
    *pbVar6 = 2;
    FUN_80017698((int)*(short *)(pbVar6 + 8),1);
    pbVar6[1] = pbVar6[1] & 0xfe;
    *(undefined *)(param_1 + 0x36) = 0xff;
  }
  if (((*(byte *)(param_1 + 0xaf) & 4) != 0) && ((*(byte *)(param_1 + 0xaf) & 8) == 0)) {
    uVar2 = FUN_80017690(0x86a);
    if (uVar2 == 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    }
  }
  pbVar6[1] = pbVar6[1] | 2;
  bVar1 = *pbVar6;
  if (bVar1 == 2) {
    iVar3 = FUN_80017a90();
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    if ((pbVar6[1] & 2) != 0) {
      if ((pbVar6[1] & 4) != 0) {
        uVar2 = FUN_80017760(0xffffffff,1);
        *(float *)(param_1 + 0x10) =
             *(float *)(iVar4 + 0xc) +
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5280);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x70f,0,2,0xffffffff,0);
      }
      *(float *)(pbVar6 + 0x14) = *(float *)(pbVar6 + 0x14) - FLOAT_803dc074;
      if (*(float *)(pbVar6 + 0x14) <= FLOAT_803e528c) {
        uVar2 = FUN_80017760(0,1);
        if (uVar2 == 0) {
          uVar2 = FUN_80017760(0x32,200);
          *(float *)(pbVar6 + 0x14) =
               (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5280);
          pbVar6[1] = pbVar6[1] & 0xfb;
        }
        else {
          *(float *)(pbVar6 + 0x14) = FLOAT_803e5290;
          pbVar6[1] = pbVar6[1] | 4;
          FUN_80006824(param_1,0x438);
        }
      }
      iVar4 = FUN_80017a98();
      if ((iVar4 == 0) ||
         (dVar7 = FUN_80017708((float *)(iVar4 + 0x18),(float *)(param_1 + 0x18)),
         (double)FLOAT_803e5294 < dVar7)) {
        FUN_800810f4((double)FLOAT_803e5274,(double)FLOAT_803e529c,param_1,5,6,1,0x28,0,0);
      }
      else {
        FUN_800810f4((double)FLOAT_803e5274,(double)FLOAT_803e5298,param_1,5,5,1,0x28,0,0);
        (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,param_1,1,4);
      }
      iVar4 = ObjHits_GetPriorityHit(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if (iVar4 == 0x1a) {
        *pbVar6 = 3;
        pbVar6[0xc] = 0;
        pbVar6[0xd] = 0;
        *(float *)(pbVar6 + 0x10) = FLOAT_803e52a0;
      }
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      *pbVar6 = 1;
      *(float *)(param_1 + 0x10) = *(float *)(iVar4 + 0xc) - FLOAT_803e5288;
      uVar2 = FUN_80017690((int)*(short *)(pbVar6 + 8));
      if (uVar2 != 0) {
        *pbVar6 = 2;
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
        *(undefined *)(param_1 + 0x36) = 0xff;
      }
      uVar2 = FUN_80017690((int)*(short *)(pbVar6 + 10));
      if (uVar2 != 0) {
        puVar5 = *(undefined **)(param_1 + 0xb8);
        iVar4 = *(int *)(param_1 + 0x4c);
        uVar2 = FUN_80017690((int)*(short *)(puVar5 + 8));
        if (uVar2 != 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
          FUN_80017698((int)*(short *)(puVar5 + 10),1);
          *puVar5 = 4;
          *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
        }
      }
    }
    else if ((((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
             (iVar3 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x86a), iVar3 != 0)) &&
            (uVar2 = FUN_80017690(0x86a), uVar2 != 0)) {
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined *)(param_1 + 0x36) = 0;
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      FUN_80017698(0x86a,uVar2 - 1);
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
  }
  else if (bVar1 < 4) {
    iVar3 = FUN_80017a90();
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
    dVar7 = FUN_80017708((float *)(iVar3 + 0x18),(float *)(param_1 + 0x18));
    if ((double)FLOAT_803e5294 < dVar7) {
      FUN_800810f4((double)FLOAT_803e5274,(double)FLOAT_803e529c,param_1,5,6,1,0x28,0,0);
    }
    else {
      FUN_800810f4((double)FLOAT_803e5274,(double)FLOAT_803e5298,param_1,5,5,1,0x28,0,0);
    }
    if (((*(float *)(pbVar6 + 0x10) <= FLOAT_803e528c) &&
        (uVar2 = FUN_80017690((int)*(short *)(pbVar6 + 8)), uVar2 != 0)) &&
       (uVar2 = FUN_80017690((int)*(short *)(pbVar6 + 10)), uVar2 == 0)) {
      puVar5 = *(undefined **)(param_1 + 0xb8);
      iVar4 = *(int *)(param_1 + 0x4c);
      uVar2 = FUN_80017690((int)*(short *)(puVar5 + 8));
      if (uVar2 != 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        FUN_80017698((int)*(short *)(puVar5 + 10),1);
        *puVar5 = 4;
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
      }
    }
    *(float *)(pbVar6 + 0x10) = *(float *)(pbVar6 + 0x10) - FLOAT_803dc074;
    if (*(float *)(pbVar6 + 0x10) < FLOAT_803e528c) {
      *(float *)(pbVar6 + 0x10) = FLOAT_803e528c;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aa378
 * EN v1.0 Address: 0x801AA378
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AA230
 * EN v1.1 Size: 512b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aa378(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801aa37c
 * EN v1.0 Address: 0x801AA37C
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801AA430
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aa37c(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x3f);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aa3a0
 * EN v1.0 Address: 0x801AA3A0
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x801AA458
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aa3a0(int param_1)
{
  uint uVar1;
  char *pcVar2;
  float local_18 [4];
  
  local_18[0] = FLOAT_803e52a8;
  pcVar2 = *(char **)(param_1 + 0xb8);
  uVar1 = FUN_80017690(0x1c0);
  if (uVar1 != 0) {
    ObjGroup_FindNearestObject(5,param_1,local_18);
    if (*pcVar2 == '\x01') {
      if (FLOAT_803e52ac <= local_18[0]) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x3df,0,0,0xffffffff,0);
      }
      else {
        *pcVar2 = '\0';
      }
    }
    else if ((*pcVar2 == '\0') && (FLOAT_803e52ac <= local_18[0])) {
      *pcVar2 = '\x01';
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aa480
 * EN v1.0 Address: 0x801AA480
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801AA538
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801aa480(int param_1)
{
  ObjGroup_AddObject(param_1,0x3f);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801aa4a4
 * EN v1.0 Address: 0x801AA4A4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801AA55C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801aa4a4(void)
{
  ccqueen_render();
  return 0;
}


/* Trivial 4b 0-arg blr leaves. */
void animsharpclaw_hitDetect(void) {}
void animsharpclaw_release(void) {}
void animsharpclaw_initialise(void) {}
void fn_801A970C(void) {}
void fn_801A9E6C(void) {}
void fn_801A9E70(void) {}
void ccgasvent_render(void) {}
