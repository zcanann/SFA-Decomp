#include "ghidra_import.h"
#include "main/dll/dll_1CA.h"

extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80006c10();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_8001771c();
extern int FUN_80017a98();
extern int ObjHits_GetPriorityHit();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern int FUN_80044404();
extern undefined4 FUN_80055ef0();
extern undefined4 FUN_80057690();
extern undefined8 FUN_80080f28();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80294ccc();

extern undefined4 DAT_802c2b48;
extern undefined4 DAT_802c2b4c;
extern undefined4 DAT_802c2b50;
extern undefined4 DAT_802c2b54;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc270;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f0;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de850;
extern undefined4 DAT_803de858;
extern f64 DOUBLE_803e5de0;
extern f32 FLOAT_803e5dd0;
extern f32 FLOAT_803e5dd4;
extern f32 FLOAT_803e5dd8;
extern f32 FLOAT_803e5ddc;

/*
 * --INFO--
 *
 * Function: FUN_801ca5b4
 * EN v1.0 Address: 0x801CA5B4
 * EN v1.0 Size: 1148b
 * EN v1.1 Address: 0x801CA6BC
 * EN v1.1 Size: 1196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ca5b4(uint param_1)
{
  int iVar1;
  bool bVar4;
  int *piVar2;
  uint uVar3;
  uint *puVar5;
  double dVar6;
  undefined4 local_48;
  int local_44;
  int local_40;
  undefined4 local_3c;
  undefined auStack_38 [16];
  float local_28;
  
  puVar5 = *(uint **)(param_1 + 0xb8);
  local_48 = DAT_802c2b48;
  local_44 = DAT_802c2b4c;
  local_40 = DAT_802c2b50;
  local_3c = DAT_802c2b54;
  iVar1 = FUN_80017a98();
  dVar6 = (double)FUN_8001771c((float *)(iVar1 + 0x18),(float *)(param_1 + 0x18));
  bVar4 = FUN_800067f0(param_1,0x40);
  if (bVar4) {
    if (((double)FLOAT_803e5dd0 <= dVar6) && (*(char *)(puVar5 + 3) != '\0')) {
      FUN_8000680c(param_1,0x40);
    }
  }
  else if ((dVar6 < (double)FLOAT_803e5dd0) && (*(char *)(puVar5 + 3) != '\0')) {
    FUN_80006824(param_1,0x72);
  }
  FUN_80057690(param_1);
  if (0 < *(short *)(puVar5 + 2)) {
    *(ushort *)(puVar5 + 2) = *(short *)(puVar5 + 2) - (ushort)DAT_803dc070;
  }
  if (*(char *)((int)puVar5 + 0xb) == '\x01') {
    local_28 = FLOAT_803e5dd4;
    *(undefined *)((int)puVar5 + 0xe) = *(undefined *)(puVar5 + 3);
    iVar1 = ObjHits_GetPriorityHit(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if ((iVar1 != 0) || ((*(short *)(puVar5 + 2) != 0 && (*(short *)(puVar5 + 2) < 0x15)))) {
      *(char *)(puVar5 + 3) = '\x01' - *(char *)(puVar5 + 3);
      if (*(char *)(puVar5 + 3) != '\0') {
        *(undefined2 *)((int)puVar5 + 6) = 1000;
      }
      if (*(short *)(puVar5 + 2) != 0) {
        *(undefined2 *)(puVar5 + 2) = 0;
        DAT_803de850 = '\x03';
        *(undefined2 *)((int)puVar5 + 6) = 300;
        if (*(char *)((int)puVar5 + 0xf) == '\x02') {
          FUN_80017698(0x472,1);
        }
      }
    }
    if (((*(char *)(puVar5 + 3) != '\0') && (*(short *)((int)puVar5 + 6) != 0)) &&
       (*(ushort *)((int)puVar5 + 6) = *(short *)((int)puVar5 + 6) - (ushort)DAT_803dc070,
       *(short *)((int)puVar5 + 6) < 1)) {
      *(undefined2 *)((int)puVar5 + 6) = 0;
      *(undefined *)(puVar5 + 3) = 0;
    }
    if (((*(char *)(puVar5 + 3) != '\0') && (*(short *)(puVar5 + 1) < 1)) &&
       (*(char *)((int)puVar5 + 0xd) != '\0')) {
      *(undefined *)((int)puVar5 + 0xd) = 0;
      FUN_80006824(param_1,0x80);
    }
    if (*(char *)(puVar5 + 3) != *(char *)((int)puVar5 + 0xe)) {
      if (*(char *)(puVar5 + 3) == '\0') {
        FUN_8000680c(param_1,0x7f);
        (**(code **)(*DAT_803dd6fc + 0x18))(param_1);
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
        if ((*puVar5 != 0xffffffff) && (uVar3 = FUN_80017690(*puVar5), uVar3 != 0)) {
          FUN_80017698(*puVar5,0);
        }
        if ((DAT_803de850 == '\x01') && (*(char *)((int)puVar5 + 0xf) == '\0')) {
          DAT_803de850 = '\0';
        }
        if ((DAT_803de850 == '\x02') && (*(char *)((int)puVar5 + 0xf) == '\x01')) {
          DAT_803de850 = '\0';
        }
        if (((DAT_803de850 == '\x03') && (*(char *)((int)puVar5 + 0xf) == '\x02')) &&
           (uVar3 = FUN_80017690(0x474), uVar3 == 0)) {
          FUN_80017698(0x472,0);
          DAT_803de850 = '\0';
        }
      }
      else {
        piVar2 = (int *)FUN_80006b14(0x69);
        local_40 = (uint)*(byte *)((int)puVar5 + 0xf) * 2;
        local_44 = local_40 + 0x19d;
        local_40 = local_40 + 0x19e;
        (**(code **)(*piVar2 + 4))(param_1,1,auStack_38,0x10004,0xffffffff,&local_48);
        FUN_80006b0c((undefined *)piVar2);
        iVar1 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x1a3,0,0,0xffffffff,0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < 200);
        if ((*puVar5 != 0xffffffff) && (uVar3 = FUN_80017690(*puVar5), uVar3 == 0)) {
          FUN_80017698(*puVar5,1);
        }
        if (((DAT_803de850 == '\0') && (*(char *)((int)puVar5 + 0xf) == '\0')) &&
           (uVar3 = FUN_80017690(*puVar5), uVar3 != 0)) {
          DAT_803de850 = '\x01';
        }
        if (((DAT_803de850 == '\x01') && (*(char *)((int)puVar5 + 0xf) == '\x01')) &&
           (uVar3 = FUN_80017690(*puVar5), uVar3 != 0)) {
          DAT_803de850 = '\x02';
        }
        if (((DAT_803de850 == '\x02') && (*(char *)((int)puVar5 + 0xf) == '\x02')) &&
           (uVar3 = FUN_80017690(*puVar5), uVar3 != 0)) {
          FUN_80017698(0x472,1);
          DAT_803de850 = '\x03';
        }
        *(undefined *)((int)puVar5 + 0xd) = 1;
        *(undefined2 *)(puVar5 + 1) = 1;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801caa30
 * EN v1.0 Address: 0x801CAA30
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x801CAB68
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801caa30(undefined2 *param_1,int param_2)
{
  int *piVar1;
  int *piVar2;
  undefined auStack_38 [16];
  float local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *param_1 = (short)(((int)*(char *)(param_2 + 0x18) & 0x3fU) << 10);
  if (*(short *)(param_2 + 0x1a) < 1) {
    *(float *)(param_1 + 4) = FLOAT_803e5ddc;
  }
  else {
    uStack_1c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5de0) / FLOAT_803e5dd8;
  }
  *(undefined *)((int)piVar2 + 0xb) = *(undefined *)(param_2 + 0x19);
  *(undefined *)(piVar2 + 3) = 0;
  *(undefined *)((int)piVar2 + 0xf) = 0;
  *piVar2 = (int)*(short *)(param_2 + 0x1e);
  local_28 = FLOAT_803e5dd4;
  if (*(char *)((int)piVar2 + 0xb) == '\x01') {
    *(char *)((int)piVar2 + 0xf) = (char)*(undefined2 *)(param_2 + 0x1c);
    *(undefined *)((int)piVar2 + 0xd) = 0;
    *(ushort *)(piVar2 + 2) = (ushort)*(byte *)((int)piVar2 + 0xf) * 0x28 + 0x398;
    *(undefined *)((int)piVar2 + 0xe) = 0;
  }
  else if (*(char *)((int)piVar2 + 0xb) == '\0') {
    *(undefined *)(piVar2 + 3) = 1;
    piVar1 = (int *)FUN_80006b14(0x69);
    if (*(short *)(param_2 + 0x1c) == 0) {
      (**(code **)(*piVar1 + 4))(param_1,0,auStack_38,0x10004,0xffffffff,0);
    }
  }
  *(undefined2 *)(piVar2 + 1) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cab60
 * EN v1.0 Address: 0x801CAB60
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x801CACCC
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801cab60(undefined4 param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80017a98();
  if (iVar1 != 0) {
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
      if (*(char *)(param_3 + iVar2 + 0x81) == '\x01') {
        FUN_80294ccc(iVar1,0x10,1);
        FUN_80017698(0x174,1);
        (**(code **)(*DAT_803dd72c + 0x50))(0xb,4,1);
        (**(code **)(*DAT_803dd72c + 0x50))(0xb,0x1d,1);
        (**(code **)(*DAT_803dd72c + 0x50))(0xb,0x1e,1);
        (**(code **)(*DAT_803dd72c + 0x50))(0xb,0x1f,1);
        (**(code **)(*DAT_803dd72c + 0x44))(0xb,6);
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801caca0
 * EN v1.0 Address: 0x801CACA0
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801CAE0C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801caca0(void)
{
  FUN_800067c0((int *)0x6,0);
  FUN_80017698(0xefd,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cacd4
 * EN v1.0 Address: 0x801CACD4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801CAE40
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cacd4(int param_1)
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
 * Function: FUN_801cacfc
 * EN v1.0 Address: 0x801CACFC
 * EN v1.0 Size: 432b
 * EN v1.1 Address: 0x801CAE74
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cacfc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar1;
  
  if ((*(int *)(param_9 + 0xf4) != 0) &&
     (*(int *)(param_9 + 0xf4) = *(int *)(param_9 + 0xf4) + -1, *(int *)(param_9 + 0xf4) == 0)) {
    uVar1 = FUN_80080f28(7,'\x01');
    uVar1 = FUN_80006728(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0xd1,0,
                         in_r7,in_r8,in_r9,in_r10);
    uVar1 = FUN_80006728(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0xd6,0,
                         in_r7,in_r8,in_r9,in_r10);
    FUN_80006728(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x222,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801caeac
 * EN v1.0 Address: 0x801CAEAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CAEF8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801caeac(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801caeb0
 * EN v1.0 Address: 0x801CAEB0
 * EN v1.0 Size: 1240b
 * EN v1.1 Address: 0x801CAF74
 * EN v1.1 Size: 788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801caeb0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  
  iVar1 = FUN_80286840();
  iVar4 = *(int *)(iVar1 + 0xb8);
  *(undefined2 *)(param_11 + 0x70) = 0xffff;
  *(undefined *)(param_11 + 0x56) = 0;
  uVar5 = extraout_f1;
  if (*(short *)(iVar4 + 10) != 0) {
    *(short *)(iVar4 + 8) = *(short *)(iVar4 + 8) + *(short *)(iVar4 + 10);
    if ((*(short *)(iVar4 + 8) < 2) && (*(short *)(iVar4 + 10) < 1)) {
      *(undefined2 *)(iVar4 + 8) = 1;
      *(undefined2 *)(iVar4 + 10) = 0;
    }
    else if ((0x45 < *(short *)(iVar4 + 8)) && (-1 < *(short *)(iVar4 + 10))) {
      *(undefined2 *)(iVar4 + 8) = 0x46;
      *(undefined2 *)(iVar4 + 10) = 0;
    }
    uVar5 = (**(code **)(*DAT_803dd6f0 + 0x38))(3,*(ushort *)(iVar4 + 8) & 0xff);
  }
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)(param_11 + iVar3 + 0x81)) {
    case 1:
      uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1
                           ,0xc3,0,param_13,param_14,param_15,param_16);
      break;
    case 2:
      if (DAT_803dc270 == 0xffffffff) {
        uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             iVar1,0x14,0,param_13,param_14,param_15,param_16);
      }
      else {
        uVar5 = FUN_80006728(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             iVar1,DAT_803dc270 & 0xffff,0,param_13,param_14,param_15,param_16);
      }
      break;
    case 3:
      *(undefined *)(iVar4 + 0x10) = 1;
      break;
    case 4:
      *(undefined *)(iVar4 + 0xf) = 4;
      *(undefined *)(iVar4 + 0x10) = 2;
      FUN_80017698(0x129,1);
      FUN_80017698(0x1cf,0);
      uVar5 = FUN_80017698(0x126,1);
      *(undefined2 *)(iVar4 + 10) = 0xfffd;
      break;
    case 5:
      *(undefined *)(iVar4 + 0x10) = 3;
      *(undefined2 *)(iVar4 + 10) = 0xfffd;
      uVar5 = FUN_80017698(0x129,1);
      break;
    case 6:
      uVar5 = FUN_80017698(0x1cf,1);
      break;
    case 7:
      uVar5 = FUN_80017698(0x1cf,0);
      *(undefined2 *)(iVar4 + 10) = 0xfffd;
      break;
    case 8:
      uVar5 = FUN_80017698(0x127,1);
      break;
    case 9:
      uVar5 = FUN_80017698(0x128,1);
      if (DAT_803de858 == 0) {
        DAT_803de858 = FUN_80055ef0();
      }
      break;
    case 10:
      *(undefined2 *)(iVar4 + 8) = 100;
      param_13 = 0;
      param_14 = *DAT_803dd6f0;
      uVar5 = (**(code **)(param_14 + 0x18))(3,0x2d,0x50,*(ushort *)(iVar4 + 8) & 0xff);
      break;
    case 0xb:
      *(undefined *)(iVar4 + 0xf) = 7;
    }
    *(undefined *)(param_11 + iVar3 + 0x81) = 0;
  }
  if (*(char *)(iVar4 + 0xf) == '\a') {
    uVar2 = FUN_80006c10(0);
    if ((uVar2 & 0x100) == 0) {
      uVar2 = FUN_80006c10(0);
      if ((uVar2 & 0x200) != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x4c))((int)*(char *)(param_11 + 0x57));
        *(undefined *)(iVar4 + 0xf) = 7;
        *(undefined2 *)(iVar4 + 2) = 0;
      }
    }
    else {
      (**(code **)(*DAT_803dd6d4 + 0x4c))((int)*(char *)(param_11 + 0x57));
      *(undefined *)(iVar4 + 0xf) = 8;
      *(undefined2 *)(iVar4 + 2) = 0;
    }
  }
  FUN_8028688c();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_801CA710(void) {}
void fn_801CA714(void) {}
void nwsh_levcon_hitDetect(void) {}
void nwsh_levcon_release(void) {}
void nwsh_levcon_initialise(void) {}
void fn_801CAD7C(void) {}
