#include "ghidra_import.h"
#include "main/dll/screenOverlay.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006824();
extern void* FUN_80017470();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern int FUN_80017a98();
extern undefined4 FUN_800360d4();
extern int FUN_800369d0();
extern undefined4 FUN_80037ce0();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b56c();
extern undefined4 FUN_8003b818();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_80321b80;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd728;
extern f64 DOUBLE_803e4370;
extern f64 DOUBLE_803e4388;
extern f64 DOUBLE_803e43a8;
extern f32 FLOAT_803e4334;
extern f32 FLOAT_803e4378;
extern f32 FLOAT_803e439c;
extern f32 FLOAT_803e43a0;

/*
 * --INFO--
 *
 * Function: FUN_8017a38c
 * EN v1.0 Address: 0x8017A38C
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x8017A3F4
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017a38c(int param_1)
{
  int iVar1;
  undefined local_18 [8];
  undefined4 local_10;
  uint uStack_c;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  local_18[0] = 5;
  FUN_800033a8(iVar1,0,0x2cc);
  FUN_80017a98();
  *(undefined *)(iVar1 + 0x274) = 0;
  *(float *)(iVar1 + 0x26c) = FLOAT_803e4334;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  uStack_c = (int)*(short *)(*(int *)(param_1 + 0x54) + 0x5a) ^ 0x80000000;
  local_10 = 0x43300000;
  *(float *)(iVar1 + 0x268) = (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e4370);
  (**(code **)(*DAT_803dd728 + 4))(iVar1,0,0x40007,1);
  (**(code **)(*DAT_803dd728 + 8))(iVar1,1,&DAT_80321b80,iVar1 + 0x268,1);
  (**(code **)(*DAT_803dd728 + 0xc))(iVar1,1,&DAT_80321b80,iVar1 + 0x268,local_18);
  (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar1);
  FUN_800360d4(param_1);
  *(undefined *)(iVar1 + 0x25b) = 0;
  FUN_80037ce0(param_1,1);
  FUN_80017698(0x3f8,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017a4e8
 * EN v1.0 Address: 0x8017A4E8
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x8017A58C
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017a4e8(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar2 = 0;
  uVar1 = (uint)*(byte *)(param_3 + 0x8b);
  while( true ) {
    if (uVar1 == 0) {
      return 0;
    }
    if (*(char *)(param_3 + iVar2 + 0x81) == '\x01') break;
    iVar2 = iVar2 + 1;
    uVar1 = uVar1 - 1;
  }
  uVar1 = (uint)*(short *)(iVar3 + 0xe);
  if (uVar1 != 0xffffffff) {
    FUN_80017698(uVar1,1);
  }
  *(undefined *)(iVar3 + 0x14) = 1;
  return 4;
}

/*
 * --INFO--
 *
 * Function: FUN_8017a56c
 * EN v1.0 Address: 0x8017A56C
 * EN v1.0 Size: 428b
 * EN v1.1 Address: 0x8017A624
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017a56c(int param_1)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  bVar1 = *(byte *)(iVar3 + 0x14);
  if (bVar1 == 2) {
    *(ushort *)(iVar3 + 0x10) = *(short *)(iVar3 + 0x10) + (ushort)DAT_803dc070;
    if (*(uint *)(iVar3 + 8) < (uint)(int)*(short *)(iVar3 + 0x10)) {
      *(undefined *)(iVar3 + 0x14) = 3;
    }
    dVar4 = (double)FUN_80293f90();
    *(short *)(iVar3 + 0x12) = (short)(int)((double)FLOAT_803e4378 * dVar4) + 0xdc;
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      iVar2 = FUN_80017a98();
      dVar4 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
      if (dVar4 < (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 0xc)) -
                                 DOUBLE_803e4388)) {
        if ((int)*(short *)(iVar3 + 0xe) != 0xffffffff) {
          FUN_80017698((int)*(short *)(iVar3 + 0xe),1);
        }
        *(undefined *)(iVar3 + 0x14) = 1;
      }
    }
    else {
      *(ushort *)(iVar3 + 0x12) = *(short *)(iVar3 + 0x12) + (ushort)DAT_803dc070 * 4;
      if (0xdc < *(short *)(iVar3 + 0x12)) {
        *(undefined2 *)(iVar3 + 0x12) = 0xdc;
        *(undefined *)(iVar3 + 0x14) = 2;
      }
    }
  }
  else if (((bVar1 != 4) && (bVar1 < 4)) &&
          (*(ushort *)(iVar3 + 0x12) = *(short *)(iVar3 + 0x12) + (ushort)DAT_803dc070 * -4,
          *(short *)(iVar3 + 0x12) < 0)) {
    *(undefined2 *)(iVar3 + 0x12) = 0;
    *(undefined *)(iVar3 + 0x14) = 4;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017a718
 * EN v1.0 Address: 0x8017A718
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017A7D0
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017a718(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017a71c
 * EN v1.0 Address: 0x8017A71C
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8017A8D0
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017a71c(void)
{
  int iVar1;
  int iVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  iVar2 = *(int *)(iVar1 + 0x4c);
  if (in_r8 != '\0') {
    if ((*(byte *)(iVar2 + 0x23) & 1) != 0) {
      FUN_8003b56c((ushort)*(byte *)(iVar2 + 0x20),(ushort)*(byte *)(iVar2 + 0x21),
                   (ushort)*(byte *)(iVar2 + 0x22));
    }
    FUN_8003b818(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017a77c
 * EN v1.0 Address: 0x8017A77C
 * EN v1.0 Size: 432b
 * EN v1.1 Address: 0x8017A95C
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017a77c(uint param_1)
{
  bool bVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined *puVar5;
  char *pcVar6;
  int local_28 [6];
  
  iVar4 = *(int *)(param_1 + 0x4c);
  pcVar6 = *(char **)(param_1 + 0xb8);
  iVar2 = FUN_800369d0(param_1,local_28,(int *)0x0,(uint *)0x0);
  if ((iVar2 == 0xe) || (iVar2 == 0xf)) {
    bVar1 = false;
    if ((*(short *)(local_28[0] + 0x46) == 0x14b) &&
       ((*(byte *)(*(int *)(local_28[0] + 0x54) + 0xad) & 2) != 0)) {
      bVar1 = true;
    }
    if (!bVar1) {
      if (*pcVar6 == '\0') {
        puVar5 = *(undefined **)(param_1 + 0xb8);
        if (*(char *)(param_1 + 0xac) == ',') {
          FUN_80006824(param_1,0x109);
        }
        else {
          FUN_80006824(param_1,0x62);
        }
        puVar3 = (undefined4 *)FUN_80039520(param_1,0);
        if (puVar3 != (undefined4 *)0x0) {
          *puVar3 = 0x100;
        }
        *puVar5 = 1;
        FUN_80017698((int)*(short *)(pcVar6 + 2),1);
        if ((*(byte *)(iVar4 + 0x1e) & 3) == 2) {
          *(float *)(pcVar6 + 4) =
               FLOAT_803e439c *
               FLOAT_803e43a0 *
               (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar4 + 0x1a) ^ 0x80000000) -
                      DOUBLE_803e43a8);
        }
      }
      else if ((*(byte *)(iVar4 + 0x1e) & 3) == 1) {
        puVar5 = *(undefined **)(param_1 + 0xb8);
        if (*(char *)(param_1 + 0xac) == ',') {
          FUN_80006824(param_1,0x109);
        }
        else {
          FUN_80006824(param_1,99);
        }
        puVar3 = (undefined4 *)FUN_80039520(param_1,0);
        if (puVar3 != (undefined4 *)0x0) {
          *puVar3 = 0;
        }
        *puVar5 = 0;
        FUN_80017698((int)*(short *)(pcVar6 + 2),0);
      }
    }
  }
  return;
}
