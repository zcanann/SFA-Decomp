#include "ghidra_import.h"
#include "main/dll/DF/DFcradle.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000e670();
extern undefined4 FUN_80014acc();
extern undefined4 FUN_8001dbb4();
extern undefined4 FUN_8001dbd8();
extern undefined4 FUN_8001dbf0();
extern undefined4 FUN_8001dc30();
extern undefined4 FUN_8001dcfc();
extern undefined4 FUN_8001f448();
extern void* FUN_8001f58c();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_800217c8();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern void* FUN_8002becc();
extern int FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_80035a6c();
extern undefined4 FUN_80035eec();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036018();
extern void* FUN_80037048();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_800972fc();

extern undefined4 DAT_80326928;
extern undefined4 DAT_8032692a;
extern undefined4 DAT_8032692c;
extern undefined4 DAT_8032692e;
extern undefined4 DAT_80326930;
extern undefined4 DAT_80326932;
extern undefined4 DAT_803269a8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e5a28;
extern f64 DOUBLE_803e5a60;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5a24;
extern f32 FLOAT_803e5a38;
extern f32 FLOAT_803e5a3c;
extern f32 FLOAT_803e5a40;
extern f32 FLOAT_803e5a44;
extern f32 FLOAT_803e5a48;
extern f32 FLOAT_803e5a4c;
extern f32 FLOAT_803e5a50;
extern f32 FLOAT_803e5a54;
extern f32 FLOAT_803e5a58;

/*
 * --INFO--
 *
 * Function: FUN_801c05bc
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C05BC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c05bc(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c05f0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C05F0
 * EN v1.1 Size: 636b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c05f0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  uint uVar1;
  int *piVar2;
  undefined2 *puVar3;
  int iVar4;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  double dVar6;
  int local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  iVar5 = *(int *)(param_9 + 0x4c);
  uVar1 = FUN_8002e144();
  if (((uVar1 & 0xff) != 0) && (uVar1 = FUN_80020078(0x26b), uVar1 != 0)) {
    FUN_800201ac(0x26b,0);
    piVar2 = FUN_80037048(4,local_28);
    iVar4 = 0;
    if (0 < local_28[0]) {
      do {
        in_r8 = *piVar2;
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_80326928) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_8032692a) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_8032692c) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_8032692e) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_80326930) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_80326932) {
          iVar4 = iVar4 + 1;
        }
        piVar2 = piVar2 + 1;
        local_28[0] = local_28[0] + -1;
      } while (local_28[0] != 0);
    }
    if (iVar4 < 10) {
      uVar1 = FUN_80022264(0,5);
      puVar3 = FUN_8002becc(0x30,(&DAT_80326928)[uVar1]);
      if (puVar3 != (undefined2 *)0x0) {
        *(undefined *)(puVar3 + 0xd) = 0x14;
        puVar3[0x16] = 0xffff;
        puVar3[0xe] = 0xffff;
        uStack_1c = FUN_80022264(0xfffffea2,0x15e);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        *(float *)(puVar3 + 4) =
             *(float *)(param_9 + 0xc) +
             (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5a28);
        *(float *)(puVar3 + 6) = FLOAT_803e5a24 + *(float *)(param_9 + 0x10);
        uStack_14 = FUN_80022264(0xfffffea2,0x15e);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        dVar6 = (double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e5a28);
        *(float *)(puVar3 + 8) = (float)((double)*(float *)(param_9 + 0x14) + dVar6);
        puVar3[0x12] = 0xffff;
        *(undefined *)(puVar3 + 2) = *(undefined *)(iVar5 + 4);
        *(undefined *)(puVar3 + 3) = *(undefined *)(iVar5 + 6);
        *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar5 + 5);
        *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar5 + 7);
        puVar3[0x17] = 3;
        iVar5 = FUN_8002e088(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                             *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),
                             in_r8,in_r9,in_r10);
        if (iVar5 != 0) {
          iVar4 = 3;
          do {
            FUN_800972fc(iVar5,2,2,100,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c086c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C086C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801c086c(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x1e));
  if (uVar1 != 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,*(short *)(iVar2 + 0x1a) + 0x4c6,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x4c8,0,2,0xffffffff,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801c0928
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C0928
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c0928(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c0968
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C0968
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c0968(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x1e));
  if (uVar1 != 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,*(short *)(iVar2 + 0x1a) + 0x4c6,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x4c8,0,2,0xffffffff,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c0a7c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C0A7C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c0a7c(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = *(uint *)(iVar2 + 0x10);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *(undefined4 *)(iVar2 + 0x10) = 0;
  }
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c0af0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C0AF0
 * EN v1.1 Size: 1136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c0af0(uint param_1)
{
  uint uVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  byte *pbVar5;
  double dVar6;
  
  pbVar5 = *(byte **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((int)*(short *)(iVar4 + 0x20) == 0xffffffff) {
    *(float *)(pbVar5 + 0xc) = *(float *)(pbVar5 + 0xc) - FLOAT_803dc074;
    if (*(float *)(pbVar5 + 0xc) <= FLOAT_803e5a38) {
      uVar1 = FUN_80022264(0xf0,0x1e0);
      *(float *)(pbVar5 + 0xc) =
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5a60);
      *pbVar5 = *pbVar5 | 1;
      *(undefined4 *)(pbVar5 + 4) = *(undefined4 *)(&DAT_803269a8 + (uint)pbVar5[1] * 4);
      *(undefined4 *)(pbVar5 + 8) = *(undefined4 *)(pbVar5 + 4);
      pbVar5[1] = pbVar5[1] + 1;
      if (9 < pbVar5[1]) {
        pbVar5[1] = 0;
      }
    }
  }
  else {
    uVar1 = FUN_80020078((int)*(short *)(iVar4 + 0x20));
    if (uVar1 != 0) {
      FUN_800201ac((int)*(short *)(iVar4 + 0x20),0);
      *pbVar5 = *pbVar5 | 1;
      *(undefined4 *)(pbVar5 + 4) = *(undefined4 *)(&DAT_803269a8 + (uint)pbVar5[1] * 4);
      *(undefined4 *)(pbVar5 + 8) = *(undefined4 *)(pbVar5 + 4);
      pbVar5[1] = pbVar5[1] + 1;
      if (9 < pbVar5[1]) {
        pbVar5[1] = 0;
      }
    }
  }
  if (FLOAT_803e5a38 < *(float *)(pbVar5 + 4)) {
    if ((*pbVar5 & 1) != 0) {
      *pbVar5 = *pbVar5 & 0xfe;
      FUN_80035eec(param_1,9,1,0);
      FUN_80035a6c(param_1,0xf);
      FUN_80036018(param_1);
      if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
        iVar3 = 0;
        do {
          if (*(short *)(iVar4 + 0x1a) == 0) {
            (**(code **)(*DAT_803dd708 + 8))(param_1,0x4cc,0,2,0xffffffff,0);
          }
          else {
            (**(code **)(*DAT_803dd708 + 8))(param_1,0x4c9,0,2,0xffffffff,0);
          }
          iVar3 = iVar3 + 1;
        } while (iVar3 < 0x32);
      }
      iVar3 = FUN_8002bac4();
      if ((iVar3 != 0) && ((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0)) {
        dVar6 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18));
        if (dVar6 <= (double)FLOAT_803e5a3c) {
          dVar6 = (double)(FLOAT_803e5a40 - (float)(dVar6 / (double)FLOAT_803e5a3c));
          FUN_8000e670((double)(float)((double)FLOAT_803e5a44 * dVar6),(double)FLOAT_803e5a44,
                       (double)FLOAT_803e5a48);
          FUN_80014acc((double)(float)((double)FLOAT_803e5a4c * dVar6));
        }
      }
      if (*(int *)(pbVar5 + 0x10) == 0) {
        piVar2 = FUN_8001f58c(param_1,'\x01');
        *(int **)(pbVar5 + 0x10) = piVar2;
        if (*(int *)(pbVar5 + 0x10) != 0) {
          FUN_8001dbf0(*(int *)(pbVar5 + 0x10),2);
          FUN_8001dbd8(*(int *)(pbVar5 + 0x10),1);
          if (*(short *)(iVar4 + 0x1a) == 0) {
            FUN_8001dbb4(*(int *)(pbVar5 + 0x10),0x7f,0xff,0,0);
          }
          else {
            FUN_8001dbb4(*(int *)(pbVar5 + 0x10),0xff,0x7f,0,0);
          }
          FUN_8001dcfc((double)FLOAT_803e5a50,(double)FLOAT_803e5a54,*(int *)(pbVar5 + 0x10));
          FUN_8001dc30((double)FLOAT_803e5a38,*(int *)(pbVar5 + 0x10),'\x01');
          FUN_8001dc30((double)(*(float *)(pbVar5 + 4) / FLOAT_803e5a58),*(int *)(pbVar5 + 0x10),
                       '\0');
        }
      }
      FUN_8000bb38(param_1,0x188);
    }
    *(float *)(pbVar5 + 4) = *(float *)(pbVar5 + 4) - FLOAT_803dc074;
    if (FLOAT_803e5a38 < *(float *)(pbVar5 + 4)) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x4ca,0,2,0xffffffff,0);
      if (*(short *)(iVar4 + 0x1a) == 0) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x4cd,0,2,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x4cb,0,2,0xffffffff,0);
      }
    }
    else {
      *(float *)(pbVar5 + 4) = FLOAT_803e5a38;
      if (*(uint *)(pbVar5 + 0x10) != 0) {
        FUN_8001f448(*(uint *)(pbVar5 + 0x10));
        pbVar5[0x10] = 0;
        pbVar5[0x11] = 0;
        pbVar5[0x12] = 0;
        pbVar5[0x13] = 0;
      }
      FUN_80035eec(param_1,0,0,0);
      FUN_80035a6c(param_1,0);
      FUN_80035ff8(param_1);
    }
  }
  return;
}
