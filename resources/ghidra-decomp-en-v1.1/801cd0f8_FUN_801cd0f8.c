// Function: FUN_801cd0f8
// Entry: 801cd0f8
// Size: 904 bytes

void FUN_801cd0f8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  float fVar1;
  short sVar2;
  uint uVar3;
  int in_r9;
  undefined4 in_r10;
  int iVar4;
  double dVar5;
  undefined8 uVar6;
  undefined auStack_28 [8];
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  undefined4 local_10;
  uint uStack_c;
  
  dVar5 = DOUBLE_803e5e58;
  iVar4 = *(int *)(param_9 + 0x5c);
  local_1c = FLOAT_803e5e50;
  local_18 = FLOAT_803e5e50;
  local_14 = FLOAT_803e5e50;
  uStack_c = (int)*(char *)(*(int *)(param_9 + 0x26) + 0x19) ^ 0x80000000;
  local_10 = 0x43300000;
  local_20 = (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e5e58);
  if ((*(byte *)(iVar4 + 0x36) & 1) == 0) {
    *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(param_9 + 10);
    *(byte *)(iVar4 + 0x36) = *(byte *)(iVar4 + 0x36) | 1;
  }
  if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) != '\0') {
    FUN_8000bb38((uint)param_9,0xb3);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x2a0,auStack_28,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x2a0,auStack_28,1,0xffffffff,0);
    in_r9 = *DAT_803dd708;
    dVar5 = (double)(**(code **)(in_r9 + 8))(param_9,0x2a0,auStack_28,1,0xffffffff,0);
    *(undefined2 *)(iVar4 + 0x32) = 0x32;
  }
  if (*(short *)(iVar4 + 0x32) == 0) {
    *(undefined4 *)(param_9 + 0x40) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(param_9 + 0x42) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(param_9 + 0x44) = *(undefined4 *)(param_9 + 10);
    *param_9 = *param_9 + *(short *)(iVar4 + 0x2e) * (ushort)DAT_803dc070;
    param_9[2] = param_9[2] + *(short *)(iVar4 + 0x2c) * (ushort)DAT_803dc070;
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x29d,auStack_28,4,0xffffffff,0);
    sVar2 = *(short *)(iVar4 + 0x30) - (ushort)DAT_803dc070;
    *(short *)(iVar4 + 0x30) = sVar2;
    if (sVar2 < 1) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x29e,auStack_28,4,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x29f,auStack_28,4,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x2a1,auStack_28,4,0xffffffff,0);
      *(undefined2 *)(iVar4 + 0x30) = 0x32;
    }
    *(float *)(iVar4 + 8) = *(float *)(param_9 + 0x12) * FLOAT_803dc074 + *(float *)(iVar4 + 8);
    *(float *)(iVar4 + 0xc) = *(float *)(param_9 + 0x14) * FLOAT_803dc074 + *(float *)(iVar4 + 0xc);
    fVar1 = *(float *)(param_9 + 0x16);
    dVar5 = (double)FLOAT_803dc074;
    *(float *)(iVar4 + 0x10) = (float)((double)fVar1 * dVar5 + (double)*(float *)(iVar4 + 0x10));
    *(ushort *)(iVar4 + 0x34) = *(short *)(iVar4 + 0x34) + (ushort)DAT_803dc070 * 0x5dc;
    *(undefined4 *)(param_9 + 6) = *(undefined4 *)(iVar4 + 8);
    *(undefined4 *)(param_9 + 8) = *(undefined4 *)(iVar4 + 0xc);
    *(undefined4 *)(param_9 + 10) = *(undefined4 *)(iVar4 + 0x10);
    uVar3 = (uint)DAT_803dc070;
    iVar4 = *(int *)(param_9 + 0x7a);
    *(uint *)(param_9 + 0x7a) = iVar4 - uVar3;
    if ((int)(iVar4 - uVar3) < 0) {
      FUN_8002cc9c(dVar5,(double)fVar1,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9)
      ;
    }
  }
  else {
    if ((*(byte *)(iVar4 + 0x36) & 2) == 0) {
      FUN_800066e0(dVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,1,0
                   ,0,0,in_r9,in_r10);
      *(byte *)(iVar4 + 0x36) = *(byte *)(iVar4 + 0x36) | 2;
    }
    fVar1 = FLOAT_803e5e50;
    *(float *)(param_9 + 0x12) = FLOAT_803e5e50;
    *(float *)(param_9 + 0x14) = fVar1;
    *(float *)(param_9 + 0x16) = fVar1;
    uVar6 = FUN_80035ea4((int)param_9);
    *(short *)(iVar4 + 0x32) = *(short *)(iVar4 + 0x32) + -1;
    if (*(short *)(iVar4 + 0x32) < 1) {
      FUN_8002cc9c(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  return;
}

