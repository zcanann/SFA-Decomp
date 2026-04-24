// Function: FUN_801ccb44
// Entry: 801ccb44
// Size: 904 bytes

void FUN_801ccb44(short *param_1)

{
  float fVar1;
  short sVar2;
  uint uVar3;
  int iVar4;
  undefined auStack40 [8];
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  undefined4 local_10;
  uint uStack12;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  local_1c = FLOAT_803e51b8;
  local_18 = FLOAT_803e51b8;
  local_14 = FLOAT_803e51b8;
  uStack12 = (int)*(char *)(*(int *)(param_1 + 0x26) + 0x19) ^ 0x80000000;
  local_10 = 0x43300000;
  local_20 = (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e51c0);
  if ((*(byte *)(iVar4 + 0x36) & 1) == 0) {
    *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(param_1 + 10);
    *(byte *)(iVar4 + 0x36) = *(byte *)(iVar4 + 0x36) | 1;
  }
  if (*(char *)(*(int *)(param_1 + 0x2a) + 0xad) != '\0') {
    FUN_8000bb18(param_1,0xb3);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x2a0,auStack40,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x2a0,auStack40,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x2a0,auStack40,1,0xffffffff,0);
    *(undefined2 *)(iVar4 + 0x32) = 0x32;
  }
  if (*(short *)(iVar4 + 0x32) == 0) {
    *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
    *param_1 = *param_1 + *(short *)(iVar4 + 0x2e) * (ushort)DAT_803db410;
    param_1[2] = param_1[2] + *(short *)(iVar4 + 0x2c) * (ushort)DAT_803db410;
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x29d,auStack40,4,0xffffffff,0);
    sVar2 = *(short *)(iVar4 + 0x30) - (ushort)DAT_803db410;
    *(short *)(iVar4 + 0x30) = sVar2;
    if (sVar2 < 1) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x29e,auStack40,4,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x29f,auStack40,4,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x2a1,auStack40,4,0xffffffff,0);
      *(undefined2 *)(iVar4 + 0x30) = 0x32;
    }
    *(float *)(iVar4 + 8) = *(float *)(param_1 + 0x12) * FLOAT_803db414 + *(float *)(iVar4 + 8);
    *(float *)(iVar4 + 0xc) = *(float *)(param_1 + 0x14) * FLOAT_803db414 + *(float *)(iVar4 + 0xc);
    *(float *)(iVar4 + 0x10) =
         *(float *)(param_1 + 0x16) * FLOAT_803db414 + *(float *)(iVar4 + 0x10);
    *(ushort *)(iVar4 + 0x34) = *(short *)(iVar4 + 0x34) + (ushort)DAT_803db410 * 0x5dc;
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar4 + 8);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0xc);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar4 + 0x10);
    uVar3 = (uint)DAT_803db410;
    iVar4 = *(int *)(param_1 + 0x7a);
    *(uint *)(param_1 + 0x7a) = iVar4 - uVar3;
    if ((int)(iVar4 - uVar3) < 0) {
      FUN_8002cbc4(param_1);
    }
  }
  else {
    if ((*(byte *)(iVar4 + 0x36) & 2) == 0) {
      FUN_800066e0(param_1,param_1,1,0,0,0);
      *(byte *)(iVar4 + 0x36) = *(byte *)(iVar4 + 0x36) | 2;
    }
    fVar1 = FLOAT_803e51b8;
    *(float *)(param_1 + 0x12) = FLOAT_803e51b8;
    *(float *)(param_1 + 0x14) = fVar1;
    *(float *)(param_1 + 0x16) = fVar1;
    FUN_80035dac(param_1);
    *(short *)(iVar4 + 0x32) = *(short *)(iVar4 + 0x32) + -1;
    if (*(short *)(iVar4 + 0x32) < 1) {
      FUN_8002cbc4(param_1);
    }
  }
  return;
}

