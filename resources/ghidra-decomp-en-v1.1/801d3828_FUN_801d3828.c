// Function: FUN_801d3828
// Entry: 801d3828
// Size: 320 bytes

void FUN_801d3828(undefined2 *param_1,int param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar3 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x1f) << 8);
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(code **)(param_1 + 0x5e) = FUN_801d2e5c;
  puVar3[3] = *(undefined4 *)(param_1 + 4);
  if (param_3 == 0) {
    if (((int)*(short *)(param_2 + 0x1c) == 0xffffffff) ||
       (uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1c)), uVar1 != 0)) {
      iVar2 = *(int *)(param_1 + 0x26);
      *(undefined *)(param_1 + 0x1b) = 0xff;
      param_1[3] = param_1[3] & 0xbfff;
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar2 + 8);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar2 + 0x10);
      FUN_8003613c((int)param_1);
    }
    else {
      iVar2 = *(int *)(param_1 + 0x26);
      *(undefined *)(param_1 + 0x1b) = 0xff;
      param_1[3] = param_1[3] & 0xbfff;
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar2 + 8);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar2 + 0x10);
      *(float *)(param_1 + 4) = FLOAT_803e5ff0;
      puVar3[2] = FLOAT_803e5ff4;
      puVar3[1] = puVar3[3];
      puVar3[4] = (float)puVar3[1] / (float)puVar3[2];
      *puVar3 = puVar3[2];
      FUN_8003613c((int)param_1);
      *(undefined *)(puVar3 + 5) = 1;
    }
  }
  return;
}

