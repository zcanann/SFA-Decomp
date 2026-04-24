// Function: FUN_802003b4
// Entry: 802003b4
// Size: 148 bytes

void FUN_802003b4(int param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar3 + 8) = 5;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x10);
  fVar1 = FLOAT_803e6f14;
  *(float *)(param_1 + 0x2c) = FLOAT_803e6f14;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = FLOAT_803e6f38;
  uVar2 = FUN_80022264(0,0xffff);
  *(uint *)(iVar3 + 4) = uVar2;
  uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x20));
  if (uVar2 != 0) {
    *(undefined *)(iVar3 + 8) = 4;
  }
  return;
}

