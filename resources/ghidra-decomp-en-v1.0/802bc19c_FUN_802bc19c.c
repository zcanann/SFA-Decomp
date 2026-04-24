// Function: FUN_802bc19c
// Entry: 802bc19c
// Size: 224 bytes

undefined4 FUN_802bc19c(int param_1,uint *param_2)

{
  float fVar1;
  undefined2 uVar2;
  int iVar3;
  
  fVar1 = FLOAT_803e82c0;
  iVar3 = *(int *)(param_1 + 0xb8);
  param_2[0xa5] = (uint)FLOAT_803e82c0;
  param_2[0xa1] = (uint)fVar1;
  param_2[0xa0] = (uint)fVar1;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  *param_2 = *param_2 | 0x200000;
  param_2[0xa8] = (uint)FLOAT_803e82c4;
  if (*(short *)(param_1 + 0xa0) != 0) {
    FUN_80030334(param_1,0,0);
  }
  uVar2 = FUN_800221a0(0x4b0,0x960);
  *(undefined2 *)(iVar3 + 0x38c) = uVar2;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    FUN_80014b3c(0,0x100);
  }
  return 0;
}

