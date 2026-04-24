// Function: FUN_8017b064
// Entry: 8017b064
// Size: 268 bytes

void FUN_8017b064(int param_1,int param_2)

{
  uint uVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  if (*(byte *)(param_2 + 0x1d) == 0) {
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(param_1 + 0x50) + 4);
  }
  else {
    *(float *)(param_1 + 8) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1d)) - DOUBLE_803e43d8) *
         *(float *)(*(int *)(param_1 + 0x50) + 4) * FLOAT_803e43e8;
  }
  FUN_80035a6c(param_1,(short)((int)((uint)*(byte *)(param_2 + 0x1d) *
                                    (uint)*(byte *)(*(int *)(param_1 + 0x50) + 0x62)) >> 6));
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x18));
  *puVar2 = (char)uVar1;
  uVar1 = (int)(*(byte *)(param_2 + 0x23) & 0xe) >> 1;
  if (uVar1 == 1) {
    puVar2[1] = 0x10;
  }
  else if ((uVar1 == 0) || (2 < uVar1)) {
    puVar2[1] = 5;
  }
  else {
    puVar2[1] = 0x15;
  }
  return;
}

