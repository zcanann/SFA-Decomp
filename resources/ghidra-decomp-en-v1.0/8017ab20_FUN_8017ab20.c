// Function: FUN_8017ab20
// Entry: 8017ab20
// Size: 268 bytes

void FUN_8017ab20(int param_1,int param_2)

{
  uint uVar1;
  undefined uVar2;
  undefined *puVar3;
  
  puVar3 = *(undefined **)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  if (*(byte *)(param_2 + 0x1d) == 0) {
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(param_1 + 0x50) + 4);
  }
  else {
    *(float *)(param_1 + 8) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1d)) - DOUBLE_803e3740) *
         *(float *)(*(int *)(param_1 + 0x50) + 4) * FLOAT_803e3750;
  }
  FUN_80035974(param_1,(short)((int)((uint)*(byte *)(param_2 + 0x1d) *
                                    (uint)*(byte *)(*(int *)(param_1 + 0x50) + 0x62)) >> 6));
  uVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 0x18));
  *puVar3 = uVar2;
  uVar1 = (int)(*(byte *)(param_2 + 0x23) & 0xe) >> 1;
  if (uVar1 == 1) {
    puVar3[1] = 0x10;
  }
  else if ((uVar1 == 0) || (2 < uVar1)) {
    puVar3[1] = 5;
  }
  else {
    puVar3[1] = 0x15;
  }
  return;
}

