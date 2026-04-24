// Function: FUN_80170228
// Entry: 80170228
// Size: 164 bytes

void FUN_80170228(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8008016c(iVar1 + 4);
  *(float *)(iVar1 + 8) =
       ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
               DOUBLE_803e3398) / FLOAT_803e33a0) * FLOAT_803dbd60;
  *(float *)(param_1 + 0x28) = FLOAT_803e338c;
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  *(undefined4 *)(iVar1 + 0x10) = 1;
  FUN_80035f00(param_1);
  return;
}

