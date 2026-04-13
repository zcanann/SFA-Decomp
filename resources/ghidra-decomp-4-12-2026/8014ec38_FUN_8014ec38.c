// Function: FUN_8014ec38
// Entry: 8014ec38
// Size: 232 bytes

void FUN_8014ec38(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b9ec(param_1);
    if ((*(byte *)(iVar1 + 0x26) & 0x10) != 0) {
      FUN_8009a010((double)FLOAT_803e32e8,
                   (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) -
                                   DOUBLE_803e32d8) / FLOAT_803e32ec),param_1,3,(int *)0x0);
    }
    if ((*(byte *)(iVar1 + 0x26) & 8) != 0) {
      FUN_8009a010((double)FLOAT_803e32e8,
                   (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) -
                                   DOUBLE_803e32d8) / FLOAT_803e32ec),param_1,4,(int *)0x0);
    }
  }
  return;
}

