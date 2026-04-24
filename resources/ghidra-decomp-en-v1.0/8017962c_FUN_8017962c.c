// Function: FUN_8017962c
// Entry: 8017962c
// Size: 36 bytes

void FUN_8017962c(int param_1)

{
  char cVar1;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 0x274);
  if ((cVar1 != '\x03') && (cVar1 != '\x02')) {
    return;
  }
  *(float *)(*(int *)(param_1 + 0xb8) + 0x26c) = FLOAT_803e369c;
  return;
}

