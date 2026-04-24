// Function: FUN_80179af4
// Entry: 80179af4
// Size: 36 bytes

void FUN_80179af4(int param_1)

{
  char cVar1;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 0x274);
  if ((cVar1 != '\x03') && (cVar1 != '\x02')) {
    return;
  }
  *(float *)(*(int *)(param_1 + 0xb8) + 0x26c) = FLOAT_803e4334;
  return;
}

