// Function: FUN_801ff9dc
// Entry: 801ff9dc
// Size: 60 bytes

void FUN_801ff9dc(int param_1)

{
  char cVar1;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 8);
  if ((cVar1 != '\0') && (cVar1 != '\x04')) {
    FUN_8003b8f4((double)FLOAT_803e6278);
  }
  return;
}

