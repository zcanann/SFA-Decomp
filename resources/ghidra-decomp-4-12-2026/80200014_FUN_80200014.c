// Function: FUN_80200014
// Entry: 80200014
// Size: 60 bytes

void FUN_80200014(int param_1)

{
  char cVar1;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 8);
  if ((cVar1 != '\0') && (cVar1 != '\x04')) {
    FUN_8003b9ec(param_1);
  }
  return;
}

