// Function: FUN_8002b884
// Entry: 8002b884
// Size: 68 bytes

void FUN_8002b884(int param_1,int param_2)

{
  int iVar1;
  
  if (param_2 == *(char *)(param_1 + 0xad)) {
    return;
  }
  if (param_2 < 0) {
    param_2 = 0;
  }
  else {
    iVar1 = (int)*(char *)(*(int *)(param_1 + 0x50) + 0x55);
    if (iVar1 <= param_2) {
      param_2 = iVar1 + -1;
    }
  }
  *(char *)(param_1 + 0xad) = (char)param_2;
  return;
}

