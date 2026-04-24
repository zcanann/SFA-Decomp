// Function: FUN_80171df8
// Entry: 80171df8
// Size: 92 bytes

void FUN_80171df8(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar1 + 0xf) = (char)param_2;
  if (param_2 == 0) {
    iVar1 = FUN_8001ffb4((int)*(short *)(iVar1 + 0x10));
    if (iVar1 == 0) {
      FUN_80035f20(param_1);
    }
  }
  else {
    FUN_80035f00();
  }
  return;
}

