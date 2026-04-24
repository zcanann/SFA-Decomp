// Function: FUN_801722a4
// Entry: 801722a4
// Size: 92 bytes

void FUN_801722a4(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar2 + 0xf) = (char)param_2;
  if (param_2 == 0) {
    uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x10));
    if (uVar1 == 0) {
      FUN_80036018(param_1);
    }
  }
  else {
    FUN_80035ff8(param_1);
  }
  return;
}

