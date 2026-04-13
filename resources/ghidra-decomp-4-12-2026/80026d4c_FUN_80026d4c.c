// Function: FUN_80026d4c
// Entry: 80026d4c
// Size: 116 bytes

void FUN_80026d4c(uint *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  for (iVar1 = 0; iVar1 < (int)param_1[1]; iVar1 = iVar1 + 1) {
    FUN_800238c4(*(uint *)(*param_1 + iVar2));
    iVar2 = iVar2 + 0xc;
  }
  FUN_800238c4(*param_1);
  FUN_800238c4((uint)param_1);
  return;
}

