// Function: FUN_80162b0c
// Entry: 80162b0c
// Size: 252 bytes

void FUN_80162b0c(int param_1)

{
  char in_r8;
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b8f4((double)FLOAT_803e2ebc);
    if (FLOAT_803e2eb8 < *(float *)(iVar1 + 0x50)) {
      (**(code **)(*DAT_803dcab4 + 0xc))(param_1,0x52a,0,100,0);
    }
    if ((*(ushort *)(iVar2 + 0x400) & 0x60) != 0) {
      FUN_80099d84((double)FLOAT_803e2ebc,(double)*(float *)(iVar2 + 1000),param_1,3,0);
    }
    if ((*(ushort *)(iVar2 + 0x400) & 0x100) != 0) {
      FUN_80099d84((double)FLOAT_803e2ebc,(double)*(float *)(iVar2 + 1000),param_1,4,0);
      *(ushort *)(iVar2 + 0x400) = *(ushort *)(iVar2 + 0x400) & 0xfeff;
    }
  }
  return;
}

