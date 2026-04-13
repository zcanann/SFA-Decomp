// Function: FUN_801e2508
// Entry: 801e2508
// Size: 196 bytes

void FUN_801e2508(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (DAT_803de898 != 0) {
    FUN_80054484();
    DAT_803de898 = 0;
  }
  if (DAT_803de89c != 0) {
    FUN_80054484();
    DAT_803de89c = 0;
  }
  FUN_8003709c(param_1,3);
  if ((*(char *)(iVar1 + 0x80) != '\0') && (param_2 == 0)) {
    *(undefined *)(iVar1 + 0x80) = 0;
  }
  DAT_803de8a0 = 0;
  FUN_8000a538(*(int **)(iVar1 + 0x9c),0);
  FUN_8000a538(*(int **)(iVar1 + 0x98),0);
  FUN_800201ac(0xac8,1);
  return;
}

