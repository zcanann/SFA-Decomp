// Function: FUN_801804a0
// Entry: 801804a0
// Size: 136 bytes

void FUN_801804a0(int param_1,undefined4 param_2,byte *param_3,int param_4,int param_5)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_80180528(param_1,iVar2,param_3,param_4,param_5);
  if (iVar1 == 0) {
    if (*(char *)(iVar2 + 1) != '\0') {
      *(undefined *)(iVar2 + 1) = 0;
      FUN_8003709c(param_1,0x4b);
    }
  }
  else if (*(char *)(iVar2 + 1) == '\0') {
    *(undefined *)(iVar2 + 1) = 1;
    FUN_800372f8(param_1,0x4b);
  }
  return;
}

