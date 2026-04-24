// Function: FUN_8017ff48
// Entry: 8017ff48
// Size: 136 bytes

void FUN_8017ff48(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8017ffd0(param_1,iVar2);
  if (iVar1 == 0) {
    if (*(char *)(iVar2 + 1) != '\0') {
      *(undefined *)(iVar2 + 1) = 0;
      FUN_80036fa4(param_1,0x4b);
    }
  }
  else if (*(char *)(iVar2 + 1) == '\0') {
    *(undefined *)(iVar2 + 1) = 1;
    FUN_80037200(param_1,0x4b);
  }
  return;
}

