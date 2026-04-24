// Function: FUN_8018afd0
// Entry: 8018afd0
// Size: 132 bytes

void FUN_8018afd0(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  char *pcVar4;
  
  pcVar4 = *(char **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  FUN_80014a28();
  iVar1 = FUN_8002b9ec();
  if ((iVar1 != 0) && (iVar1 = FUN_802966cc(), iVar1 != 0)) {
    FUN_8016d9ec(iVar1,5,0);
  }
  if ((*pcVar4 == '\x01') && (*(char *)(iVar3 + 0x22) == '\0')) {
    uVar2 = FUN_800481b0(*(undefined *)(iVar3 + 0x1f));
    FUN_800437bc(uVar2,0x20000000);
  }
  return;
}

