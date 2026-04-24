// Function: FUN_801a1e50
// Entry: 801a1e50
// Size: 196 bytes

void FUN_801a1e50(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd740 + 0x10))();
  if (((*(int *)(iVar2 + 0x10) != 0) && (param_2 == 0)) &&
     (iVar1 = FUN_80037ad4(*(int *)(iVar2 + 0x10)), iVar1 != 0)) {
    FUN_80037da8(param_1,*(int *)(iVar2 + 0x10));
    *(undefined4 *)(iVar2 + 0x10) = 0;
  }
  FUN_8003709c(param_1,0x19);
  FUN_8003709c(param_1,0x16);
  if (*(char *)(iVar2 + 0x17) != '\0') {
    (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  }
  return;
}

