// Function: FUN_8020a658
// Entry: 8020a658
// Size: 164 bytes

void FUN_8020a658(int param_1)

{
  uint uVar1;
  int iVar2;
  
  if (param_1 != 0) {
    iVar2 = *(int *)(param_1 + 0xb8);
    uVar1 = FUN_80020078(*(uint *)(iVar2 + 8));
    if (uVar1 == 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,*(undefined4 *)(iVar2 + 4),0,4,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,*(undefined4 *)(iVar2 + 4),0,1,0xffffffff,0);
    }
  }
  return;
}

