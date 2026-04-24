// Function: FUN_8020a020
// Entry: 8020a020
// Size: 164 bytes

void FUN_8020a020(int param_1)

{
  int iVar1;
  int iVar2;
  
  if (param_1 != 0) {
    iVar2 = *(int *)(param_1 + 0xb8);
    iVar1 = FUN_8001ffb4(*(undefined4 *)(iVar2 + 8));
    if (iVar1 == 0) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,*(undefined4 *)(iVar2 + 4),0,4,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,*(undefined4 *)(iVar2 + 4),0,1,0xffffffff,0);
    }
  }
  return;
}

