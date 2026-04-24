// Function: FUN_801a90a0
// Entry: 801a90a0
// Size: 168 bytes

void FUN_801a90a0(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = *(undefined4 *)(param_1 + 0xb8);
  iVar1 = *(int *)(param_1 + 200);
  if (iVar1 != 0) {
    FUN_80037cb0(param_1,iVar1);
    FUN_8002cbc4(iVar1);
  }
  (**(code **)(*DAT_803dca54 + 0x24))(uVar2);
  (**(code **)(*DAT_803dca74 + 8))(param_1,0xffff,0,0,0);
  FUN_8000b7bc(param_1,0x7f);
  return;
}

