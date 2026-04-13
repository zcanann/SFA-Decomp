// Function: FUN_801d3970
// Entry: 801d3970
// Size: 84 bytes

void FUN_801d3970(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  uVar1 = *(uint *)(iVar2 + 0x270);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *(undefined4 *)(iVar2 + 0x270) = 0;
  }
  return;
}

