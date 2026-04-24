// Function: FUN_801e8ea8
// Entry: 801e8ea8
// Size: 160 bytes

void FUN_801e8ea8(int param_1)

{
  uint uVar1;
  byte bVar2;
  int iVar3;
  
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  if (*(short *)(param_1 + 0x46) == 0x468) {
    iVar3 = *(int *)(param_1 + 0xb8);
    for (bVar2 = 0; bVar2 < 10; bVar2 = bVar2 + 1) {
      uVar1 = *(uint *)(iVar3 + (uint)bVar2 * 4 + 0x98);
      if (uVar1 != 0) {
        FUN_8008ff08(uVar1);
      }
    }
    FUN_8003709c(param_1,0x4f);
  }
  return;
}

