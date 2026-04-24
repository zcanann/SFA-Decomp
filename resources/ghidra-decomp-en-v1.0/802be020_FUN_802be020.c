// Function: FUN_802be020
// Entry: 802be020
// Size: 144 bytes

void FUN_802be020(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 0x14f8) != 0) {
    FUN_80026c88();
  }
  FUN_80036fa4(param_1,10);
  if ((*(byte *)(iVar1 + 0x14ec) >> 1 & 1) != 0) {
    (**(code **)(*DAT_803dca68 + 0x60))();
  }
  if (*(int *)(iVar1 + 0xb54) != 0) {
    FUN_80037cb0(param_1);
    FUN_8002cbc4(*(undefined4 *)(iVar1 + 0xb54));
  }
  return;
}

