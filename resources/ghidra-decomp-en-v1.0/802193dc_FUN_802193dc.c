// Function: FUN_802193dc
// Entry: 802193dc
// Size: 144 bytes

undefined4 FUN_802193dc(int param_1)

{
  int iVar1;
  
  FUN_8002b9ec();
  if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    FUN_80014b3c(0,0x100);
    iVar1 = (**(code **)(*DAT_803dca68 + 0x1c))();
    if (iVar1 == 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    }
  }
  return 0;
}

