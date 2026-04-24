// Function: FUN_80037fa4
// Entry: 80037fa4
// Size: 128 bytes

undefined4 FUN_80037fa4(int param_1,short param_2)

{
  int iVar1;
  
  if ((((*(byte *)(param_1 + 0xaf) & 4) != 0) && ((*(byte *)(param_1 + 0xaf) & 0x10) == 0)) &&
     (iVar1 = (**(code **)(*DAT_803dca68 + 0x20))((int)param_2), iVar1 != 0)) {
    FUN_8002b9ec();
    iVar1 = FUN_80296ba0();
    if (iVar1 == -1) {
      FUN_80014b3c(0,0x100);
      return 1;
    }
  }
  return 0;
}

