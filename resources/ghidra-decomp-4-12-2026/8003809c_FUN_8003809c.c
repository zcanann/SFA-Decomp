// Function: FUN_8003809c
// Entry: 8003809c
// Size: 128 bytes

undefined4 FUN_8003809c(int param_1,short param_2)

{
  int iVar1;
  
  if ((((*(byte *)(param_1 + 0xaf) & 4) != 0) && ((*(byte *)(param_1 + 0xaf) & 0x10) == 0)) &&
     (iVar1 = (**(code **)(*DAT_803dd6e8 + 0x20))((int)param_2), iVar1 != 0)) {
    iVar1 = FUN_8002bac4();
    iVar1 = FUN_80297300(iVar1);
    if (iVar1 == -1) {
      FUN_80014b68(0,0x100);
      return 1;
    }
  }
  return 0;
}

