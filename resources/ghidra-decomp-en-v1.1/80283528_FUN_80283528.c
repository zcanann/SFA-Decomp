// Function: FUN_80283528
// Entry: 80283528
// Size: 152 bytes

void FUN_80283528(int param_1,uint param_2,short param_3)

{
  uint uVar1;
  
  if (param_3 < 0) {
    param_3 = 0;
  }
  else if (0x3fff < param_3) {
    param_3 = 0x3fff;
  }
  uVar1 = FUN_80283418(param_2);
  if (((0xa1 < (uVar1 & 0xff)) || ((uVar1 & 0xff) < 0xa0)) && (*(byte *)(param_1 + 0x121) != 0xff))
  {
    FUN_8028206c((byte)param_2,*(byte *)(param_1 + 0x121),*(byte *)(param_1 + 0x122),(int)param_3);
  }
  return;
}

