// Function: FUN_8026f070
// Entry: 8026f070
// Size: 196 bytes

void FUN_8026f070(uint param_1)

{
  undefined4 *puVar1;
  uint uVar2;
  
  if (*(int *)(DAT_803dee98 + 0x14e4) == 0) {
    uVar2 = 0;
    do {
      puVar1 = (undefined4 *)FUN_8026e5bc((byte)uVar2);
      if (puVar1 != (undefined4 *)0x0) {
        FUN_8026e7d4(DAT_803dee98 + 0x14e8,puVar1);
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x40);
  }
  else {
    uVar2 = 0;
    do {
      if (((param_1 & 0xff) == (uint)*(byte *)(*(int *)(DAT_803dee98 + 0x14e4) + uVar2)) &&
         (puVar1 = (undefined4 *)FUN_8026e5bc((byte)uVar2), puVar1 != (undefined4 *)0x0)) {
        FUN_8026e7d4(DAT_803dee98 + (param_1 & 0xff) * 0x38 + 0x14e8,puVar1);
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x40);
  }
  return;
}

