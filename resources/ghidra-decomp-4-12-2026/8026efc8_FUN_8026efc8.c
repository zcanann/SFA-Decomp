// Function: FUN_8026efc8
// Entry: 8026efc8
// Size: 168 bytes

void FUN_8026efc8(void)

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
      puVar1 = (undefined4 *)FUN_8026e5bc((byte)uVar2);
      if (puVar1 != (undefined4 *)0x0) {
        FUN_8026e7d4(DAT_803dee98 +
                     (uint)*(byte *)(*(int *)(DAT_803dee98 + 0x14e4) + uVar2) * 0x38 + 0x14e8,puVar1
                    );
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x40);
  }
  return;
}

