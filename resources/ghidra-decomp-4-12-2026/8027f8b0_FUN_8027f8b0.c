// Function: FUN_8027f8b0
// Entry: 8027f8b0
// Size: 352 bytes

void FUN_8027f8b0(void)

{
  undefined4 *puVar1;
  uint uVar2;
  byte bVar3;
  uint local_20;
  int local_1c;
  int local_18;
  
  puVar1 = &DAT_803cce40;
  for (bVar3 = 0; bVar3 < DAT_803deffc; bVar3 = bVar3 + 1) {
    if (*(char *)(puVar1 + 0x14) == '\x01') {
      if (puVar1[0x2b] != 0) {
        uVar2 = puVar1[(DAT_803deffe + 2) % 3 + 0xc];
        local_1c = uVar2 + 0x280;
        local_18 = uVar2 + 0x500;
        local_20 = uVar2;
        (*(code *)puVar1[0x2b])(0,&local_20,puVar1[0x2d]);
        FUN_80242148(uVar2,0x780);
      }
      if ((puVar1[0x15] == 0) && (puVar1[0x2c] != 0)) {
        uVar2 = puVar1[(DAT_803deffe + 2) % 3 + 0xf];
        local_1c = uVar2 + 0x280;
        local_18 = uVar2 + 0x500;
        local_20 = uVar2;
        (*(code *)puVar1[0x2c])(0,&local_20,puVar1[0x2e]);
        FUN_80242148(uVar2,0x780);
      }
    }
    puVar1 = puVar1 + 0x2f;
  }
  return;
}

