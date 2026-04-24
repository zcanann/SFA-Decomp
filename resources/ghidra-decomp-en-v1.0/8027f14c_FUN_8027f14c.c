// Function: FUN_8027f14c
// Entry: 8027f14c
// Size: 352 bytes

void FUN_8027f14c(void)

{
  undefined4 *puVar1;
  int iVar2;
  byte bVar3;
  int local_20;
  int local_1c;
  int local_18;
  
  puVar1 = &DAT_803cc1e0;
  for (bVar3 = 0; bVar3 < DAT_803de37c; bVar3 = bVar3 + 1) {
    if (*(char *)(puVar1 + 0x14) == '\x01') {
      if (puVar1[0x2b] != 0) {
        iVar2 = puVar1[(DAT_803de37e + 2) % 3 + 0xc];
        local_1c = iVar2 + 0x280;
        local_18 = iVar2 + 0x500;
        local_20 = iVar2;
        (*(code *)puVar1[0x2b])(0,&local_20,puVar1[0x2d]);
        FUN_80241a50(iVar2,0x780);
      }
      if ((puVar1[0x15] == 0) && (puVar1[0x2c] != 0)) {
        iVar2 = puVar1[(DAT_803de37e + 2) % 3 + 0xf];
        local_1c = iVar2 + 0x280;
        local_18 = iVar2 + 0x500;
        local_20 = iVar2;
        (*(code *)puVar1[0x2c])(0,&local_20,puVar1[0x2e]);
        FUN_80241a50(iVar2,0x780);
      }
    }
    puVar1 = puVar1 + 0x2f;
  }
  return;
}

