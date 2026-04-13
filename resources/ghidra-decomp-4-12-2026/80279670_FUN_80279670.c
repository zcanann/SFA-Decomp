// Function: FUN_80279670
// Entry: 80279670
// Size: 248 bytes

int FUN_80279670(void)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int iVar5;
  
  puVar2 = &DAT_803caf30;
  DAT_803def78 = &DAT_803caf30;
  DAT_803def70 = 0;
  iVar5 = 0x10;
  puVar4 = (undefined4 *)0x0;
  DAT_803def74 = 0;
  iVar1 = 0;
  do {
    puVar2[1] = puVar4;
    if (puVar4 != (undefined4 *)0x0) {
      *puVar4 = puVar2;
    }
    puVar2[5] = puVar2;
    puVar4 = puVar2 + 4;
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = puVar4;
    }
    puVar2[9] = puVar4;
    puVar3 = puVar2 + 8;
    if (puVar4 != (undefined4 *)0x0) {
      *puVar4 = puVar3;
    }
    puVar2[0xd] = puVar3;
    puVar4 = puVar2 + 0xc;
    if (puVar3 != (undefined4 *)0x0) {
      *puVar3 = puVar4;
    }
    puVar2[0x11] = puVar4;
    puVar3 = puVar2 + 0x10;
    if (puVar4 != (undefined4 *)0x0) {
      *puVar4 = puVar3;
    }
    puVar2[0x15] = puVar3;
    puVar4 = puVar2 + 0x14;
    if (puVar3 != (undefined4 *)0x0) {
      *puVar3 = puVar4;
    }
    puVar2[0x19] = puVar4;
    puVar3 = puVar2 + 0x18;
    if (puVar4 != (undefined4 *)0x0) {
      *puVar4 = puVar3;
    }
    puVar2[0x1d] = puVar3;
    puVar4 = puVar2 + 0x1c;
    if (puVar3 != (undefined4 *)0x0) {
      *puVar3 = puVar4;
    }
    puVar2 = puVar2 + 0x20;
    iVar1 = iVar1 + 7;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  *puVar4 = 0;
  return iVar1;
}

