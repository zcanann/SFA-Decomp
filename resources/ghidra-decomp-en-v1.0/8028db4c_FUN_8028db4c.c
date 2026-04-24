// Function: FUN_8028db4c
// Entry: 8028db4c
// Size: 152 bytes

void FUN_8028db4c(void)

{
  undefined *puVar1;
  undefined *puVar2;
  
  puVar1 = &DAT_80332380;
  while( true ) {
    puVar2 = puVar1;
    if (puVar2 == (undefined *)0x0) break;
    if ((*(ushort *)(puVar2 + 4) >> 6 & 7) != 0) {
      FUN_8028ed58(puVar2);
    }
    puVar1 = *(undefined **)(puVar2 + 0x4c);
    if (puVar2[0xc] == '\0') {
      *(ushort *)(puVar2 + 4) = *(ushort *)(puVar2 + 4) & 0xfe3f | 0xc0;
      if ((puVar1 != (undefined *)0x0) && (puVar1[0xc] != '\0')) {
        *(undefined4 *)(puVar2 + 0x4c) = 0;
      }
    }
    else {
      FUN_8028d574();
    }
  }
  return;
}

