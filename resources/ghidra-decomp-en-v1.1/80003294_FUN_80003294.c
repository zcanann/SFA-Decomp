// Function: FUN_80003294
// Entry: 80003294
// Size: 192 bytes

void FUN_80003294(void)

{
  undefined **ppuVar1;
  undefined *puVar2;
  undefined *puVar3;
  
  ppuVar1 = &PTR_FUN_80005570;
  while( true ) {
    puVar2 = ppuVar1[2];
    if (puVar2 == (undefined *)0x0) break;
    puVar3 = ppuVar1[1];
    if ((puVar2 != (undefined *)0x0) && (puVar3 != *ppuVar1)) {
      FUN_80003494((uint)puVar3,(uint)*ppuVar1,(int)puVar2);
      FUN_80003374((uint)puVar3,(int)puVar2);
    }
    ppuVar1 = ppuVar1 + 3;
  }
  ppuVar1 = &PTR_DAT_800055f4;
  while( true ) {
    puVar2 = ppuVar1[1];
    if (puVar2 == (undefined *)0x0) break;
    if (puVar2 != (undefined *)0x0) {
      FUN_800033a8((int)*ppuVar1,0,(uint)puVar2);
    }
    ppuVar1 = ppuVar1 + 2;
  }
  return;
}

