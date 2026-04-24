// Function: FUN_80121348
// Entry: 80121348
// Size: 192 bytes

void FUN_80121348(undefined4 param_1,undefined4 param_2,undefined2 param_3)

{
  undefined **ppuVar1;
  short *psVar2;
  undefined6 uVar3;
  
  uVar3 = FUN_802860dc();
  ppuVar1 = &PTR_DAT_8031b5d8;
  DAT_803a9398 = 0;
  do {
    psVar2 = (short *)*ppuVar1;
    if (psVar2 == (short *)0x0) {
      if (DAT_803a9398 != 0) {
        DAT_803a93a0 = FLOAT_803e1e3c;
        DAT_803a939c = (int)uVar3;
        DAT_803a93a4 = param_3;
      }
      FUN_80286128();
      return;
    }
    for (; *psVar2 != -1; psVar2 = psVar2 + 8) {
      if (*psVar2 == (short)((uint6)uVar3 >> 0x20)) {
        DAT_803a9398 = FUN_80054d54((int)psVar2[3]);
        break;
      }
    }
    ppuVar1 = (undefined **)((short **)ppuVar1 + 4);
  } while( true );
}

