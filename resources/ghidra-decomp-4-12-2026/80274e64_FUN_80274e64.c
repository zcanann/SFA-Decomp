// Function: FUN_80274e64
// Entry: 80274e64
// Size: 152 bytes

undefined4 FUN_80274e64(short param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  short *psVar3;
  
  puVar2 = &DAT_803c08d8;
  uVar1 = (uint)DAT_803def08;
  do {
    if (uVar1 == 0) {
      return 0;
    }
    for (psVar3 = (short *)*puVar2; *psVar3 != -1; psVar3 = psVar3 + 0x10) {
      if ((*psVar3 == param_1) && (psVar3[1] != -1)) {
        psVar3[1] = psVar3[1] + -1;
        if (psVar3[1] == 0) {
          FUN_802845f4((int)(psVar3 + 6),*(undefined4 *)(psVar3 + 4));
        }
        return 1;
      }
    }
    puVar2 = puVar2 + 3;
    uVar1 = uVar1 - 1;
  } while( true );
}

