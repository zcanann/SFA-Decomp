// Function: FUN_80274700
// Entry: 80274700
// Size: 152 bytes

undefined4 FUN_80274700(short param_1)

{
  uint uVar1;
  short **ppsVar2;
  short *psVar3;
  
  ppsVar2 = (short **)&DAT_803bfc78;
  uVar1 = (uint)DAT_803de288;
  do {
    if (uVar1 == 0) {
      return 0;
    }
    for (psVar3 = *ppsVar2; *psVar3 != -1; psVar3 = psVar3 + 0x10) {
      if ((*psVar3 == param_1) && (psVar3[1] != -1)) {
        psVar3[1] = psVar3[1] + -1;
        if (psVar3[1] == 0) {
          FUN_80283e90(psVar3 + 6,*(undefined4 *)(psVar3 + 4));
        }
        return 1;
      }
    }
    ppsVar2 = ppsVar2 + 3;
    uVar1 = uVar1 - 1;
  } while( true );
}

