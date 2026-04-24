// Function: FUN_80134c28
// Entry: 80134c28
// Size: 280 bytes

void FUN_80134c28(char param_1)

{
  short *psVar1;
  int iVar2;
  
  if (param_1 == '\0') {
    if (DAT_803dd9a0 == '\0') {
      FLOAT_803dd99c = FLOAT_803e2318;
      if (FLOAT_803e231c < FLOAT_803dd9b4) {
        DAT_803dd9a0 = '\x01';
      }
    }
    else {
      FLOAT_803dd99c = FLOAT_803dd9b4;
    }
  }
  else {
    FLOAT_803dd99c = FLOAT_803e2318;
    DAT_803dd9a0 = '\0';
  }
  psVar1 = (short *)FUN_80019570(0x3d9);
  if (*psVar1 != -1) {
    iVar2 = FUN_800173c8(*(undefined *)(psVar1 + 2));
    if (DAT_803dd9ac == 0) {
      DAT_803dd9ac = (uint)*(short *)(iVar2 + 0x16);
    }
    *(short *)(iVar2 + 0x16) =
         (short)(int)(FLOAT_803e2320 * (FLOAT_803e2318 - FLOAT_803dd99c) +
                     (float)((double)CONCAT44(0x43300000,DAT_803dd9ac ^ 0x80000000) -
                            DOUBLE_803e22e8));
    FUN_80019908(0xff,0xff,0xff,(int)(FLOAT_803e2324 * FLOAT_803dd9b0));
    FUN_80016870(0x3d9);
  }
  return;
}

