// Function: FUN_8009305c
// Entry: 8009305c
// Size: 180 bytes

void FUN_8009305c(void)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = 0;
  piVar2 = &DAT_8039a828;
  do {
    if (*piVar2 != 0) {
      FUN_80090078(iVar1);
    }
    *piVar2 = 0;
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 8);
  FLOAT_803dd1bc = FLOAT_803df1a0;
  FLOAT_803dd1b8 = FLOAT_803df1a0;
  FLOAT_803dd1b4 = FLOAT_803df1a0;
  FLOAT_803dd190 = FLOAT_803df1a0;
  FLOAT_803db760 = FLOAT_803df1a4;
  FLOAT_803dd194 = FLOAT_803df1a0;
  DAT_803dd198 = 0;
  FLOAT_803db764 = FLOAT_803df1a4;
  DAT_803dd199 = 0;
  DAT_803dd19a = 0;
  FLOAT_803db768 = FLOAT_803df1a4;
  DAT_803dd1cc = 0;
  FUN_8000a518(0xeb,0);
  return;
}

