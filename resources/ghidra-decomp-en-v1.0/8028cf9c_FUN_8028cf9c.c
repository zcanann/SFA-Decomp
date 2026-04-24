// Function: FUN_8028cf9c
// Entry: 8028cf9c
// Size: 240 bytes

int FUN_8028cf9c(undefined *param_1)

{
  undefined1 *puVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = 4;
  if (DAT_803d8890 <= DAT_803d888c) {
    DAT_803d888c = 0;
    DAT_803d8890 = (*DAT_80332368)();
    if (0 < DAT_803d8890) {
      if (0x110a < DAT_803d8890) {
        DAT_803d8890 = 0x110a;
      }
      uVar2 = (*DAT_8033236c)(&DAT_803d8898,DAT_803d8890);
      iVar3 = (int)(-uVar2 | uVar2) >> 0x1f;
      if ((int)(-uVar2 | uVar2) < 0) {
        DAT_803d8890 = 0;
      }
    }
  }
  if (DAT_803d888c < DAT_803d8890) {
    iVar3 = 0;
    puVar1 = &DAT_803d8898 + DAT_803d888c;
    DAT_803d888c = DAT_803d888c + 1;
    *param_1 = *puVar1;
  }
  return iVar3;
}

