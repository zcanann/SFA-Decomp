// Function: FUN_8028d6fc
// Entry: 8028d6fc
// Size: 240 bytes

int FUN_8028d6fc(undefined *param_1)

{
  undefined1 *puVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = 4;
  if (DAT_803d94f0 <= DAT_803d94ec) {
    DAT_803d94ec = 0;
    DAT_803d94f0 = (*DAT_80332fc8)();
    if (0 < DAT_803d94f0) {
      if (0x110a < DAT_803d94f0) {
        DAT_803d94f0 = 0x110a;
      }
      uVar2 = (*DAT_80332fcc)(&DAT_803d94f8,DAT_803d94f0);
      iVar3 = (int)(-uVar2 | uVar2) >> 0x1f;
      if ((int)(-uVar2 | uVar2) < 0) {
        DAT_803d94f0 = 0;
      }
    }
  }
  if (DAT_803d94ec < DAT_803d94f0) {
    iVar3 = 0;
    puVar1 = &DAT_803d94f8 + DAT_803d94ec;
    DAT_803d94ec = DAT_803d94ec + 1;
    *param_1 = *puVar1;
  }
  return iVar3;
}

