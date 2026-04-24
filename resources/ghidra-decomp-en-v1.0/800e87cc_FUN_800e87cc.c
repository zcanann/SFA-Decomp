// Function: FUN_800e87cc
// Entry: 800e87cc
// Size: 192 bytes

int FUN_800e87cc(undefined param_1)

{
  int iVar1;
  
  DAT_803db890 = param_1;
  FUN_800033a8(&DAT_803a32a8,0,0xf70);
  if ((*(byte *)(DAT_803dd498 + 0x21) & 0x80) == 0) {
    FUN_800033a8(DAT_803dd498,0,0x6ec);
  }
  iVar1 = FUN_8007dc5c(DAT_803db890,DAT_803dd498);
  if (iVar1 == 0) {
    FUN_800e8abc(&DAT_803db894,0xffffffff);
  }
  else if (*(char *)(DAT_803dd498 + 0x21) == '\0') {
    iVar1 = FUN_800e8abc(&DAT_803db894,DAT_803db890);
  }
  else {
    FUN_80003494(&DAT_803a32a8,DAT_803dd498,0x6ec);
  }
  return iVar1;
}

