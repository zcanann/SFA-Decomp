// Function: FUN_80192d50
// Entry: 80192d50
// Size: 124 bytes

void FUN_80192d50(int param_1)

{
  DAT_803de768 = DAT_803de768 + -1;
  if (DAT_803de768 == '\0') {
    if (DAT_803de774 != 0) {
      FUN_800238c4(DAT_803de774);
    }
    if (DAT_803de770 != 0) {
      FUN_800238c4(DAT_803de770);
    }
    if (DAT_803de76c != 0) {
      FUN_800238c4(DAT_803de76c);
    }
  }
  FUN_8003709c(param_1,0x1b);
  return;
}

