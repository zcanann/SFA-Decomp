// Function: FUN_80059bcc
// Entry: 80059bcc
// Size: 112 bytes

void FUN_80059bcc(int param_1)

{
  if ((&DAT_803870c8)[param_1] != 0) {
    FUN_800598a8();
    FUN_800238c4((&DAT_803870c8)[param_1]);
    (&DAT_803870c8)[param_1] = 0;
  }
  return;
}

