// Function: FUN_80043560
// Entry: 80043560
// Size: 40 bytes

int FUN_80043560(undefined4 param_1,int param_2)

{
  if ((&DAT_803db5b0)[param_2] == -2) {
    (&DAT_803db5b0)[param_2] = param_1;
    return -1;
  }
  return (&DAT_803db5b0)[param_2];
}

