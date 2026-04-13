// Function: FUN_80043658
// Entry: 80043658
// Size: 40 bytes

int FUN_80043658(undefined4 param_1,int param_2)

{
  if ((&DAT_803dc210)[param_2] == -2) {
    (&DAT_803dc210)[param_2] = param_1;
    return -1;
  }
  return (&DAT_803dc210)[param_2];
}

