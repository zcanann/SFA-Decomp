// Function: FUN_800278e4
// Entry: 800278e4
// Size: 156 bytes

undefined4 FUN_800278e4(int *param_1)

{
  float *pfVar1;
  
  if (*(int *)(*param_1 + 0xdc) == 0) {
    return 0;
  }
  pfVar1 = (float *)param_1[10];
  if ((*pfVar1 == pfVar1[1]) && ((*(byte *)((int)pfVar1 + 0xe) & 0xe) == 0)) {
    if ((pfVar1[4] == pfVar1[5]) && ((*(byte *)((int)pfVar1 + 0x1e) & 0xe) == 0)) {
      if ((pfVar1[8] == pfVar1[9]) && ((*(byte *)((int)pfVar1 + 0x2e) & 0xe) == 0)) {
        return 0;
      }
      return 1;
    }
    return 1;
  }
  return 1;
}

