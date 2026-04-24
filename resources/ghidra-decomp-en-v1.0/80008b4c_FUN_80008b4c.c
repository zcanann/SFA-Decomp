// Function: FUN_80008b4c
// Entry: 80008b4c
// Size: 32 bytes

int FUN_80008b4c(int param_1)

{
  if (param_1 != -1) {
    DAT_803dc7b4 = param_1;
    return (int)(short)param_1;
  }
  return (int)(short)DAT_803dc7b4;
}

