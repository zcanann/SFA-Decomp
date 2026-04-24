// Function: FUN_8026d060
// Entry: 8026d060
// Size: 100 bytes

void FUN_8026d060(int *param_1)

{
  bool bVar1;
  
  if ((int *)param_1[1] == (int *)0x0) {
    DAT_803de234 = *param_1;
  }
  else {
    *(int *)param_1[1] = *param_1;
  }
  if (*param_1 != 0) {
    *(int *)(*param_1 + 4) = param_1[1];
  }
  bVar1 = DAT_803de230 != (int *)0x0;
  *param_1 = (int)DAT_803de230;
  if (bVar1) {
    *(int **)((int)DAT_803de230 + 4) = param_1;
  }
  param_1[1] = 0;
  DAT_803de230 = param_1;
  *(undefined *)(param_1 + 2) = 2;
  return;
}

