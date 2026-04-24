// Function: FUN_8026c320
// Entry: 8026c320
// Size: 96 bytes

void FUN_8026c320(int *param_1)

{
  bool bVar1;
  
  if (*param_1 != 0) {
    *(int *)(*param_1 + 4) = param_1[1];
  }
  if ((int *)param_1[1] == (int *)0x0) {
    *(int *)(DAT_803de218 + 0xe6c) = *param_1;
  }
  else {
    *(int *)param_1[1] = *param_1;
  }
  bVar1 = DAT_803de21c != (int *)0x0;
  *param_1 = (int)DAT_803de21c;
  if (bVar1) {
    *(int **)((int)DAT_803de21c + 4) = param_1;
  }
  param_1[1] = 0;
  DAT_803de21c = param_1;
  return;
}

