// Function: FUN_8026ca84
// Entry: 8026ca84
// Size: 96 bytes

void FUN_8026ca84(int *param_1)

{
  bool bVar1;
  
  if (*param_1 != 0) {
    *(int *)(*param_1 + 4) = param_1[1];
  }
  if ((int *)param_1[1] == (int *)0x0) {
    *(int *)(DAT_803dee98 + 0xe6c) = *param_1;
  }
  else {
    *(int *)param_1[1] = *param_1;
  }
  bVar1 = DAT_803dee9c != (int *)0x0;
  *param_1 = (int)DAT_803dee9c;
  if (bVar1) {
    *(int **)((int)DAT_803dee9c + 4) = param_1;
  }
  param_1[1] = 0;
  DAT_803dee9c = param_1;
  return;
}

