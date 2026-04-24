// Function: FUN_80048d20
// Entry: 80048d20
// Size: 88 bytes

void FUN_80048d20(int param_1,int *param_2,int *param_3,undefined4 *param_4,int param_5)

{
  int iVar1;
  
  if (DAT_803600bc == 0) {
    return;
  }
  if (DAT_803600c0 == 0) {
    return;
  }
  iVar1 = DAT_803600bc + param_1;
  *param_2 = (int)*(short *)(iVar1 + 0x1c);
  *param_3 = (int)*(short *)(iVar1 + 0x1e);
  *param_4 = *(undefined4 *)(DAT_803600bc + *(int *)(DAT_803600c0 + param_5 * 4 + 0x18) + 4);
  return;
}

