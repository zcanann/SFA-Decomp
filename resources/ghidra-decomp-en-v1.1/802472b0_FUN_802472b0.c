// Function: FUN_802472b0
// Entry: 802472b0
// Size: 260 bytes

void FUN_802472b0(int *param_1)

{
  int iVar1;
  int iVar2;
  
  FUN_80243e74();
  while (iVar2 = *param_1, iVar2 != 0) {
    iVar1 = *(int *)(iVar2 + 0x2e0);
    if (iVar1 == 0) {
      param_1[1] = 0;
    }
    else {
      *(undefined4 *)(iVar1 + 0x2e4) = 0;
    }
    *param_1 = iVar1;
    *(undefined2 *)(iVar2 + 0x2c8) = 1;
    if (*(int *)(iVar2 + 0x2cc) < 1) {
      *(undefined **)(iVar2 + 0x2dc) = &DAT_803ae098 + *(int *)(iVar2 + 0x2d0) * 8;
      iVar1 = (*(int **)(iVar2 + 0x2dc))[1];
      if (iVar1 == 0) {
        **(int **)(iVar2 + 0x2dc) = iVar2;
      }
      else {
        *(int *)(iVar1 + 0x2e0) = iVar2;
      }
      *(int *)(iVar2 + 0x2e4) = iVar1;
      *(undefined4 *)(iVar2 + 0x2e0) = 0;
      *(int *)(*(int *)(iVar2 + 0x2dc) + 4) = iVar2;
      DAT_803deb08 = DAT_803deb08 | 1 << 0x1f - *(int *)(iVar2 + 0x2d0);
      DAT_803deb0c = 1;
    }
  }
  if (DAT_803deb0c != 0) {
    FUN_802467dc(0);
  }
  FUN_80243e9c();
  return;
}

