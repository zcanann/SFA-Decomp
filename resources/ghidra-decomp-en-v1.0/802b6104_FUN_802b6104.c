// Function: FUN_802b6104
// Entry: 802b6104
// Size: 140 bytes

void FUN_802b6104(int param_1)

{
  float fVar1;
  int iVar2;
  
  fVar1 = FLOAT_803e7ea4;
  iVar2 = *(int *)(param_1 + 0xb8);
  if (FLOAT_803e7ea4 < *(float *)(iVar2 + 0x820)) {
    *(float *)(iVar2 + 0x820) = *(float *)(iVar2 + 0x820) - FLOAT_803e7ee0;
    if (fVar1 < *(float *)(iVar2 + 0x820)) {
      if (FLOAT_803e7ef0 == *(float *)(iVar2 + 0x820)) {
        FUN_80020634(1,0);
        FUN_80020628(0xfd);
      }
    }
    else {
      FUN_80020634(0,0);
      *(undefined *)(iVar2 + 0x8cf) = 1;
    }
  }
  return;
}

