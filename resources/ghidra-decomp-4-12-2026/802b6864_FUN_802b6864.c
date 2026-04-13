// Function: FUN_802b6864
// Entry: 802b6864
// Size: 140 bytes

void FUN_802b6864(int param_1)

{
  float fVar1;
  int iVar2;
  
  fVar1 = FLOAT_803e8b3c;
  iVar2 = *(int *)(param_1 + 0xb8);
  if (FLOAT_803e8b3c < *(float *)(iVar2 + 0x820)) {
    *(float *)(iVar2 + 0x820) = *(float *)(iVar2 + 0x820) - FLOAT_803e8b78;
    if (fVar1 < *(float *)(iVar2 + 0x820)) {
      if (FLOAT_803e8b88 == *(float *)(iVar2 + 0x820)) {
        FUN_800206f8(1,0);
        FUN_800206ec(0xfd);
      }
    }
    else {
      FUN_800206f8(0,0);
      *(undefined *)(iVar2 + 0x8cf) = 1;
    }
  }
  return;
}

