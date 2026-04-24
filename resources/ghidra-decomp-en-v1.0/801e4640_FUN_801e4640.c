// Function: FUN_801e4640
// Entry: 801e4640
// Size: 156 bytes

void FUN_801e4640(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(*(int *)(param_1 + 0x54) + 0x50);
  if ((iVar1 != 0) && (*(float *)(iVar2 + 0x20) == FLOAT_803e58ec)) {
    if (*(short *)(iVar1 + 0x46) == 0x8e) {
      FUN_8000bb18(param_1,0x36);
    }
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
    *(float *)(iVar2 + 0x20) = FLOAT_803e58f0;
    *(undefined *)(param_1 + 0x36) = 0;
    FUN_80099660((double)FLOAT_803e58e8,param_1,2);
  }
  return;
}

