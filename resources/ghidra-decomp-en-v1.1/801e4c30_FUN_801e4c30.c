// Function: FUN_801e4c30
// Entry: 801e4c30
// Size: 156 bytes

void FUN_801e4c30(uint param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(*(int *)(param_1 + 0x54) + 0x50);
  if ((iVar1 != 0) && (*(float *)(iVar2 + 0x20) == FLOAT_803e6584)) {
    if (*(short *)(iVar1 + 0x46) == 0x8e) {
      FUN_8000bb38(param_1,0x36);
    }
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
    *(float *)(iVar2 + 0x20) = FLOAT_803e6588;
    *(undefined *)(param_1 + 0x36) = 0;
    FUN_800998ec(param_1,2);
  }
  return;
}

