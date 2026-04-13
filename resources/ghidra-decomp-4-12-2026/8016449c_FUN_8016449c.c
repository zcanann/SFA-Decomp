// Function: FUN_8016449c
// Entry: 8016449c
// Size: 112 bytes

void FUN_8016449c(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar1 + 0x278) == '\x01') {
    FUN_80036018(param_1);
    *(undefined *)(iVar1 + 0x278) = 2;
    *(byte *)(iVar1 + 0x27a) = *(byte *)(iVar1 + 0x27a) | 3;
    if (*(short *)(param_1 + 0x46) == 0x4c1) {
      *(float *)(iVar1 + 0x2a0) = FLOAT_803e3c34;
    }
  }
  return;
}

