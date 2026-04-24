// Function: FUN_80163ff0
// Entry: 80163ff0
// Size: 112 bytes

void FUN_80163ff0(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar1 + 0x278) == '\x01') {
    FUN_80035f20();
    *(undefined *)(iVar1 + 0x278) = 2;
    *(byte *)(iVar1 + 0x27a) = *(byte *)(iVar1 + 0x27a) | 3;
    if (*(short *)(param_1 + 0x46) == 0x4c1) {
      *(float *)(iVar1 + 0x2a0) = FLOAT_803e2f9c;
    }
  }
  return;
}

