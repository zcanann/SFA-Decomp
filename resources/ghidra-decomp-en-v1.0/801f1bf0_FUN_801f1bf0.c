// Function: FUN_801f1bf0
// Entry: 801f1bf0
// Size: 144 bytes

void FUN_801f1bf0(int param_1)

{
  char in_r8;
  
  if (*(int *)(param_1 + 0xf8) == 0) {
    if (in_r8 == '\0') {
      return;
    }
  }
  else if (in_r8 != -1) {
    return;
  }
  if (*(short *)(*(int *)(param_1 + 0x50) + 0x48) == 2) {
    if (*(short *)(param_1 + 0xb4) == -1) {
      *(uint *)(*(int *)(param_1 + 100) + 0x30) =
           *(uint *)(*(int *)(param_1 + 100) + 0x30) & 0xffffefff;
    }
    else {
      *(uint *)(*(int *)(param_1 + 100) + 0x30) = *(uint *)(*(int *)(param_1 + 100) + 0x30) | 0x1000
      ;
    }
  }
  FUN_8003b8f4((double)FLOAT_803e5d80);
  return;
}

