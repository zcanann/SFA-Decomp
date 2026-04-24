// Function: FUN_8015038c
// Entry: 8015038c
// Size: 40 bytes

void FUN_8015038c(undefined4 param_1,int param_2,undefined4 param_3,int param_4)

{
  if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
    return;
  }
  *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
  return;
}

