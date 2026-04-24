// Function: FUN_80155c1c
// Entry: 80155c1c
// Size: 100 bytes

void FUN_80155c1c(uint param_1,int param_2,undefined4 param_3,int param_4)

{
  if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
  }
  else if (param_4 != 0x11) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
    FUN_8000bb38(param_1,0x254);
    *(undefined2 *)(param_2 + 0x2b0) = 0;
  }
  return;
}

