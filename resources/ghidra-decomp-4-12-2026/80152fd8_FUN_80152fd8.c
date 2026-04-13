// Function: FUN_80152fd8
// Entry: 80152fd8
// Size: 100 bytes

void FUN_80152fd8(uint param_1,int param_2,undefined4 param_3,int param_4)

{
  if ((param_4 != 0x10) && (param_4 != 0x11)) {
    FUN_8000bb38(param_1,0x248);
    *(undefined2 *)(param_2 + 0x2b0) = 0;
    *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x20;
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
  }
  return;
}

