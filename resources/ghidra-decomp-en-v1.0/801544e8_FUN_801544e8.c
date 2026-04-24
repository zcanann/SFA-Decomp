// Function: FUN_801544e8
// Entry: 801544e8
// Size: 156 bytes

void FUN_801544e8(int param_1,int param_2,undefined4 param_3,int param_4)

{
  if ((param_4 != 0x11) && (param_4 != 0x10)) {
    if (*(float *)(param_1 + 0x98) <= FLOAT_803e29a4) {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x10;
    }
    else {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
      FUN_8000bb18(param_1,0x232);
      FUN_8000bb18(param_1,0x233);
      *(undefined2 *)(param_2 + 0x2b0) = 0;
      *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x20;
    }
  }
  return;
}

