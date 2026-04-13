// Function: FUN_80159d88
// Entry: 80159d88
// Size: 124 bytes

void FUN_80159d88(uint param_1,int param_2,undefined4 param_3,int param_4)

{
  if (param_4 != 0x11) {
    if (param_4 == 0x10) {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
    }
    else {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
      FUN_8000b844(param_1,1000);
      FUN_8000bb38(param_1,0x3ea);
      *(undefined2 *)(param_2 + 0x2b0) = 0;
    }
  }
  return;
}

