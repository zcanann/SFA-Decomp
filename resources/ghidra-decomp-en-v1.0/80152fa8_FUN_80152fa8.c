// Function: FUN_80152fa8
// Entry: 80152fa8
// Size: 152 bytes

void FUN_80152fa8(undefined4 param_1,int param_2,undefined4 param_3,int param_4)

{
  if (*(char *)(param_2 + 0x33b) == '\0') {
    if (param_4 != 0x11) {
      if (param_4 == 0x10) {
        *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
      }
      else {
        *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
        FUN_8000bb18(param_1,0x25b);
        *(undefined2 *)(param_2 + 0x2b0) = 0;
      }
    }
  }
  else if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x28;
    FUN_8000bb18(param_1,0x25b);
    *(undefined2 *)(param_2 + 0x2b0) = 0;
  }
  return;
}

