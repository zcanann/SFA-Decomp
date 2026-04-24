// Function: FUN_80281908
// Entry: 80281908
// Size: 296 bytes

void FUN_80281908(uint param_1,uint param_2,undefined4 param_3,uint param_4)

{
  if ((param_2 & 0xff) != 0xff) {
    if ((param_1 & 0xff) < 0x40) {
      FUN_80281338(param_1 & 0x1f,param_2,param_3,param_4 >> 7 & 0xff);
      FUN_80281338((param_1 & 0x1f) + 0x20,param_2,param_3,param_4 & 0x7f);
    }
    else if ((param_1 - 0x80 & 0xff) < 2) {
      FUN_80281338(param_1 & 0xfe,param_2,param_3,param_4 >> 7 & 0xff);
      FUN_80281338((param_1 & 0xfe) + 1,param_2,param_3,param_4 & 0x7f);
    }
    else if ((param_1 - 0x84 & 0xff) < 2) {
      FUN_80281338(param_1 & 0xfe,param_2,param_3,param_4 >> 7 & 0xff);
      FUN_80281338((param_1 & 0xfe) + 1,param_2,param_3,param_4 & 0x7f);
    }
    else {
      FUN_80281338(param_1,param_2,param_3,param_4 >> 7 & 0xff);
    }
  }
  return;
}

