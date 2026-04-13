// Function: FUN_80258dac
// Entry: 80258dac
// Size: 40 bytes

void FUN_80258dac(uint param_1,uint param_2,undefined4 *param_3)

{
  *param_3 = *(undefined4 *)
              ((param_1 & 0x3ff) << 2 | 0xc8000000 | (param_2 & 0xf3ff) << 0xc | 0x400000);
  return;
}

