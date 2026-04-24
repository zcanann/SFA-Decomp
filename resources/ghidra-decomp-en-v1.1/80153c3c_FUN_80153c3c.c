// Function: FUN_80153c3c
// Entry: 80153c3c
// Size: 172 bytes

void FUN_80153c3c(uint param_1,int param_2,undefined4 param_3,int param_4,undefined4 param_5,
                 int param_6)

{
  if ((*(short *)(param_1 + 0xa0) != 1) || ((*(uint *)(param_2 + 0x2dc) & 0x40000000) == 0)) {
    if (param_4 == 0x10) {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
    }
    else {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
      if ((int)(uint)*(ushort *)(param_2 + 0x2b0) < param_6) {
        FUN_8000bb38(param_1,0x246);
        *(undefined2 *)(param_2 + 0x2b0) = 0;
      }
      else {
        FUN_8000bb38(param_1,0x247);
        *(short *)(param_2 + 0x2b0) = *(short *)(param_2 + 0x2b0) - (short)param_6;
      }
    }
  }
  return;
}

