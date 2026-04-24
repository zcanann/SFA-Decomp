// Function: FUN_80155f20
// Entry: 80155f20
// Size: 240 bytes

void FUN_80155f20(int param_1,int param_2)

{
  *(float *)(param_2 + 0x324) = FLOAT_803e2a60;
  if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
    if (*(char *)(param_2 + 0x33a) == '\x01') {
      if (*(short *)(param_1 + 0xa0) == 1) {
        *(undefined *)(param_2 + 0x33a) = 2;
        *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) & 0xfffeffff;
      }
      else if (*(short *)(param_1 + 0xa0) == 3) {
        *(undefined *)(param_2 + 0x33a) = 0;
        *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x10000;
        FUN_8014d08c((double)FLOAT_803e2a54,param_1,param_2,0,0,0);
      }
    }
    else if ((*(char *)(param_2 + 0x33a) == '\x02') && (*(short *)(param_1 + 0xa0) != 2)) {
      FUN_8014d08c((double)FLOAT_803e2a54,param_1,param_2,2,0,0);
    }
  }
  FUN_80155cf8(param_1,param_2);
  return;
}

