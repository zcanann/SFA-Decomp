// Function: FUN_80155e10
// Entry: 80155e10
// Size: 272 bytes

void FUN_80155e10(int param_1,int param_2,undefined4 param_3,int param_4,undefined4 param_5,
                 int param_6)

{
  if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
  }
  else if (param_4 == 0x11) {
    if ((*(char *)(param_2 + 0x33a) == '\x02') && (*(short *)(param_1 + 0xa0) != 5)) {
      FUN_8014d08c((double)FLOAT_803e2a7c,param_1,param_2,5,0,0);
    }
  }
  else if ((*(short *)(param_1 + 0xa0) == 5) || (*(short *)(param_1 + 0xa0) == 4)) {
    if ((int)(uint)*(ushort *)(param_2 + 0x2b0) < param_6) {
      *(undefined2 *)(param_2 + 0x2b0) = 0;
      FUN_8000bb18(param_1,600);
      FUN_8000bb18(param_1,0x22);
    }
    else {
      *(ushort *)(param_2 + 0x2b0) = *(ushort *)(param_2 + 0x2b0) - (short)param_6;
      FUN_8000bb18(param_1,0x24f);
      FUN_8000bb18(param_1,0x22);
    }
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
  }
  else {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x10;
    FUN_8000bb18(param_1,0x250);
  }
  return;
}

