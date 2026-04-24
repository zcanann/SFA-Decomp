// Function: FUN_801562bc
// Entry: 801562bc
// Size: 272 bytes

void FUN_801562bc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)

{
  if (param_12 == 0x10) {
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x20;
  }
  else if (param_12 == 0x11) {
    if ((*(char *)(param_10 + 0x33a) == '\x02') && (*(short *)(param_9 + 0xa0) != 5)) {
      FUN_8014d504((double)FLOAT_803e3714,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,param_10,5,0,0,param_14,param_15,param_16);
    }
  }
  else if ((*(short *)(param_9 + 0xa0) == 5) || (*(short *)(param_9 + 0xa0) == 4)) {
    if ((int)(uint)*(ushort *)(param_10 + 0x2b0) < param_14) {
      *(undefined2 *)(param_10 + 0x2b0) = 0;
      FUN_8000bb38(param_9,600);
      FUN_8000bb38(param_9,0x22);
    }
    else {
      *(ushort *)(param_10 + 0x2b0) = *(ushort *)(param_10 + 0x2b0) - (short)param_14;
      FUN_8000bb38(param_9,0x24f);
      FUN_8000bb38(param_9,0x22);
    }
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 8;
  }
  else {
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x10;
    FUN_8000bb38(param_9,0x250);
  }
  return;
}

