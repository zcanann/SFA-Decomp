// Function: FUN_8015454c
// Entry: 8015454c
// Size: 524 bytes

void FUN_8015454c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)

{
  bool bVar1;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  *(float *)(param_10 + 0x32c) = FLOAT_803e35e4;
  bVar1 = false;
  FUN_80035eec((int)param_9,0x18,1,-1);
  if (*(int *)(param_10 + 0x340) != 0) {
    bVar1 = true;
    *(float *)(param_10 + 0x324) = FLOAT_803e3600;
    *(float *)(param_10 + 0x32c) = FLOAT_803e35e4;
    if (param_9[0x50] != 0) {
      FUN_8014d504((double)FLOAT_803e35f0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,param_10,2,0,3,in_r8,in_r9,in_r10);
    }
  }
  if (param_9[0x50] == 3) {
    *(float *)(param_10 + 0x328) = *(float *)(param_10 + 0x328) - FLOAT_803dc074;
    if (*(float *)(param_10 + 0x328) <= FLOAT_803e35e4) {
      bVar1 = true;
      *(float *)(param_10 + 0x32c) = FLOAT_803e35d8;
      *(float *)(param_10 + 0x324) = FLOAT_803e35dc;
      FUN_8014d504((double)FLOAT_803e35e0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,param_10,4,0,3,in_r8,in_r9,in_r10);
    }
  }
  else {
    param_2 = (double)*(float *)(*(int *)(param_10 + 0x29c) + 0x14);
    FUN_8014d3f4(param_9,param_10,0x3c,0);
  }
  if (bVar1) {
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
  }
  else if (*(char *)(param_10 + 0x33a) == '\0') {
    *(undefined *)(param_10 + 0x33a) = 1;
    FUN_8014d504((double)FLOAT_803e3604,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)param_9,param_10,1,0,3,in_r8,in_r9,in_r10);
  }
  else if (((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) &&
          (FUN_8014d504((double)FLOAT_803e3608,param_2,param_3,param_4,param_5,param_6,param_7,
                        param_8,(int)param_9,param_10,3,0,3,in_r8,in_r9,in_r10),
          FLOAT_803e35e4 == *(float *)(param_10 + 0x328))) {
    *(float *)(param_10 + 0x328) = FLOAT_803e360c;
    FUN_8014d3f4(param_9,param_10,1,0);
    FUN_8000bb38((uint)param_9,0x25d);
  }
  param_9[1] = *(short *)(param_10 + 0x19c);
  param_9[2] = *(short *)(param_10 + 0x19e);
  if (*(char *)(param_10 + 0x33b) != '\0') {
    *(char *)(param_10 + 0x33b) = *(char *)(param_10 + 0x33b) + -1;
  }
  return;
}

