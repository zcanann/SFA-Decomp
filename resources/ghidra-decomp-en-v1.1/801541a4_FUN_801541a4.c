// Function: FUN_801541a4
// Entry: 801541a4
// Size: 276 bytes

void FUN_801541a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  bool bVar2;
  
  bVar2 = false;
  sVar1 = *(short *)(param_9 + 0xa0);
  if ((((sVar1 == 5) || (sVar1 == 4)) ||
      ((sVar1 == 6 && ((double)*(float *)(param_9 + 0x98) < DOUBLE_803e35d0)))) && (param_12 != 0xe)
     ) {
    bVar2 = true;
  }
  if (param_12 == 0x10) {
    if (bVar2) {
      *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x20;
    }
  }
  else if (bVar2) {
    if (*(char *)(param_10 + 0x33b) == '\0') {
      *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 8;
      *(undefined2 *)(param_10 + 0x2b0) = 0;
      FUN_8000bb38(param_9,0x25f);
    }
  }
  else if (param_12 == 0x11) {
    *(float *)(param_10 + 0x32c) = FLOAT_803e35d8;
    *(float *)(param_10 + 0x324) = FLOAT_803e35dc;
    FUN_8014d504((double)FLOAT_803e35e0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,4,0,3,param_14,param_15,param_16);
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
    *(undefined *)(param_10 + 0x33b) = 0x3c;
  }
  else {
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x10;
  }
  return;
}

