// Function: FUN_80156ef0
// Entry: 80156ef0
// Size: 200 bytes

void FUN_80156ef0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  
  if (param_12 != 0x11) {
    if (param_12 == 0x10) {
      *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x20;
    }
    else {
      sVar1 = *(short *)(param_9 + 0xa0);
      if ((((sVar1 == 0) || (sVar1 == 1)) || (sVar1 == 3)) || (sVar1 == 4)) {
        FUN_8000bb38(param_9,0x250);
        *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x10;
      }
      else {
        FUN_8014d504((double)FLOAT_803e379c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,param_10,4,0,0,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x33a) = 0;
        FUN_8000bb38(param_9,0x24f);
        *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 8;
      }
    }
  }
  return;
}

