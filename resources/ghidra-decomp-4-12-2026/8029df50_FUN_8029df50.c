// Function: FUN_8029df50
// Entry: 8029df50
// Size: 272 bytes

/* WARNING: Removing unreachable block (ram,0x8029e040) */
/* WARNING: Removing unreachable block (ram,0x8029df60) */

undefined4
FUN_8029df50(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  
  *(undefined *)(param_10 + 0x34d) = 3;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x44c,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8c6c;
  }
  sVar1 = *(short *)(param_9 + 0xa0);
  if (sVar1 == 0x44d) {
    if (*(char *)(param_10 + 0x346) != '\0') {
      *(code **)(param_10 + 0x308) = FUN_802a58ac;
      return 2;
    }
  }
  else if (((sVar1 < 0x44d) && (1099 < sVar1)) && (*(char *)(param_10 + 0x346) != '\0')) {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x44d,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8c64;
  }
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
  return 0;
}

