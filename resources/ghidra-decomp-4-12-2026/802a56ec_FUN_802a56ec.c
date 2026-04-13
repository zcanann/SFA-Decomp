// Function: FUN_802a56ec
// Entry: 802a56ec
// Size: 188 bytes

/* WARNING: Removing unreachable block (ram,0x802a5788) */
/* WARNING: Removing unreachable block (ram,0x802a56fc) */

undefined4
FUN_802a56ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x92,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8cf8;
  }
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,3);
  if (*(char *)(param_10 + 0x346) == '\0') {
    uVar1 = 0;
  }
  else {
    *(code **)(param_10 + 0x308) = FUN_802a58ac;
    uVar1 = 2;
  }
  return uVar1;
}

