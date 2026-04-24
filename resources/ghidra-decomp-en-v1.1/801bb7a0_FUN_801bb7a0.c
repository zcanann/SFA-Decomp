// Function: FUN_801bb7a0
// Entry: 801bb7a0
// Size: 196 bytes

/* WARNING: Removing unreachable block (ram,0x801bb844) */
/* WARNING: Removing unreachable block (ram,0x801bb7b0) */

undefined4
FUN_801bb7a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,2,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e58bc;
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
  (**(code **)(*DAT_803dd70c + 0x30))(param_1,param_9,param_10,4);
  return 0;
}

