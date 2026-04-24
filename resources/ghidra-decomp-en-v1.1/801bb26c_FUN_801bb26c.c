// Function: FUN_801bb26c
// Entry: 801bb26c
// Size: 328 bytes

/* WARNING: Removing unreachable block (ram,0x801bb394) */
/* WARNING: Removing unreachable block (ram,0x801bb27c) */

undefined4
FUN_801bb26c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(float *)(param_10 + 0x2a0) = FLOAT_803e58ac;
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x11,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e5870;
    *(float *)(param_10 + 0x280) = FLOAT_803e5870;
    *(float *)(param_10 + 0x284) = fVar1;
  }
  if (*(float *)(param_9 + 0x98) <= FLOAT_803e58b0) {
    if (FLOAT_803e58b4 < *(float *)(param_9 + 0x98)) {
      DAT_803de800 = DAT_803de800 | 0x40;
    }
  }
  else {
    DAT_803de800 = DAT_803de800 & 0xffffffbf;
  }
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    DAT_803de800 = DAT_803de800 | 0x10000;
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_9,param_10,0,3,&DAT_803266e0);
  (**(code **)(*DAT_803dd70c + 0x30))(param_1,param_9,param_10,0xf0);
  return 0;
}

