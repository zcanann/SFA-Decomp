// Function: FUN_801baf0c
// Entry: 801baf0c
// Size: 300 bytes

undefined4
FUN_801baf0c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e5870;
    *(float *)(param_10 + 0x280) = FLOAT_803e5870;
    *(float *)(param_10 + 0x284) = fVar1;
    *(float *)(param_10 + 0x2a0) = FLOAT_803e5898;
    uVar2 = FUN_80022264(0,1);
    if (uVar2 == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0xc,0,param_12,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xd,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_9,param_10,0,0,&DAT_803266e0);
  (**(code **)(*DAT_803dd70c + 0x34))(param_9,param_10,7,1,&DAT_803266e0);
  return 0;
}

