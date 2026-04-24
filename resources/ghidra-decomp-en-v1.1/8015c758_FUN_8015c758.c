// Function: FUN_8015c758
// Entry: 8015c758
// Size: 512 bytes

undefined4
FUN_8015c758(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) | 4;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
  FUN_80033a34(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    uVar1 = FUN_80022264(0,1);
    if (uVar1 == 0) {
      DAT_803de6f8 = 3;
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e39ac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,10,0,param_12,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else {
      uVar1 = FUN_80022264(0,2);
      DAT_803de6f8 = (undefined)uVar1;
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e39ac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,6,0,param_12,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         FLOAT_803e39e4 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         FLOAT_803e39e8;
  }
  if ((*(byte *)(iVar2 + 0x406) < 0x33) || ((*(byte *)(iVar2 + 0x404) & 2) != 0)) {
    *(float *)(param_10 + 0x280) = FLOAT_803e39ac;
  }
  else if ((*(float *)(param_10 + 0x2c0) <= FLOAT_803e39ec) || (*(char *)(param_10 + 0x346) != '\0')
          ) {
    *(float *)(param_10 + 0x280) = FLOAT_803e39ac;
  }
  else {
    *(float *)(param_10 + 0x280) = *(float *)(param_10 + 0x2c0) / FLOAT_803e39ec - FLOAT_803e39e0;
    *(float *)(param_10 + 0x280) =
         *(float *)(param_10 + 0x280) *
         ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         FLOAT_803e39f0);
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)FLOAT_803dc074,param_9,param_10,4);
  return 0;
}

