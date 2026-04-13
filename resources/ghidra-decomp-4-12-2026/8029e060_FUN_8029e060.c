// Function: FUN_8029e060
// Entry: 8029e060
// Size: 352 bytes

/* WARNING: Removing unreachable block (ram,0x8029e19c) */
/* WARNING: Removing unreachable block (ram,0x8029e070) */

undefined4
FUN_8029e060(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int local_28 [3];
  
  iVar3 = *(int *)(param_9 + 0xb8);
  *(undefined *)(param_10 + 0x34d) = 3;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    param_12 = 0;
    iVar2 = FUN_80036974(param_9,local_28,(int *)0x0,(uint *)0x0);
    if (iVar2 != 0) {
      param_2 = -(double)*(float *)(local_28[0] + 0x2c);
      iVar2 = FUN_80021884();
      *(short *)(iVar3 + 0x478) = (short)iVar2;
      *(undefined2 *)(iVar3 + 0x484) = *(undefined2 *)(iVar3 + 0x478);
    }
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x407,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8bcc;
  }
  sVar1 = *(short *)(param_9 + 0xa0);
  if (sVar1 == 0x408) {
    if (*(char *)(param_10 + 0x346) != '\0') {
      *(code **)(param_10 + 0x308) = FUN_802a58ac;
      return 2;
    }
  }
  else if (((sVar1 < 0x408) && (0x406 < sVar1)) && (*(char *)(param_10 + 0x346) != '\0')) {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x408,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8c64;
  }
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
  return 0;
}

