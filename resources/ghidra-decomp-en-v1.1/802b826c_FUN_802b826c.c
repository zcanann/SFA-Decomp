// Function: FUN_802b826c
// Entry: 802b826c
// Size: 228 bytes

/* WARNING: Removing unreachable block (ram,0x802b8330) */
/* WARNING: Removing unreachable block (ram,0x802b827c) */

undefined4
FUN_802b826c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8000bb38((uint)param_9,*(ushort *)(*(int *)(*(int *)(param_9 + 0x5c) + 0x40c) + 0x2a));
    uVar1 = FUN_80022264(0,1);
    if (uVar1 == 0) {
      *param_9 = *param_9 + 0x7557;
    }
    else {
      *param_9 = *param_9 + -0x7557;
    }
    FUN_8003042c((double)FLOAT_803e8e18,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x23,0,param_12,param_13,param_14,param_15,param_16);
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e8e40;
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
  return 0;
}

