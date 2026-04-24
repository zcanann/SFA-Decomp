// Function: FUN_802a57a8
// Entry: 802a57a8
// Size: 260 bytes

/* WARNING: Removing unreachable block (ram,0x802a5888) */
/* WARNING: Removing unreachable block (ram,0x802a57b8) */

undefined4
FUN_802a57a8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int *piVar1;
  int iVar2;
  undefined8 uVar3;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x8e,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8cf8;
  }
  uVar3 = (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,3);
  if (*(char *)(param_10 + 0x346) != '\0') {
    DAT_803df0ac = 0;
    iVar2 = 0;
    piVar1 = &DAT_80333b34;
    do {
      if (*piVar1 != 0) {
        uVar3 = FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar1);
        *piVar1 = 0;
      }
      piVar1 = piVar1 + 1;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 7);
    if (DAT_803df0d4 != (undefined *)0x0) {
      FUN_80013e4c(DAT_803df0d4);
      DAT_803df0d4 = (undefined *)0x0;
    }
    FUN_8011e06c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return 0;
}

