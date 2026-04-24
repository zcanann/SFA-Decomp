// Function: FUN_802a5048
// Entry: 802a5048
// Size: 260 bytes

/* WARNING: Removing unreachable block (ram,0x802a5128) */

undefined4 FUN_802a5048(undefined8 param_1,undefined4 param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (*(char *)(param_3 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e7ea4,param_2,0x8e,0);
    *(float *)(param_3 + 0x2a0) = FLOAT_803e8060;
  }
  (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,3);
  if (*(char *)(param_3 + 0x346) != '\0') {
    DAT_803de42c = 0;
    iVar2 = 0;
    piVar1 = &DAT_80332ed4;
    do {
      if (*piVar1 != 0) {
        FUN_8002cbc4();
        *piVar1 = 0;
      }
      piVar1 = piVar1 + 1;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 7);
    if (DAT_803de454 != 0) {
      FUN_80013e2c();
      DAT_803de454 = 0;
    }
    FUN_8011dd88();
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return 0;
}

