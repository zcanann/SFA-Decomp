// Function: FUN_8029d7f0
// Entry: 8029d7f0
// Size: 272 bytes

/* WARNING: Removing unreachable block (ram,0x8029d8e0) */

undefined4 FUN_8029d7f0(undefined8 param_1,int param_2,int param_3)

{
  short sVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  *(undefined *)(param_3 + 0x34d) = 3;
  if (*(char *)(param_3 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e7ea4,param_2,0x44c,0);
    *(float *)(param_3 + 0x2a0) = FLOAT_803e7fd4;
  }
  sVar1 = *(short *)(param_2 + 0xa0);
  if (sVar1 == 0x44d) {
    if (*(char *)(param_3 + 0x346) != '\0') {
      *(code **)(param_3 + 0x308) = FUN_802a514c;
      uVar2 = 2;
      goto LAB_8029d8e0;
    }
  }
  else if (((sVar1 < 0x44d) && (1099 < sVar1)) && (*(char *)(param_3 + 0x346) != '\0')) {
    FUN_80030334((double)FLOAT_803e7ea4,param_2,0x44d,0);
    *(float *)(param_3 + 0x2a0) = FLOAT_803e7fcc;
  }
  (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
  uVar2 = 0;
LAB_8029d8e0:
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return uVar2;
}

