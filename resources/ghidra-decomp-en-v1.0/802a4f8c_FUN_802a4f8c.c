// Function: FUN_802a4f8c
// Entry: 802a4f8c
// Size: 188 bytes

/* WARNING: Removing unreachable block (ram,0x802a5028) */

undefined4 FUN_802a4f8c(undefined8 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (*(char *)(param_3 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e7ea4,param_2,0x92,0);
    *(float *)(param_3 + 0x2a0) = FLOAT_803e8060;
  }
  (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,3);
  if (*(char *)(param_3 + 0x346) == '\0') {
    uVar1 = 0;
  }
  else {
    *(code **)(param_3 + 0x308) = FUN_802a514c;
    uVar1 = 2;
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return uVar1;
}

