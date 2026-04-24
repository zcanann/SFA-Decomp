// Function: FUN_800956f4
// Entry: 800956f4
// Size: 112 bytes

/* WARNING: Removing unreachable block (ram,0x8009574c) */

undefined4 FUN_800956f4(double param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if ((DAT_803dd1f8 == '\0') ||
     (dVar3 = (double)FUN_8024795c(param_2,&DAT_8039ab48),
     (double)(float)(param_1 * param_1) <= dVar3)) {
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  DAT_803dd1f8 = 0;
  return uVar1;
}

