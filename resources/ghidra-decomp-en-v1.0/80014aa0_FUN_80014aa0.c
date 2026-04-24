// Function: FUN_80014aa0
// Entry: 80014aa0
// Size: 108 bytes

/* WARNING: Removing unreachable block (ram,0x80014af4) */

void FUN_80014aa0(double param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if ((DAT_803dc909 != '\0') && (iVar1 = FUN_80020620(), iVar1 == 1)) {
    FUN_8024ec10(0,1);
    if (param_1 < (double)FLOAT_803dc90c) {
      param_1 = (double)FLOAT_803dc90c;
    }
    FLOAT_803dc90c = (float)param_1;
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

