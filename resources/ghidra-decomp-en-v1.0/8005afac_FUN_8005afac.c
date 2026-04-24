// Function: FUN_8005afac
// Entry: 8005afac
// Size: 252 bytes

/* WARNING: Removing unreachable block (ram,0x8005b08c) */

int FUN_8005afac(double param_1,double param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  double dVar4;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  dVar4 = (double)FUN_80291e40((double)(float)(param_1 / (double)FLOAT_803debb4));
  iVar2 = (int)(dVar4 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dcdd0 ^ 0x80000000) -
                                       DOUBLE_803debc0));
  dVar4 = (double)FUN_80291e40((double)(float)(param_2 / (double)FLOAT_803debb4));
  iVar1 = (int)(dVar4 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dcdd4 ^ 0x80000000) -
                                       DOUBLE_803debc0));
  if ((iVar2 < 0) || (0xf < iVar2)) {
    iVar2 = -1;
  }
  else if ((iVar1 < 0) || (0xf < iVar1)) {
    iVar2 = -1;
  }
  else {
    iVar2 = (int)*(short *)(DAT_803822a0 + (iVar2 + iVar1 * 0x10) * 0xc);
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return iVar2;
}

