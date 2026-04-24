// Function: FUN_800385e8
// Entry: 800385e8
// Size: 212 bytes

/* WARNING: Removing unreachable block (ram,0x80038690) */
/* WARNING: Removing unreachable block (ram,0x80038698) */

int FUN_800385e8(short *param_1,int param_2,float *param_3)

{
  short sVar1;
  int iVar2;
  undefined4 uVar3;
  undefined8 in_f30;
  double dVar4;
  undefined8 in_f31;
  double dVar5;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  dVar5 = (double)(*(float *)(param_1 + 6) - *(float *)(param_2 + 0xc));
  dVar4 = (double)(*(float *)(param_1 + 10) - *(float *)(param_2 + 0x14));
  sVar1 = FUN_800217c0(dVar5,dVar4);
  if (param_3 != (float *)0x0) {
    dVar4 = (double)FUN_802931a0((double)(float)(dVar5 * dVar5 + (double)(float)(dVar4 * dVar4)));
    *param_3 = (float)dVar4;
  }
  iVar2 = (int)sVar1 - ((int)*param_1 & 0xffffU);
  if (0x8000 < iVar2) {
    iVar2 = iVar2 + -0xffff;
  }
  if (iVar2 < -0x8000) {
    iVar2 = iVar2 + 0xffff;
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  return (int)(short)iVar2;
}

