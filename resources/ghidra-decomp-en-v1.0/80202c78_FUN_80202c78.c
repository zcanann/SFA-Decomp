// Function: FUN_80202c78
// Entry: 80202c78
// Size: 300 bytes

/* WARNING: Removing unreachable block (ram,0x80202d80) */
/* WARNING: Removing unreachable block (ram,0x80202d78) */
/* WARNING: Removing unreachable block (ram,0x80202d88) */

undefined4
FUN_80202c78(double param_1,double param_2,undefined8 param_3,double param_4,int param_5,
            undefined4 param_6)

{
  short sVar2;
  undefined4 uVar1;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  float local_48 [5];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar3 = *(int *)(param_5 + 0xb8);
  sVar2 = FUN_800385e8(param_5,param_6,local_48);
  if ((double)FLOAT_803e62a8 == param_4) {
    uVar1 = 0;
  }
  else {
    dVar6 = (double)(float)((double)(float)((double)local_48[0] - param_1) / param_4);
    dVar5 = dVar6;
    if (dVar6 < (double)FLOAT_803e62a8) {
      dVar5 = -dVar6;
    }
    if ((double)FLOAT_803e6370 <= dVar5) {
      if (dVar6 < (double)FLOAT_803e62a8) {
        param_2 = -param_2;
      }
      *(float *)(iVar3 + 0x280) =
           FLOAT_803db414 * FLOAT_803e634c *
           ((float)(param_2 *
                   (double)(FLOAT_803e62c8 -
                           (float)((double)CONCAT44(0x43300000,(int)sVar2 ^ 0x80000000) -
                                  DOUBLE_803e6368) / FLOAT_803e6374)) - *(float *)(iVar3 + 0x280)) +
           *(float *)(iVar3 + 0x280);
      *(float *)(iVar3 + 0x284) = FLOAT_803e62a8;
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  return uVar1;
}

