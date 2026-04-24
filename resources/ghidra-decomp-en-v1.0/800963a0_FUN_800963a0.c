// Function: FUN_800963a0
// Entry: 800963a0
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x800964b4) */
/* WARNING: Removing unreachable block (ram,0x800964ac) */
/* WARNING: Removing unreachable block (ram,0x800964bc) */

void FUN_800963a0(undefined4 param_1,undefined4 param_2,float *param_3,int param_4)

{
  uint uVar1;
  short *psVar2;
  undefined4 uVar3;
  double extraout_f1;
  undefined8 in_f29;
  double dVar4;
  undefined8 in_f30;
  double dVar5;
  undefined8 in_f31;
  double dVar6;
  undefined8 uVar7;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar7 = FUN_802860dc();
  psVar2 = (short *)((ulonglong)uVar7 >> 0x20);
  dVar4 = extraout_f1;
  for (uVar1 = (uint)uVar7; (uVar1 & 0xffff) != 0; uVar1 = (int)(uVar1 & 0xffff) >> 1) {
    if ((uVar1 & 1) != 0) {
      dVar6 = (double)*param_3;
      dVar5 = (double)param_3[2];
      if ((*(float *)(param_4 + 0x1b4) < FLOAT_803df338) && ((double)FLOAT_803df33c < dVar4)) {
        FUN_80095a00(dVar6,(double)(*(float *)(psVar2 + 8) + *(float *)(param_4 + 0x1b4)),dVar5,
                     (double)FLOAT_803df300,psVar2);
      }
      FLOAT_803dd20c = FLOAT_803df318;
      FUN_80095764(dVar6,(double)(*(float *)(psVar2 + 8) + *(float *)(param_4 + 0x1b4)),dVar5,
                   (double)FLOAT_803df300,(int)*psVar2,4);
      DAT_8039ab48 = (float)dVar6;
      DAT_8039ab4c = *(float *)(psVar2 + 8) + *(float *)(param_4 + 0x1b4);
      DAT_8039ab50 = (float)dVar5;
      DAT_803dd1f8 = 1;
    }
    param_3 = param_3 + 3;
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  __psq_l0(auStack40,uVar3);
  __psq_l1(auStack40,uVar3);
  FUN_80286128();
  return;
}

