// Function: FUN_801147bc
// Entry: 801147bc
// Size: 864 bytes

/* WARNING: Removing unreachable block (ram,0x80114af4) */
/* WARNING: Removing unreachable block (ram,0x80114afc) */

void FUN_801147bc(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,byte *param_5
                 )

{
  short sVar1;
  short *psVar2;
  undefined4 uVar3;
  int iVar4;
  short *psVar5;
  undefined4 uVar6;
  double extraout_f1;
  double dVar7;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  undefined8 uVar9;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  double local_48;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar9 = FUN_802860dc();
  psVar2 = (short *)((ulonglong)uVar9 >> 0x20);
  psVar5 = (short *)uVar9;
  if (psVar5 == (short *)0x0) {
    uVar3 = 0;
  }
  else {
    local_64 = *(float *)(psVar5 + 6) - *(float *)(psVar2 + 6);
    local_60 = *(float *)(psVar5 + 8) - *(float *)(psVar2 + 8);
    local_5c = *(float *)(psVar5 + 10) - *(float *)(psVar2 + 10);
    dVar8 = extraout_f1;
    dVar7 = (double)FUN_802931a0((double)(local_5c * local_5c +
                                         local_64 * local_64 + local_60 * local_60));
    if ((double)(float)((double)FLOAT_803e1cb4 * dVar8) <= dVar7) {
      FUN_800701a4(&local_64,&local_60,&local_5c);
      *(float *)(psVar2 + 0x12) = local_64 * (float)(dVar8 * (double)FLOAT_803db414);
      *(float *)(psVar2 + 0x14) = local_60 * (float)(dVar8 * (double)FLOAT_803db414);
      *(float *)(psVar2 + 0x16) = local_5c * (float)(dVar8 * (double)FLOAT_803db414);
      if (((*param_5 & 1) != 0) &&
         (iVar4 = FUN_800658a4((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                               (double)*(float *)(psVar2 + 10),psVar2,&local_68,0), iVar4 == 0)) {
        *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_68;
      }
      if ((*param_5 & 2) != 0) {
        sVar1 = *psVar5 - *psVar2;
        if (0x8000 < sVar1) {
          sVar1 = sVar1 + 1;
        }
        if (sVar1 < -0x8000) {
          sVar1 = sVar1 + -1;
        }
        uStack84 = (int)*psVar2 ^ 0x80000000;
        local_58 = 0x43300000;
        uStack76 = (int)sVar1 ^ 0x80000000;
        local_50 = 0x43300000;
        iVar4 = (int)((float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e1c98) +
                     (float)((double)((FLOAT_803e1cb8 +
                                      (float)((double)CONCAT44(0x43300000,uStack76) -
                                             DOUBLE_803e1c98)) *
                                     (float)(dVar8 * (double)FLOAT_803db414)) / dVar7));
        local_48 = (double)(longlong)iVar4;
        *psVar2 = (short)iVar4;
      }
      FUN_8002b95c((double)*(float *)(psVar2 + 0x12),(double)*(float *)(psVar2 + 0x14),
                   (double)*(float *)(psVar2 + 0x16),psVar2);
      if (param_3 != -1) {
        if (psVar2[0x50] != param_3) {
          FUN_80030334((double)FLOAT_803e1c90,psVar2,param_3,0);
        }
        sVar1 = FUN_800217c0((double)local_64,(double)local_5c);
        sVar1 = *psVar2 - sVar1;
        if (0x8000 < sVar1) {
          sVar1 = sVar1 + 1;
        }
        if (sVar1 < -0x8000) {
          sVar1 = sVar1 + -1;
        }
        local_48 = (double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000);
        dVar7 = (double)FUN_80294204((double)((FLOAT_803e1cbc * (float)(local_48 - DOUBLE_803e1c98))
                                             / FLOAT_803e1cc0));
        FUN_8002f5d4((double)(float)(dVar8 * -dVar7),psVar2,param_4);
      }
      uVar3 = 0;
    }
    else {
      *(undefined4 *)(psVar2 + 6) = *(undefined4 *)(psVar5 + 6);
      *(undefined4 *)(psVar2 + 8) = *(undefined4 *)(psVar5 + 8);
      *(undefined4 *)(psVar2 + 10) = *(undefined4 *)(psVar5 + 10);
      if (((*param_5 & 1) != 0) &&
         (iVar4 = FUN_800658a4((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                               (double)*(float *)(psVar2 + 10),psVar2,&local_68,0), iVar4 == 0)) {
        *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_68;
      }
      uVar3 = 1;
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  FUN_80286128(uVar3);
  return;
}

