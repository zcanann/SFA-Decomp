// Function: FUN_8003adc4
// Entry: 8003adc4
// Size: 780 bytes

/* WARNING: Removing unreachable block (ram,0x8003b0a8) */
/* WARNING: Removing unreachable block (ram,0x8003b098) */
/* WARNING: Removing unreachable block (ram,0x8003b0a0) */
/* WARNING: Removing unreachable block (ram,0x8003b0b0) */

void FUN_8003adc4(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,uint param_5,
                 uint param_6)

{
  int iVar1;
  float fVar2;
  uint uVar3;
  short sVar4;
  short sVar5;
  int iVar6;
  int iVar7;
  short *psVar8;
  int iVar9;
  int iVar10;
  short *psVar11;
  undefined4 uVar12;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar13;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  undefined8 uVar16;
  short local_88 [4];
  undefined4 local_80;
  uint uStack124;
  longlong local_78;
  double local_70;
  double local_68;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar12 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar16 = FUN_802860d8();
  psVar8 = (short *)((ulonglong)uVar16 >> 0x20);
  iVar6 = (int)uVar16;
  psVar11 = (short *)0x0;
  iVar7 = *(int *)(psVar8 + 0x28);
  if (iVar7 != 0) {
    iVar9 = 0;
    iVar10 = 0;
    for (uVar3 = (uint)*(byte *)(iVar7 + 0x5a); uVar3 != 0; uVar3 = uVar3 - 1) {
      if ((*(char *)(*(int *)(iVar7 + 0x10) + *(char *)((int)psVar8 + 0xad) + iVar9 + 1) != -1) &&
         (*(char *)(*(int *)(iVar7 + 0x10) + iVar9) == '\0')) {
        psVar11 = (short *)(*(int *)(psVar8 + 0x36) + iVar10);
      }
      iVar9 = *(char *)(iVar7 + 0x55) + iVar9 + 1;
      iVar10 = iVar10 + 0x12;
    }
  }
  if (psVar11 != (short *)0x0) {
    if (iVar6 == 0) {
      psVar11[1] = psVar11[1] >> 1;
      *psVar11 = *psVar11 >> 1;
    }
    else {
      dVar15 = (double)(*(float *)(psVar8 + 6) - *(float *)(iVar6 + 0xc));
      dVar14 = (double)(*(float *)(psVar8 + 10) - *(float *)(iVar6 + 0x14));
      dVar13 = (double)(*(float *)(psVar8 + 8) - *(float *)(iVar6 + 0x10));
      uVar16 = FUN_802931a0((double)(float)(dVar15 * dVar15 + (double)(float)(dVar14 * dVar14)));
      local_88[0] = FUN_800217c0(dVar15,dVar14);
      local_88[0] = local_88[0] - *psVar8;
      if (0x8000 < local_88[0]) {
        local_88[0] = local_88[0] + 1;
      }
      if (local_88[0] < -0x8000) {
        local_88[0] = local_88[0] + -1;
      }
      if ((param_5 & 0xff) != 0) {
        local_88[0] = local_88[0] + -0x8000;
      }
      sVar5 = FUN_800217c0(uVar16,dVar13);
      local_88[1] = sVar5 + -0x3fff;
      uStack124 = param_4 ^ 0x80000000;
      local_80 = 0x43300000;
      iVar6 = (int)(FLOAT_803de9ec *
                   (float)((double)CONCAT44(0x43300000,param_4 ^ 0x80000000) - DOUBLE_803de9d0));
      local_78 = (longlong)iVar6;
      sVar5 = (short)iVar6;
      psVar8 = local_88;
      local_70 = (double)CONCAT44(0x43300000,param_6 ^ 0x80000000);
      fVar2 = FLOAT_803de9ec * (float)(local_70 - DOUBLE_803de9d0);
      iVar6 = (int)fVar2;
      local_68 = (double)(longlong)iVar6;
      iVar7 = -(int)(short)iVar6;
      iVar9 = -(int)sVar5;
      iVar10 = 2;
      iVar6 = param_3;
      do {
        *psVar8 = *psVar8 - *(short *)(iVar6 + 0x14);
        sVar4 = *psVar8;
        if (sVar4 < iVar7) {
          sVar4 = (short)iVar7;
        }
        else {
          iVar1 = (int)fVar2;
          local_68 = (double)(longlong)iVar1;
          if ((int)(short)iVar1 < (int)sVar4) {
            local_70 = (double)(longlong)iVar1;
            sVar4 = (short)iVar1;
          }
        }
        *psVar8 = sVar4;
        *(short *)(iVar6 + 0x14) = *(short *)(iVar6 + 0x14) + *psVar8;
        if ((int)sVar5 < (int)*(short *)(iVar6 + 0x14)) {
          *(short *)(iVar6 + 0x14) = sVar5;
        }
        if (*(short *)(iVar6 + 0x14) < iVar9) {
          *(short *)(iVar6 + 0x14) = (short)iVar9;
        }
        iVar6 = iVar6 + 0x30;
        psVar8 = psVar8 + 1;
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
      psVar11[1] = *(short *)(param_3 + 0x14);
      *psVar11 = *(short *)(param_3 + 0x44);
    }
  }
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  __psq_l0(auStack24,uVar12);
  __psq_l1(auStack24,uVar12);
  __psq_l0(auStack40,uVar12);
  __psq_l1(auStack40,uVar12);
  __psq_l0(auStack56,uVar12);
  __psq_l1(auStack56,uVar12);
  FUN_80286124();
  return;
}

