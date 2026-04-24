// Function: FUN_801b5d48
// Entry: 801b5d48
// Size: 468 bytes

/* WARNING: Removing unreachable block (ram,0x801b5ef4) */
/* WARNING: Removing unreachable block (ram,0x801b5efc) */

void FUN_801b5d48(void)

{
  int *piVar1;
  undefined2 *puVar2;
  short *psVar3;
  undefined4 uVar4;
  float *pfVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  undefined4 uVar9;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
  double local_58;
  double local_50;
  double local_48;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar13 = FUN_802860d0();
  pfVar5 = (float *)uVar13;
  piVar1 = (int *)FUN_8002b588();
  iVar6 = *piVar1;
  dVar11 = (double)FLOAT_803e4a00;
  dVar12 = DOUBLE_803e4a10;
  for (iVar7 = 0; uVar8 = (uint)*(ushort *)(iVar6 + 0xe4), iVar7 < (int)uVar8; iVar7 = iVar7 + 1) {
    puVar2 = (undefined2 *)FUN_800284a4(piVar1,iVar7);
    psVar3 = (short *)FUN_80028414(iVar6,iVar7);
    local_58 = (double)CONCAT44(0x43300000,(int)(short)puVar2[2] ^ 0x80000000);
    uVar8 = ((int)(dVar11 * (double)((float)(local_58 - dVar12) / *pfVar5)) & 0xffffU) +
            (uint)*(ushort *)(pfVar5 + 0x18);
    if (*psVar3 < 1) {
      local_48 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
      dVar10 = (double)FUN_80293e80((double)((FLOAT_803e4a08 * (float)(local_48 - dVar12)) /
                                            FLOAT_803e4a0c));
      local_50 = (double)CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
      *puVar2 = (short)(int)-(float)((double)FLOAT_803e4a04 * dVar10 -
                                    (double)(float)(local_50 - DOUBLE_803e4a10));
    }
    else {
      local_50 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
      dVar10 = (double)FUN_80293e80((double)((FLOAT_803e4a08 * (float)(local_50 - dVar12)) /
                                            FLOAT_803e4a0c));
      local_58 = (double)CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
      *puVar2 = (short)(int)((double)FLOAT_803e4a04 * dVar10 +
                            (double)(float)(local_58 - DOUBLE_803e4a10));
    }
  }
  uVar4 = FUN_800284a4(piVar1,0);
  FUN_80241a1c(uVar4,uVar8 * 6);
  *(undefined *)((int)((ulonglong)uVar13 >> 0x20) + 0x36) = *(undefined *)((int)pfVar5 + 0x51);
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  FUN_8028611c();
  return;
}

