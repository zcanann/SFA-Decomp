// Function: FUN_80229dc4
// Entry: 80229dc4
// Size: 704 bytes

/* WARNING: Removing unreachable block (ram,0x8022a05c) */
/* WARNING: Removing unreachable block (ram,0x8022a064) */

void FUN_80229dc4(void)

{
  int iVar1;
  int *piVar2;
  undefined2 *puVar3;
  short *psVar4;
  uint uVar5;
  int iVar6;
  float *pfVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f30;
  double dVar13;
  undefined8 in_f31;
  double local_68;
  double local_60;
  double local_58;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar1 = FUN_802860cc();
  iVar6 = *(int *)(iVar1 + 0x4c);
  FUN_8002b9ec();
  pfVar7 = *(float **)(iVar1 + 0xb8);
  FUN_8022999c(iVar1,pfVar7);
  piVar2 = (int *)FUN_8002b588(iVar1);
  iVar9 = *piVar2;
  dVar13 = (double)FLOAT_803e6e70;
  dVar12 = DOUBLE_803e6e80;
  for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar9 + 0xe4); iVar8 = iVar8 + 1) {
    puVar3 = (undefined2 *)FUN_800284a4(piVar2,iVar8);
    psVar4 = (short *)FUN_80028414(iVar9,iVar8);
    local_68 = (double)CONCAT44(0x43300000,(int)(short)puVar3[2] ^ 0x80000000);
    uVar5 = ((int)(dVar13 * (double)((float)(local_68 - dVar12) / *pfVar7)) & 0xffffU) +
            (uint)*(ushort *)(pfVar7 + 0x18);
    if (*psVar4 < 1) {
      local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      dVar11 = (double)FUN_80293e80((double)((FLOAT_803e6e78 * (float)(local_58 - dVar12)) /
                                            FLOAT_803e6e7c));
      local_60 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)-(float)((double)FLOAT_803e6e74 * dVar11 -
                                    (double)(float)(local_60 - DOUBLE_803e6e80));
    }
    else {
      local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      dVar11 = (double)FUN_80293e80((double)((FLOAT_803e6e78 * (float)(local_60 - dVar12)) /
                                            FLOAT_803e6e7c));
      local_68 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)((double)FLOAT_803e6e74 * dVar11 +
                            (double)(float)(local_68 - DOUBLE_803e6e80));
    }
  }
  if (*(char *)((int)pfVar7 + 0x5f) == '\0') {
    FUN_800200e8(0xedb,0);
    FUN_80035f00(iVar1);
  }
  else {
    if ((*(byte *)((int)pfVar7 + 0x66) & 1) == 0) {
      FUN_800200e8(0xedb,1);
      *(byte *)((int)pfVar7 + 0x66) = *(byte *)((int)pfVar7 + 0x66) | 1;
      FUN_800200e8((int)*(short *)(iVar6 + 0x1e),1);
    }
    local_58 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar1 + 0x36));
    iVar6 = (int)((float)(local_58 - DOUBLE_803e6e88) + FLOAT_803db414);
    if (iVar6 < 0) {
      iVar6 = 0;
    }
    else if (0xff < iVar6) {
      iVar6 = 0xff;
    }
    *(char *)(iVar1 + 0x36) = (char)iVar6;
    FUN_80035f20(iVar1);
  }
  iVar6 = FUN_8002b9ec();
  if (iVar6 != 0) {
    iVar6 = FUN_8002b9ec();
    dVar12 = (double)FUN_80247984(iVar1 + 0x18,iVar6 + 0x18);
    if ((double)FLOAT_803e6e94 < dVar12) {
      FUN_800200e8(0xedb,0);
    }
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  FUN_80286118();
  return;
}

