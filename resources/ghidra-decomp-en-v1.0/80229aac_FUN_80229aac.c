// Function: FUN_80229aac
// Entry: 80229aac
// Size: 660 bytes

/* WARNING: Removing unreachable block (ram,0x80229d18) */
/* WARNING: Removing unreachable block (ram,0x80229d20) */

void FUN_80229aac(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  undefined2 *puVar3;
  short *psVar4;
  uint uVar5;
  int iVar6;
  float *pfVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  double local_58;
  double local_50;
  double local_48;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar1 = FUN_802860d4();
  iVar6 = *(int *)(iVar1 + 0x4c);
  pfVar7 = *(float **)(iVar1 + 0xb8);
  *(undefined *)(param_3 + 0x56) = 0;
  *(ushort *)(param_3 + 0x70) = *(ushort *)(param_3 + 0x70) & 0xffdf;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffdf;
  FUN_8022999c(iVar1,pfVar7);
  if (*(char *)(param_3 + 0x80) == '\x01') {
    *(undefined *)((int)pfVar7 + 0x5f) = 1;
  }
  if (*(char *)((int)pfVar7 + 0x5f) != '\0') {
    if ((*(byte *)((int)pfVar7 + 0x66) & 1) == 0) {
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
  }
  piVar2 = (int *)FUN_8002b588(iVar1);
  iVar6 = *piVar2;
  dVar10 = (double)FLOAT_803e6e70;
  dVar11 = DOUBLE_803e6e80;
  for (iVar1 = 0; iVar1 < (int)(uint)*(ushort *)(iVar6 + 0xe4); iVar1 = iVar1 + 1) {
    puVar3 = (undefined2 *)FUN_800284a4(piVar2,iVar1);
    psVar4 = (short *)FUN_80028414(iVar6,iVar1);
    local_50 = (double)CONCAT44(0x43300000,(int)(short)puVar3[2] ^ 0x80000000);
    uVar5 = ((int)(dVar10 * (double)((float)(local_50 - dVar11) / *pfVar7)) & 0xffffU) +
            (uint)*(ushort *)(pfVar7 + 0x18);
    if (*psVar4 < 1) {
      local_48 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      dVar9 = (double)FUN_80293e80((double)((FLOAT_803e6e78 * (float)(local_48 - dVar11)) /
                                           FLOAT_803e6e7c));
      local_50 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)-(float)((double)FLOAT_803e6e74 * dVar9 -
                                    (double)(float)(local_50 - DOUBLE_803e6e80));
    }
    else {
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      dVar9 = (double)FUN_80293e80((double)((FLOAT_803e6e78 * (float)(local_50 - dVar11)) /
                                           FLOAT_803e6e7c));
      local_58 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *puVar3 = (short)(int)((double)FLOAT_803e6e74 * dVar9 +
                            (double)(float)(local_58 - DOUBLE_803e6e80));
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  FUN_80286120(0);
  return;
}

