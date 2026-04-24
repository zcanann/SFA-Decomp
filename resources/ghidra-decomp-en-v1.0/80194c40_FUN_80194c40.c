// Function: FUN_80194c40
// Entry: 80194c40
// Size: 968 bytes

/* WARNING: Removing unreachable block (ram,0x80194fe0) */
/* WARNING: Removing unreachable block (ram,0x80194fe8) */

void FUN_80194c40(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  ushort uVar1;
  float fVar2;
  int iVar3;
  ushort *puVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  undefined2 *puVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined4 uVar15;
  undefined8 in_f30;
  double dVar16;
  undefined8 in_f31;
  double dVar17;
  undefined8 uVar18;
  double local_a8;
  double local_a0;
  double local_98;
  double local_90;
  double local_88;
  double local_80;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar18 = FUN_802860c8();
  iVar3 = (int)((ulonglong)uVar18 >> 0x20);
  iVar7 = (int)uVar18;
  iVar12 = 0;
  iVar11 = 0;
  for (iVar10 = 0; iVar10 < (int)(uint)*(ushort *)((int)param_3 + 0x9a); iVar10 = iVar10 + 1) {
    puVar4 = (ushort *)FUN_800606ec(param_3,iVar10);
    iVar5 = FUN_80060678();
    dVar17 = DOUBLE_803e4010;
    if (*(char *)(iVar3 + 0x28) == iVar5) {
      local_a8 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar7 + 0x10) + iVar12) ^ 0x80000000);
      puVar4[3] = (ushort)(int)(*(float *)(iVar7 + 0x44) + (float)(local_a8 - DOUBLE_803e4010));
      local_98 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar7 + 0x14) + iVar12) ^ 0x80000000);
      puVar4[4] = (ushort)(int)(*(float *)(iVar7 + 0x44) + (float)(local_98 - dVar17));
      iVar12 = iVar12 + 2;
      uVar1 = puVar4[10];
      dVar16 = (double)FLOAT_803e4008;
      iVar5 = iVar11;
      for (uVar9 = (uint)*puVar4; (int)uVar9 < (int)(uint)uVar1; uVar9 = uVar9 + 1) {
        puVar4 = (ushort *)FUN_800606dc(param_3,uVar9);
        iVar14 = 3;
        iVar13 = iVar5;
        do {
          puVar8 = (undefined2 *)(param_3[0x16] + (uint)*puVar4 * 6);
          local_90 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(*(int *)(iVar7 + 0xc) + iVar5) ^ 0x80000000);
          *puVar8 = (short)(int)(dVar16 * (double)*(float *)(iVar7 + 0x40) +
                                (double)(float)(local_90 - dVar17));
          local_a0 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(*(int *)(iVar7 + 0xc) + iVar5 + 2) ^
                                      0x80000000);
          puVar8[1] = (short)(int)(dVar16 * (double)*(float *)(iVar7 + 0x44) +
                                  (double)(float)(local_a0 - dVar17));
          local_88 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(*(int *)(iVar7 + 0xc) + iVar5 + 4) ^
                                      0x80000000);
          puVar8[2] = (short)(int)(dVar16 * (double)*(float *)(iVar7 + 0x48) +
                                  (double)(float)(local_88 - dVar17));
          iVar5 = iVar5 + 6;
          iVar13 = iVar13 + 6;
          iVar11 = iVar11 + 6;
          puVar4 = puVar4 + 1;
          iVar14 = iVar14 + -1;
        } while (iVar14 != 0);
        iVar5 = iVar13;
      }
    }
  }
  FUN_80241a1c(param_3[0x16],(uint)*(ushort *)(param_3 + 0x24) * 6);
  iVar10 = 0;
  for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)((int)param_3 + 0xa1); iVar11 = iVar11 + 1) {
    iVar12 = FUN_800606fc(param_3,iVar11);
    uVar6 = FUN_8006070c(param_3,*(undefined *)(iVar12 + 0x13));
    iVar5 = FUN_8004c250(uVar6,0);
    dVar17 = DOUBLE_803e4010;
    fVar2 = FLOAT_803e4008;
    if ((uint)*(byte *)(iVar5 + 5) == (int)*(char *)(iVar3 + 0x28)) {
      local_80 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar7 + 0x28) + iVar10) ^ 0x80000000);
      *(short *)(iVar12 + 6) =
           (short)(int)(FLOAT_803e4008 * *(float *)(iVar7 + 0x40) +
                       (float)(local_80 - DOUBLE_803e4010));
      local_90 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar7 + 0x2c) + iVar10) ^ 0x80000000);
      *(short *)(iVar12 + 0xc) =
           (short)(int)(fVar2 * *(float *)(iVar7 + 0x40) + (float)(local_90 - dVar17));
      local_a0 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(*(int *)(iVar7 + 0x30) + iVar10) ^ 0x80000000);
      *(short *)(iVar12 + 8) =
           (short)(int)(fVar2 * *(float *)(iVar7 + 0x44) + (float)(local_a0 - dVar17));
      *(short *)(iVar12 + 0xe) =
           (short)(int)(fVar2 * *(float *)(iVar7 + 0x44) +
                       (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(*(int *)(iVar7 + 0x34) + iVar10) ^
                                                0x80000000) - dVar17));
      *(short *)(iVar12 + 10) =
           (short)(int)(fVar2 * *(float *)(iVar7 + 0x48) +
                       (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(*(int *)(iVar7 + 0x38) + iVar10) ^
                                                0x80000000) - dVar17));
      *(short *)(iVar12 + 0x10) =
           (short)(int)(fVar2 * *(float *)(iVar7 + 0x48) +
                       (float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(*(int *)(iVar7 + 0x3c) + iVar10) ^
                                                0x80000000) - dVar17));
    }
    iVar10 = iVar10 + 2;
  }
  uVar6 = FUN_80060b90(param_3);
  *param_3 = uVar6;
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  FUN_80286114();
  return;
}

