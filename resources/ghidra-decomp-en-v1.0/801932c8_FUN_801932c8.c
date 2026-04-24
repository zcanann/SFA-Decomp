// Function: FUN_801932c8
// Entry: 801932c8
// Size: 640 bytes

/* WARNING: Removing unreachable block (ram,0x80193520) */
/* WARNING: Removing unreachable block (ram,0x80193510) */
/* WARNING: Removing unreachable block (ram,0x80193518) */
/* WARNING: Removing unreachable block (ram,0x80193528) */

void FUN_801932c8(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  ushort *puVar3;
  uint uVar4;
  ushort *puVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined4 uVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar19;
  undefined8 in_f31;
  double dVar20;
  undefined8 uVar21;
  float local_a8;
  float local_a4;
  float local_a0;
  longlong local_98;
  longlong local_90;
  undefined4 local_88;
  uint uStack132;
  double local_80;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar21 = FUN_802860b8();
  iVar8 = (int)((ulonglong)uVar21 >> 0x20);
  piVar6 = (int *)uVar21;
  FUN_8005b2fc((double)*(float *)(iVar8 + 0xc),(double)*(float *)(iVar8 + 0x10),
               (double)*(float *)(iVar8 + 0x14));
  iVar2 = FUN_8005aeec();
  if ((iVar2 != 0) && ((*(ushort *)(iVar2 + 4) & 8) != 0)) {
    dVar17 = (double)FUN_80291e40((double)((*(float *)(iVar8 + 0xc) - FLOAT_803dcdd8) /
                                          FLOAT_803e3fc0));
    local_98 = (longlong)(int)dVar17;
    dVar18 = (double)FUN_80291e40((double)((*(float *)(iVar8 + 0x14) - FLOAT_803dcddc) /
                                          FLOAT_803e3fc0));
    local_90 = (longlong)(int)dVar18;
    uStack132 = (int)dVar17 ^ 0x80000000;
    local_88 = 0x43300000;
    dVar20 = (double)(*(float *)(iVar8 + 0xc) -
                     (FLOAT_803e3fc0 *
                      (float)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e3fc8) +
                     FLOAT_803dcdd8));
    local_80 = (double)CONCAT44(0x43300000,(int)dVar18 ^ 0x80000000);
    dVar18 = (double)(*(float *)(iVar8 + 0x14) -
                     (FLOAT_803e3fc0 * (float)(local_80 - DOUBLE_803e3fc8) + FLOAT_803dcddc));
    iVar10 = 0;
    *(undefined *)((int)piVar6 + 0x2a) = 0;
    dVar17 = (double)((float)piVar6[5] * (float)piVar6[5]);
    iVar9 = 0;
    for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar2 + 0x9a); iVar8 = iVar8 + 1) {
      puVar3 = (ushort *)FUN_800606ec(iVar2,iVar8);
      uVar4 = FUN_80060678();
      if (*(byte *)(param_3 + 0x25) == uVar4) {
        dVar19 = (double)FLOAT_803e3fc4;
        iVar11 = iVar9;
        iVar12 = iVar10;
        for (uVar4 = (uint)*puVar3; (int)uVar4 < (int)(uint)puVar3[10]; uVar4 = uVar4 + 1) {
          puVar5 = (ushort *)FUN_800606dc(iVar2,uVar4);
          iVar7 = 0;
          iVar13 = iVar11;
          iVar14 = iVar12;
          do {
            FUN_800605f0(*(int *)(iVar2 + 0x58) + (uint)*puVar5 * 6,&local_a8);
            dVar16 = (double)(float)((double)((float)((double)local_a8 - dVar20) *
                                              (float)((double)local_a8 - dVar20) +
                                             (float)((double)local_a0 - dVar18) *
                                             (float)((double)local_a0 - dVar18)) / dVar17);
            if (dVar19 < dVar16) {
              dVar16 = dVar19;
            }
            *(float *)(*piVar6 + iVar14) = (float)(dVar19 - (double)(float)(dVar16 * dVar16));
            local_80 = (double)(longlong)(int)local_a4;
            *(short *)(piVar6[1] + iVar13) = (short)(int)local_a4;
            iVar14 = iVar14 + 4;
            iVar13 = iVar13 + 2;
            iVar12 = iVar12 + 4;
            iVar11 = iVar11 + 2;
            iVar10 = iVar10 + 4;
            iVar9 = iVar9 + 2;
            puVar5 = puVar5 + 1;
            iVar7 = iVar7 + 1;
          } while (iVar7 < 3);
        }
        bVar1 = *(byte *)((int)piVar6 + 0x2a);
        *(byte *)((int)piVar6 + 0x2a) = bVar1 + 1;
        *(short *)((int)piVar6 + (uint)bVar1 * 2 + 0x1c) = (short)iVar8;
      }
    }
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  __psq_l0(auStack40,uVar15);
  __psq_l1(auStack40,uVar15);
  __psq_l0(auStack56,uVar15);
  __psq_l1(auStack56,uVar15);
  FUN_80286104();
  return;
}

