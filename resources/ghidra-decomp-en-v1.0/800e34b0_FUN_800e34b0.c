// Function: FUN_800e34b0
// Entry: 800e34b0
// Size: 560 bytes

/* WARNING: Removing unreachable block (ram,0x800e36bc) */
/* WARNING: Removing unreachable block (ram,0x800e36ac) */
/* WARNING: Removing unreachable block (ram,0x800e36b4) */
/* WARNING: Removing unreachable block (ram,0x800e36c4) */

void FUN_800e34b0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4,
                 undefined4 param_5,float *param_6,float *param_7,float *param_8)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int *piVar10;
  int iVar11;
  undefined4 uVar12;
  double dVar13;
  undefined8 extraout_f1;
  double dVar14;
  double dVar15;
  undefined8 in_f28;
  undefined8 uVar16;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar17;
  undefined8 uVar18;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  float local_80;
  float local_7c;
  float local_78;
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
  uVar18 = FUN_802860c4();
  fVar1 = FLOAT_803e0638;
  *param_8 = FLOAT_803e0638;
  *param_7 = fVar1;
  *param_6 = fVar1;
  dVar17 = (double)FLOAT_803e0644;
  iVar8 = 0;
  piVar10 = &DAT_803a17e8;
  uVar16 = extraout_f1;
  do {
    if (DAT_803dd478 <= iVar8) {
      __psq_l0(auStack8,uVar12);
      __psq_l1(auStack8,uVar12);
      __psq_l0(auStack24,uVar12);
      __psq_l1(auStack24,uVar12);
      __psq_l0(auStack40,uVar12);
      __psq_l1(auStack40,uVar12);
      __psq_l0(auStack56,uVar12);
      __psq_l1(auStack56,uVar12);
      FUN_80286110(dVar17);
      return;
    }
    iVar9 = *piVar10;
    if (((int)*(char *)(iVar9 + 0x18) == (int)uVar18) &&
       ((int)*(char *)(iVar9 + 0x19) == (int)((ulonglong)uVar18 >> 0x20))) {
      local_98 = *(undefined4 *)(iVar9 + 8);
      local_94 = *(undefined4 *)(iVar9 + 0xc);
      local_90 = *(undefined4 *)(iVar9 + 0x10);
      iVar7 = 0;
      iVar11 = iVar9;
      do {
        if (((int)*(char *)(iVar9 + 0x1b) & 1 << iVar7) == 0) {
          uVar5 = *(uint *)(iVar11 + 0x1c);
          if ((int)uVar5 < 0) {
            iVar6 = 0;
          }
          else {
            iVar4 = DAT_803dd478 + -1;
            iVar3 = 0;
            while (iVar3 <= iVar4) {
              iVar2 = iVar4 + iVar3 >> 1;
              iVar6 = (&DAT_803a17e8)[iVar2];
              if (*(uint *)(iVar6 + 0x14) < uVar5) {
                iVar3 = iVar2 + 1;
              }
              else {
                if (*(uint *)(iVar6 + 0x14) <= uVar5) goto LAB_800e35f4;
                iVar4 = iVar2 + -1;
              }
            }
            iVar6 = 0;
          }
LAB_800e35f4:
          if (iVar6 != 0) {
            local_8c = *(undefined4 *)(iVar6 + 8);
            local_88 = *(undefined4 *)(iVar6 + 0xc);
            local_84 = *(undefined4 *)(iVar6 + 0x10);
            dVar14 = (double)FUN_800e4be4(uVar16,param_2,param_3,&local_98);
            dVar15 = dVar17;
            if (dVar17 < (double)FLOAT_803e0638) {
              dVar15 = -dVar17;
            }
            dVar13 = dVar14;
            if (dVar14 < (double)FLOAT_803e0638) {
              dVar13 = -dVar14;
            }
            if (dVar13 < dVar15) {
              DAT_803dd470 = iVar6;
              DAT_803dd474 = iVar9;
              *param_6 = local_80;
              *param_7 = local_7c;
              *param_8 = local_78;
              dVar17 = dVar14;
            }
          }
        }
        iVar11 = iVar11 + 4;
        iVar7 = iVar7 + 1;
      } while (iVar7 < 4);
    }
    piVar10 = piVar10 + 1;
    iVar8 = iVar8 + 1;
  } while( true );
}

