// Function: FUN_800e3734
// Entry: 800e3734
// Size: 560 bytes

/* WARNING: Removing unreachable block (ram,0x800e3948) */
/* WARNING: Removing unreachable block (ram,0x800e3940) */
/* WARNING: Removing unreachable block (ram,0x800e3938) */
/* WARNING: Removing unreachable block (ram,0x800e3930) */
/* WARNING: Removing unreachable block (ram,0x800e375c) */
/* WARNING: Removing unreachable block (ram,0x800e3754) */
/* WARNING: Removing unreachable block (ram,0x800e374c) */
/* WARNING: Removing unreachable block (ram,0x800e3744) */

void FUN_800e3734(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 *param_6,undefined4 *param_7,undefined4 *param_8)

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
  double dVar12;
  double extraout_f1;
  double dVar13;
  double dVar14;
  double in_f28;
  double dVar15;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar16;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar17;
  float local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar17 = FUN_80286828();
  fVar1 = FLOAT_803e12b8;
  *param_8 = FLOAT_803e12b8;
  *param_7 = fVar1;
  *param_6 = fVar1;
  dVar16 = (double)FLOAT_803e12c4;
  iVar8 = 0;
  piVar10 = &DAT_803a2448;
  dVar15 = extraout_f1;
  do {
    if (DAT_803de0f0 <= iVar8) {
      FUN_80286874();
      return;
    }
    iVar9 = *piVar10;
    if (((int)*(char *)(iVar9 + 0x18) == (int)uVar17) &&
       ((int)*(char *)(iVar9 + 0x19) == (int)((ulonglong)uVar17 >> 0x20))) {
      local_98 = *(float *)(iVar9 + 8);
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
            iVar4 = DAT_803de0f0 + -1;
            iVar3 = 0;
            while (iVar3 <= iVar4) {
              iVar2 = iVar4 + iVar3 >> 1;
              iVar6 = (&DAT_803a2448)[iVar2];
              if (*(uint *)(iVar6 + 0x14) < uVar5) {
                iVar3 = iVar2 + 1;
              }
              else {
                if (*(uint *)(iVar6 + 0x14) <= uVar5) goto LAB_800e3878;
                iVar4 = iVar2 + -1;
              }
            }
            iVar6 = 0;
          }
LAB_800e3878:
          if (iVar6 != 0) {
            local_8c = *(undefined4 *)(iVar6 + 8);
            local_88 = *(undefined4 *)(iVar6 + 0xc);
            local_84 = *(undefined4 *)(iVar6 + 0x10);
            dVar13 = FUN_800e4e68(dVar15,param_2,param_3,&local_98);
            dVar14 = dVar16;
            if (dVar16 < (double)FLOAT_803e12b8) {
              dVar14 = -dVar16;
            }
            dVar12 = dVar13;
            if (dVar13 < (double)FLOAT_803e12b8) {
              dVar12 = -dVar13;
            }
            if (dVar12 < dVar14) {
              DAT_803de0e8 = iVar6;
              DAT_803de0ec = iVar9;
              *param_6 = local_80;
              *param_7 = local_7c;
              *param_8 = local_78;
              dVar16 = dVar13;
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

