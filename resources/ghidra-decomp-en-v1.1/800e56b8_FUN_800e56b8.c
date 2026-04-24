// Function: FUN_800e56b8
// Entry: 800e56b8
// Size: 624 bytes

/* WARNING: Removing unreachable block (ram,0x800e5908) */
/* WARNING: Removing unreachable block (ram,0x800e5900) */
/* WARNING: Removing unreachable block (ram,0x800e58f8) */
/* WARNING: Removing unreachable block (ram,0x800e58f0) */
/* WARNING: Removing unreachable block (ram,0x800e56e0) */
/* WARNING: Removing unreachable block (ram,0x800e56d8) */
/* WARNING: Removing unreachable block (ram,0x800e56d0) */
/* WARNING: Removing unreachable block (ram,0x800e56c8) */

void FUN_800e56b8(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  uint *puVar5;
  undefined4 *puVar6;
  uint uVar7;
  int iVar8;
  float *pfVar9;
  uint *puVar10;
  double dVar11;
  double in_f28;
  double dVar12;
  double in_f29;
  double dVar13;
  double in_f30;
  double dVar14;
  double in_f31;
  double dVar15;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar16;
  undefined4 *local_98;
  float local_94 [5];
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
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
  uVar16 = FUN_8028683c();
  iVar2 = (int)((ulonglong)uVar16 >> 0x20);
  puVar5 = (uint *)uVar16;
  if ((int)(uint)*(byte *)(puVar5 + 0x97) >> 4 == 4) {
    dVar12 = (double)FLOAT_803e12e8;
    uVar7 = 0;
    pfVar9 = local_94;
    puVar10 = puVar5;
    dVar13 = dVar12;
    dVar14 = dVar12;
    dVar15 = dVar12;
    for (iVar8 = 0; dVar11 = DOUBLE_803e12f0, iVar8 < (int)(uint)*(byte *)(puVar5 + 0x97) >> 4;
        iVar8 = iVar8 + 1) {
      *pfVar9 = (float)puVar10[3];
      iVar3 = FUN_80065fcc((double)(float)puVar10[2],(double)*(float *)(iVar2 + 0x1c),
                           (double)(float)puVar10[4],iVar2,&local_98,-1,0);
      bVar1 = false;
      if ((iVar3 != 0) && (puVar6 = local_98, 0 < iVar3)) {
        do {
          if (!bVar1) {
            pfVar4 = (float *)*puVar6;
            dVar11 = (double)*pfVar4;
            if ((dVar11 < (double)(FLOAT_803e12ec + *(float *)(iVar2 + 0x1c))) &&
               (*(char *)(pfVar4 + 5) != '\x0e')) {
              *pfVar9 = *pfVar4;
              dVar15 = (double)(float)(dVar15 + (double)pfVar4[1]);
              dVar14 = (double)(float)(dVar14 + (double)pfVar4[2]);
              dVar13 = (double)(float)(dVar13 + (double)pfVar4[3]);
              dVar12 = (double)(float)(dVar12 + dVar11);
              uVar7 = uVar7 + 1;
              bVar1 = true;
            }
          }
          iVar3 = iVar3 + -1;
          puVar6 = puVar6 + 1;
        } while (iVar3 != 0);
      }
      puVar10[3] = (uint)*pfVar9;
      puVar10 = puVar10 + 3;
      pfVar9 = pfVar9 + 1;
    }
    if (uVar7 == 0) {
      *(undefined *)((int)puVar5 + 0x261) = 0;
    }
    else {
      uStack_7c = uVar7 ^ 0x80000000;
      local_80 = 0x43300000;
      *(float *)(iVar2 + 0x1c) =
           (float)(dVar12 / (double)(float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e12f0
                                           ));
      local_78 = 0x43300000;
      puVar5[0x68] = (uint)(float)(dVar15 / (double)(float)((double)CONCAT44(0x43300000,uStack_7c) -
                                                           dVar11));
      local_70 = 0x43300000;
      puVar5[0x69] = (uint)(float)(dVar14 / (double)(float)((double)CONCAT44(0x43300000,uStack_7c) -
                                                           dVar11));
      local_68 = 0x43300000;
      puVar5[0x6a] = (uint)(float)(dVar13 / (double)(float)((double)CONCAT44(0x43300000,uStack_7c) -
                                                           dVar11));
      *(undefined *)((int)puVar5 + 0x261) = 1;
      uStack_74 = uStack_7c;
      uStack_6c = uStack_7c;
      uStack_64 = uStack_7c;
    }
    FUN_80021884();
    iVar8 = FUN_80021884();
    *(short *)(iVar2 + 2) = -(short)iVar8;
    if ((*puVar5 & 0x400) != 0) {
      iVar8 = FUN_80021884();
      *(short *)(iVar2 + 4) = (short)iVar8;
    }
  }
  FUN_80286888();
  return;
}

