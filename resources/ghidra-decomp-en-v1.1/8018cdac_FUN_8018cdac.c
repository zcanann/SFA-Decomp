// Function: FUN_8018cdac
// Entry: 8018cdac
// Size: 1116 bytes

/* WARNING: Removing unreachable block (ram,0x8018d1e8) */
/* WARNING: Removing unreachable block (ram,0x8018d1e0) */
/* WARNING: Removing unreachable block (ram,0x8018d1d8) */
/* WARNING: Removing unreachable block (ram,0x8018d1d0) */
/* WARNING: Removing unreachable block (ram,0x8018cdd4) */
/* WARNING: Removing unreachable block (ram,0x8018cdcc) */
/* WARNING: Removing unreachable block (ram,0x8018cdc4) */
/* WARNING: Removing unreachable block (ram,0x8018cdbc) */

void FUN_8018cdac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  float fVar2;
  int iVar3;
  undefined2 *puVar4;
  int iVar5;
  byte bVar8;
  undefined4 *puVar6;
  int iVar7;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar9;
  undefined8 uVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  
  iVar3 = FUN_80286840();
  puVar4 = FUN_8000facc();
  pfVar9 = *(float **)(iVar3 + 0xb8);
  iVar5 = FUN_8002bac4();
  bVar1 = false;
  bVar8 = FUN_802973bc(iVar5);
  if (bVar8 == 0) {
    pfVar9[5] = FLOAT_803e49c4;
    iVar5 = (**(code **)(*DAT_803dd6cc + 0x14))();
    bVar1 = iVar5 != 0;
    if (bVar1) {
      param_2 = (double)FLOAT_803dc074;
      FUN_8002fb40((double)FLOAT_803e49b8,param_2);
    }
    if (FLOAT_803e49bc < *(float *)(iVar3 + 0x98)) {
      puVar6 = (undefined4 *)FUN_800395a4(iVar3,5);
      *puVar6 = 0x200;
      puVar6 = (undefined4 *)FUN_800395a4(iVar3,4);
      *puVar6 = 0x200;
    }
    *pfVar9 = *pfVar9 - FLOAT_803dc074;
    fVar2 = *pfVar9;
    if (((double)fVar2 <= (double)FLOAT_803e49b4) &&
       (*pfVar9 = FLOAT_803e49b4, -1 < *(char *)(pfVar9 + 8))) {
      FUN_8011e06c((double)fVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      *(byte *)(pfVar9 + 8) = *(byte *)(pfVar9 + 8) & 0x7f | 0x80;
    }
  }
  else {
    pfVar9[5] = FLOAT_803e49b0;
    if (*(short *)(iVar3 + 0xa0) != 0x92) {
      uVar10 = FUN_8000d03c();
      FUN_8000d220(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8003042c((double)FLOAT_803e49b4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   iVar3,0x92,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    }
    dVar14 = (double)FLOAT_803dc074;
    FUN_8002fb40((double)FLOAT_803e49b8,dVar14);
    if (FLOAT_803e49bc < *(float *)(iVar3 + 0x98)) {
      puVar6 = (undefined4 *)FUN_800395a4(iVar3,5);
      *puVar6 = 0;
      puVar6 = (undefined4 *)FUN_800395a4(iVar3,4);
      *puVar6 = 0;
    }
    if (*(float *)(iVar3 + 0x98) < FLOAT_803e49c0) {
      bVar1 = true;
    }
    else {
      if ((*(byte *)(pfVar9 + 8) >> 5 & 1) == 0) {
        FUN_800d7cfc(0);
        (**(code **)(*DAT_803dd6cc + 0xc))(10,1);
        *(byte *)(pfVar9 + 8) = *(byte *)(pfVar9 + 8) & 0xdf | 0x20;
      }
      iVar7 = (**(code **)(*DAT_803dd6cc + 0x14))();
      if (iVar7 != 0) {
        if (iVar5 != 0) {
          FUN_802973cc(iVar5,0);
        }
        FUN_800207ac(0);
        uVar10 = FUN_8005d0e4(0);
        FUN_8002cc9c(uVar10,dVar14,param_3,param_4,param_5,param_6,param_7,param_8,iVar3);
      }
    }
  }
  if (bVar1) {
    dVar14 = (double)FUN_802945e0();
    dVar11 = (double)FUN_80294964();
    dVar12 = (double)FUN_80294964();
    dVar13 = (double)FUN_802945e0();
    dVar15 = (double)(float)((double)pfVar9[4] * dVar13);
    dVar12 = (double)(float)((double)pfVar9[4] * dVar12);
    dVar16 = (double)(float)(dVar12 * dVar11);
    dVar13 = (double)(float)(dVar12 * dVar14);
    *puVar4 = 0x2000;
    puVar4[1] = 0x1000;
    dVar14 = (double)FUN_802945e0();
    dVar12 = (double)(float)((double)FLOAT_803e49d0 * -dVar14);
    dVar14 = (double)FUN_80294964();
    dVar11 = (double)FLOAT_803e49d0;
    *(float *)(puVar4 + 6) =
         (float)(dVar16 + (double)(float)((double)*(float *)(iVar3 + 0x18) + dVar12));
    *(float *)(puVar4 + 8) =
         (float)((double)(float)(dVar11 + (double)*(float *)(iVar3 + 0x1c)) + dVar15);
    *(float *)(puVar4 + 10) =
         (float)(dVar13 + (double)(*(float *)(iVar3 + 0x20) + (float)(dVar11 * -dVar14)));
    FUN_8000fc5c((double)FLOAT_803e49dc);
    *(byte *)(pfVar9 + 8) = *(byte *)(pfVar9 + 8) & 0xbf | 0x40;
    dVar14 = FUN_80021434((double)(pfVar9[5] - pfVar9[4]),(double)FLOAT_803e49e0,
                          (double)FLOAT_803dc074);
    pfVar9[4] = (float)((double)pfVar9[4] + dVar14);
    FUN_80055220(0);
  }
  else {
    *puVar4 = SUB42(pfVar9[6],0);
    puVar4[1] = SUB42(pfVar9[7],0);
    *(float *)(puVar4 + 6) = pfVar9[1];
    *(float *)(puVar4 + 8) = pfVar9[2];
    *(float *)(puVar4 + 10) = pfVar9[3];
    *(byte *)(pfVar9 + 8) = *(byte *)(pfVar9 + 8) & 0xbf;
  }
  if ((*(byte *)(pfVar9 + 8) >> 6 & 1) == 0) {
    *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
  }
  else {
    *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xbfff;
  }
  FUN_8028688c();
  return;
}

