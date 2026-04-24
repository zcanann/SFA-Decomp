// Function: FUN_80124c7c
// Entry: 80124c7c
// Size: 1000 bytes

/* WARNING: Removing unreachable block (ram,0x80125044) */
/* WARNING: Removing unreachable block (ram,0x8012503c) */
/* WARNING: Removing unreachable block (ram,0x80125034) */
/* WARNING: Removing unreachable block (ram,0x80124c9c) */
/* WARNING: Removing unreachable block (ram,0x80124c94) */
/* WARNING: Removing unreachable block (ram,0x80124c8c) */

void FUN_80124c7c(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  char *pcVar7;
  float *pfVar8;
  double dVar9;
  double in_f29;
  double dVar10;
  double in_f30;
  double dVar11;
  double in_f31;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  char acStack_89 [5];
  float local_84 [4];
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
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
  uVar12 = FUN_8028682c();
  uVar1 = (undefined4)((ulonglong)uVar12 >> 0x20);
  uVar3 = (undefined4)uVar12;
  FUN_8000facc();
  iVar4 = 0;
  if (DAT_803de454 == '\x03') {
    iVar4 = 1;
  }
  else if (DAT_803de454 < '\x03') {
    if ('\x01' < DAT_803de454) {
      iVar4 = 0;
    }
  }
  else if (DAT_803de454 < '\x05') {
    iVar4 = 2;
  }
  uStack_74 = -(int)DAT_803de416 * (uint)DAT_803dc698 ^ 0x80000000;
  local_84[3] = 176.0;
  *(float *)((&DAT_803aa040)[iVar4] + 0x10) =
       FLOAT_803e2ac0 +
       (float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e2af8) / FLOAT_803e2c9c;
  dVar11 = (double)FLOAT_803dc730;
  dVar10 = (double)FLOAT_803dc72c;
  dVar9 = FUN_8000fc54();
  FLOAT_803dc70c = (float)dVar9;
  FUN_8000fc5c((double)FLOAT_803e2ca0);
  FUN_8000f478(1);
  DAT_803de460 = FUN_8000fae4();
  FUN_8000faec();
  dVar9 = (double)FLOAT_803e2abc;
  FUN_8000f530(dVar9,dVar9,dVar9);
  FUN_8000f500(0x8000,0,0);
  FUN_8000f584();
  FUN_8000fb20();
  uStack_6c = (uint)*(ushort *)(DAT_803dd970 + 4);
  local_70 = 0x43300000;
  uStack_64 = (uint)*(ushort *)(DAT_803dd970 + 6);
  local_68 = 0x43300000;
  FUN_8025da64((double)(float)(dVar10 - (double)FLOAT_803e2bb4),
               (double)(float)(dVar11 - (double)FLOAT_803e2ca4),
               (double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e2b08),
               (double)(float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e2b08),
               (double)FLOAT_803e2abc,(double)FLOAT_803e2ae8);
  iVar4 = 0;
  pcVar7 = acStack_89;
  puVar6 = &DAT_803aa04c;
  pfVar8 = local_84;
  do {
    pcVar7 = pcVar7 + 1;
    *pcVar7 = '\0';
    uStack_64 = (int)*(short *)*puVar6 ^ 0x80000000;
    local_68 = 0x43300000;
    dVar9 = (double)FUN_80294964();
    *pfVar8 = (float)dVar9;
    puVar6 = puVar6 + 1;
    pfVar8 = pfVar8 + 1;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 3);
  iVar4 = 0;
  dVar9 = (double)FLOAT_803e2abc;
  do {
    dVar10 = (double)FLOAT_803e2b44;
    iVar5 = -1;
    if ((acStack_89[1] == '\0') && ((double)local_84[0] < dVar10)) {
      iVar5 = 0;
      dVar10 = (double)local_84[0];
    }
    if ((acStack_89[2] == '\0') && ((double)local_84[1] < dVar10)) {
      iVar5 = 1;
      dVar10 = (double)local_84[1];
    }
    if ((acStack_89[3] == '\0') && ((double)local_84[2] < dVar10)) {
      iVar5 = 2;
      dVar10 = (double)local_84[2];
    }
    if (iVar5 == -1) break;
    iVar2 = FUN_8002b660((&DAT_803aa04c)[iVar5]);
    *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
    *(char *)((&DAT_803aa04c)[iVar5] + 0x37) = (char)DAT_803de418;
    iVar2 = FUN_8002b660((&DAT_803aa040)[iVar5]);
    *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
    iVar2 = (int)((int)DAT_803de418 * (uint)DAT_803de554) / 0xff +
            ((int)((int)DAT_803de418 * (uint)DAT_803de554) >> 0x1f);
    *(char *)((&DAT_803aa040)[iVar5] + 0x37) = (char)iVar2 - (char)(iVar2 >> 0x1f);
    if (dVar10 <= dVar9) {
      FUN_8003ba50(uVar1,uVar3,param_3,0,(&DAT_803aa04c)[iVar5],1);
    }
    else {
      FUN_8003ba50(uVar1,uVar3,param_3,0,(&DAT_803aa04c)[iVar5],1);
      FUN_8025da88(0,0x79,0x280,0x95);
      FUN_8003ba50(uVar1,uVar3,param_3,0,(&DAT_803aa040)[iVar5],1);
      FUN_8025da88(0,0,0x280,0x1e0);
    }
    acStack_89[iVar5 + 1] = '\x01';
    iVar4 = iVar4 + 1;
  } while (iVar4 < 3);
  FUN_8000f478(0);
  if (DAT_803de460 != 0) {
    FUN_8000faf8();
  }
  FUN_8000f584();
  FUN_8000fc5c((double)FLOAT_803dc70c);
  FUN_8000fb20();
  FUN_8000f7a0();
  FUN_80286878();
  return;
}

