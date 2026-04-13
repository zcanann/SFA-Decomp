// Function: FUN_80125708
// Entry: 80125708
// Size: 1920 bytes

/* WARNING: Removing unreachable block (ram,0x80125e68) */
/* WARNING: Removing unreachable block (ram,0x80125e60) */
/* WARNING: Removing unreachable block (ram,0x80125e58) */
/* WARNING: Removing unreachable block (ram,0x80125e50) */
/* WARNING: Removing unreachable block (ram,0x80125e48) */
/* WARNING: Removing unreachable block (ram,0x80125738) */
/* WARNING: Removing unreachable block (ram,0x80125730) */
/* WARNING: Removing unreachable block (ram,0x80125728) */
/* WARNING: Removing unreachable block (ram,0x80125720) */
/* WARNING: Removing unreachable block (ram,0x80125718) */

void FUN_80125708(void)

{
  ushort uVar1;
  short sVar3;
  uint uVar2;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  undefined8 local_b8;
  undefined8 local_a8;
  
  FUN_80286824();
  if (DAT_803de4da != '\0') {
    if (DAT_803de428 == '\0') {
      DAT_803de4d8 = DAT_803de4d8 + (ushort)DAT_803dc070 * 5;
      if (0x152 < DAT_803de4d8) {
        DAT_803de4d8 = 0x152;
        DAT_803de4da = '\0';
        if (*(int *)(&DAT_8031bb84 + (uint)DAT_803de4db * 0xc) != -1) {
          FUN_8000d03c();
          FUN_8000cf74();
        }
      }
      DAT_803de4d6 = DAT_803de4d6 + (ushort)DAT_803dc070 * -10;
      DAT_803de4d4 = DAT_803de4d4 + (ushort)DAT_803dc070 * -0x17;
    }
    else {
      DAT_803de4d8 = DAT_803de4d8 + (ushort)DAT_803dc070 * -5;
      if (DAT_803de4d8 < 0x122) {
        DAT_803de4d8 = 0x122;
      }
      DAT_803de4d6 = DAT_803de4d6 + (ushort)DAT_803dc070 * 10;
      DAT_803de4d4 = DAT_803de4d4 + (ushort)DAT_803dc070 * 0x17;
    }
    uVar1 = DAT_803de4d8;
    if (DAT_803de4d4 < 0) {
      sVar3 = 0;
    }
    else {
      sVar3 = DAT_803de4d4;
      if (0xff < DAT_803de4d4) {
        sVar3 = 0xff;
      }
    }
    uVar8 = (uint)sVar3;
    uVar2 = (uint)DAT_803de4d6;
    if (0x6e < uVar2) {
      uVar2 = 0x6e;
    }
    uVar9 = (uint)DAT_803de4d8;
    uVar6 = (uint)(byte)(&DAT_8031bb8a)[(uint)DAT_803de4db * 0xc];
    if (uVar6 == 2) {
      uVar7 = 0x186;
    }
    else if ((uVar6 < 2) || (3 < uVar6)) {
      uVar7 = 0x19a;
    }
    else {
      uVar7 = 0x195;
    }
    DAT_803de4d4 = sVar3;
    DAT_803de4d6 = (short)uVar2;
    FUN_8025da88(0x1ea,uVar9,0x78,uVar2);
    FUN_8007668c((double)FLOAT_803e2cc0,
                 (double)(float)((double)CONCAT44(0x43300000,uVar9 ^ 0x80000000) - DOUBLE_803e2af8),
                 0x78,uVar2);
    dVar10 = FUN_8000fc54();
    FLOAT_803dc70c = (float)dVar10;
    FUN_8000fc5c((double)FLOAT_803e2cc4);
    FUN_8000f478(1);
    DAT_803de460 = FUN_8000fae4();
    FUN_8000faec();
    dVar10 = (double)FLOAT_803e2abc;
    FUN_8000f530(dVar10,dVar10,dVar10);
    FUN_8000f500(0x8000,0,0);
    FUN_8000f584();
    FUN_8000fb20();
    local_b8 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 4));
    FUN_8025da64((double)FLOAT_803e2cc8,
                 (double)((float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803e2af8)
                         - FLOAT_803e2ca4),(double)(float)(local_b8 - DOUBLE_803e2b08),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 6)) -
                                DOUBLE_803e2b08),(double)FLOAT_803e2abc,(double)FLOAT_803e2ae8);
    if ((&DAT_803aa058)[uVar6] != 0) {
      FUN_8002fb40((double)*(float *)(&DAT_8031cbf8 + uVar6 * 4),(double)FLOAT_803dc074);
      if (0x90000000 < *(uint *)((&DAT_803aa058)[uVar6] + 0x4c)) {
        *(undefined4 *)((&DAT_803aa058)[uVar6] + 0x4c) = 0;
      }
      *(undefined *)((&DAT_803aa058)[uVar6] + 0x37) = 0xff;
      FUN_8003ba50(0,0,0,0,(&DAT_803aa058)[uVar6],1);
      iVar4 = FUN_8002b660((&DAT_803aa058)[uVar6]);
      *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
    }
    FUN_8000f478(0);
    if (DAT_803de460 != 0) {
      FUN_8000faf8();
    }
    FUN_8000f584();
    FUN_8000fc5c((double)FLOAT_803dc70c);
    FUN_8000fb20();
    FUN_8000f7a0();
    FUN_8025da88(0,0,0x280,0x1e0);
    DAT_803de3fc = DAT_803de3fc + 1;
    dVar12 = (double)FLOAT_803e2ccc;
    dVar14 = (double)FLOAT_803e2cd0;
    dVar15 = (double)FLOAT_803e2c90;
    dVar10 = DOUBLE_803e2af8;
    for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 4) {
      dVar11 = (double)FUN_80293994();
      dVar13 = (double)(float)(dVar12 * dVar11);
      dVar11 = (double)FUN_80293994();
      dVar11 = (double)(float)(dVar12 * dVar11 + dVar13);
      uVar6 = (uint)((float)((double)CONCAT44(0x43300000,(int)sVar3 ^ 0x80000000U) - dVar10) *
                    (float)(dVar14 + dVar11));
      if ((int)uVar6 < 0) {
        uVar6 = 0;
      }
      uVar7 = FUN_80022264(0,0x1e);
      uVar5 = FUN_80022264(0,0x1e);
      if (0xff < (int)uVar6) {
        uVar6 = 0xff;
      }
      FUN_80076144((double)FLOAT_803e2cc0,
                   (double)(float)((double)CONCAT44(0x43300000,uVar9 + iVar4 ^ 0x80000000) - dVar10)
                   ,DAT_803a9760,uVar6 & 0xff,0x100,0x78,2,uVar5 << 1,uVar7 << 1);
      uVar6 = (uint)((float)((double)CONCAT44(0x43300000,(int)sVar3 ^ 0x80000000U) - dVar10) *
                    (float)(dVar15 + dVar11));
      if ((int)uVar6 < 0) {
        uVar6 = 0;
      }
      uVar7 = FUN_80022264(0,0x1e);
      uVar5 = FUN_80022264(0,0x1e);
      if (0xff < (int)uVar6) {
        uVar6 = 0xff;
      }
      FUN_80076144((double)FLOAT_803e2cc0,
                   (double)(float)((double)CONCAT44(0x43300000,uVar9 + iVar4 + 2 ^ 0x80000000) -
                                  dVar10),DAT_803a9760,uVar6 & 0xff,0x100,0x78,2,uVar5 << 1,
                   uVar7 << 1);
    }
    uVar9 = (uint)(short)uVar1;
    uVar6 = uVar9 - 5;
    FUN_80077318((double)FLOAT_803e2cd4,
                 (double)(float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a9638,uVar8 & 0xff,0x100);
    local_a8 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
    FUN_80076998((double)FLOAT_803e2cc0,(double)(float)(local_a8 - DOUBLE_803e2af8),DAT_803a9644,
                 uVar8 & 0xff,0x100,0x78,5,0);
    iVar4 = (int)(short)uVar2;
    FUN_80076998((double)FLOAT_803e2cd4,
                 (double)(float)((double)CONCAT44(0x43300000,uVar9 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a963c,uVar8 & 0xff,0x100,5,iVar4,0);
    uVar2 = uVar9 + iVar4;
    local_b8 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    FUN_80076998((double)FLOAT_803e2cc0,(double)(float)(local_b8 - DOUBLE_803e2af8),DAT_803a9644,
                 uVar8 & 0xff,0x100,0x78,5,2);
    FUN_80076998((double)FLOAT_803e2cd8,
                 (double)(float)((double)CONCAT44(0x43300000,uVar9 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a963c,uVar8 & 0xff,0x100,5,iVar4,1);
    FUN_80076998((double)FLOAT_803e2cd8,
                 (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a9638,uVar8 & 0xff,0x100,5,5,3);
    FUN_80076998((double)FLOAT_803e2cd8,
                 (double)(float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a9638,uVar8 & 0xff,0x100,5,5,1);
    FUN_80076998((double)FLOAT_803e2cd4,
                 (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e2af8),
                 DAT_803a9638,uVar8 & 0xff,0x100,5,5,2);
  }
  FUN_80286870();
  return;
}

