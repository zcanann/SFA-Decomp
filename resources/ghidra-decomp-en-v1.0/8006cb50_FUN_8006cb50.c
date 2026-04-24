// Function: FUN_8006cb50
// Entry: 8006cb50
// Size: 464 bytes

void FUN_8006cb50(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  double dVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double local_18;
  
  DAT_803dcfbc = FUN_80054c98(0x100,0x100,3,0,0,0,0,1,1);
  dVar5 = DOUBLE_803dedc8;
  fVar4 = FLOAT_803dedc0;
  fVar3 = FLOAT_803dedbc;
  fVar2 = FLOAT_803dedac;
  uVar6 = 0;
  dVar13 = (double)FLOAT_803ded28;
  dVar12 = (double)FLOAT_803dedb8;
  do {
    uVar7 = 0;
    local_18 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
    dVar9 = (double)((float)(local_18 - dVar5) - fVar2);
    iVar8 = 0x100;
    do {
      local_18 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      dVar10 = (double)((float)(local_18 - dVar5) - fVar2);
      dVar14 = (double)(float)(dVar9 * dVar9 + (double)(float)(dVar10 * dVar10));
      if (dVar13 < dVar14) {
        dVar11 = 1.0 / SQRT(dVar14);
        dVar11 = DOUBLE_803ded58 * dVar11 * -(dVar14 * dVar11 * dVar11 - DOUBLE_803ded60);
        dVar11 = DOUBLE_803ded58 * dVar11 * -(dVar14 * dVar11 * dVar11 - DOUBLE_803ded60);
        dVar14 = (double)(float)(dVar14 * DOUBLE_803ded58 * dVar11 *
                                          -(dVar14 * dVar11 * dVar11 - DOUBLE_803ded60));
      }
      fVar1 = FLOAT_803ded28;
      if (dVar14 <= dVar12) {
        fVar1 = FLOAT_803ded34 * -(float)((double)FLOAT_803ded48 * dVar14 - (double)FLOAT_803dedb0)
                * FLOAT_803dedb4;
      }
      *(ushort *)
       (DAT_803dcfbc + (uVar6 & 3) * 2 + ((int)uVar6 >> 2) * 0x20 + (uVar7 & 3) * 8 +
        ((int)uVar7 >> 2) * 0x800 + 0x60) =
           (ushort)(int)(fVar4 * (float)(dVar10 / dVar14) * fVar1 + fVar3) |
           (ushort)(((int)(fVar4 * (float)(dVar9 / dVar14) * fVar1 + fVar3) & 0xffffU) << 8);
      uVar7 = uVar7 + 1;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
    uVar6 = uVar6 + 1;
  } while ((int)uVar6 < 0x100);
  FUN_802419e8(DAT_803dcfbc + 0x60,*(undefined4 *)(DAT_803dcfbc + 0x44));
  return;
}

