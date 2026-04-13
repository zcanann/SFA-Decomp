// Function: FUN_8006cccc
// Entry: 8006cccc
// Size: 464 bytes

void FUN_8006cccc(void)

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
  undefined8 local_18;
  
  DAT_803ddc3c = FUN_80054e14(0x100,0x100,3,'\0',0,0,0,1,1);
  dVar5 = DOUBLE_803dfa48;
  fVar4 = FLOAT_803dfa40;
  fVar3 = FLOAT_803dfa3c;
  fVar2 = FLOAT_803dfa2c;
  uVar6 = 0;
  dVar13 = (double)FLOAT_803df9a8;
  dVar12 = (double)FLOAT_803dfa38;
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
        dVar11 = DOUBLE_803df9d8 * dVar11 * -(dVar14 * dVar11 * dVar11 - DOUBLE_803df9e0);
        dVar11 = DOUBLE_803df9d8 * dVar11 * -(dVar14 * dVar11 * dVar11 - DOUBLE_803df9e0);
        dVar14 = (double)(float)(dVar14 * DOUBLE_803df9d8 * dVar11 *
                                          -(dVar14 * dVar11 * dVar11 - DOUBLE_803df9e0));
      }
      fVar1 = FLOAT_803df9a8;
      if (dVar14 <= dVar12) {
        fVar1 = FLOAT_803df9b4 * -(float)((double)FLOAT_803df9c8 * dVar14 - (double)FLOAT_803dfa30)
                * FLOAT_803dfa34;
      }
      *(ushort *)
       (DAT_803ddc3c + (uVar6 & 3) * 2 + ((int)uVar6 >> 2) * 0x20 + (uVar7 & 3) * 8 +
        ((int)uVar7 >> 2) * 0x800 + 0x60) =
           (ushort)(int)(fVar4 * (float)(dVar10 / dVar14) * fVar1 + fVar3) |
           (ushort)(((int)(fVar4 * (float)(dVar9 / dVar14) * fVar1 + fVar3) & 0xffffU) << 8);
      uVar7 = uVar7 + 1;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
    uVar6 = uVar6 + 1;
  } while ((int)uVar6 < 0x100);
  FUN_802420e0(DAT_803ddc3c + 0x60,*(int *)(DAT_803ddc3c + 0x44));
  return;
}

