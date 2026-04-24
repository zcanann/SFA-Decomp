// Function: FUN_80215254
// Entry: 80215254
// Size: 740 bytes

void FUN_80215254(void)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  int iVar9;
  int iVar10;
  short *psVar11;
  uint uVar12;
  double dVar13;
  undefined4 local_38;
  float local_34;
  float local_30;
  float local_2c;
  
  iVar7 = FUN_802860d0();
  if (*(int *)(iVar7 + 0xf4) == 0) {
    iVar6 = *(int *)(iVar7 + 0xb8);
    DAT_803ddd58 = iVar6;
    if (*(int *)(iVar7 + 0xf8) == 1) {
      FUN_8000a518(0x28,1);
      *(undefined4 *)(iVar7 + 0xf8) = 2;
      *(undefined2 *)(iVar6 + 0x270) = 0xb;
      *(undefined *)(iVar6 + 0x27b) = 1;
    }
    FUN_8003393c(iVar7);
    uVar8 = FUN_8002b9ec();
    *(undefined4 *)(iVar6 + 0x2d0) = uVar8;
    iVar9 = *(int *)(iVar6 + 0x2d0);
    if (iVar9 != 0) {
      local_34 = *(float *)(iVar9 + 0x18) - *(float *)(iVar7 + 0x18);
      local_30 = *(float *)(iVar9 + 0x1c) - *(float *)(iVar7 + 0x1c);
      local_2c = *(float *)(iVar9 + 0x20) - *(float *)(iVar7 + 0x20);
      dVar13 = (double)FUN_802931a0((double)(local_2c * local_2c +
                                            local_34 * local_34 + local_30 * local_30));
      *(float *)(iVar6 + 0x2c0) = (float)dVar13;
    }
    FUN_8003b310(iVar7,DAT_803ddd58 + 0x3ac);
    uVar12 = 0;
    iVar9 = 0;
    psVar11 = (short *)&DAT_803dc290;
    do {
      iVar10 = FUN_8001ffb4((int)*psVar11);
      if (iVar10 != 0) {
        uVar12 = uVar12 | 1 << iVar9 & 0xffU;
      }
      psVar11 = psVar11 + 1;
      iVar9 = iVar9 + 1;
    } while (iVar9 < 4);
    *(char *)(DAT_803ddd54 + 0xff) = (char)uVar12;
    iVar9 = (*(ushort *)(DAT_803ddd54 + 0xfa) >> 1 & 3) * 4;
    fVar2 = *(float *)(*(int *)(DAT_803ddd54 + 0xd0) + iVar9);
    fVar4 = *(float *)(*(int *)(DAT_803ddd54 + 0xdc) + iVar9) - fVar2;
    fVar3 = *(float *)(*(int *)(DAT_803ddd54 + 0xd8) + iVar9);
    fVar5 = *(float *)(*(int *)(DAT_803ddd54 + 0xe4) + iVar9) - fVar3;
    if (ABS(fVar4) <= ABS(fVar5)) {
      fVar4 = (*(float *)(*(int *)(iVar6 + 0x2d0) + 0x14) - fVar3) / fVar5;
    }
    else {
      fVar4 = (*(float *)(*(int *)(iVar6 + 0x2d0) + 0xc) - fVar2) / fVar4;
    }
    *(float *)(DAT_803ddd54 + 0xf4) = fVar4;
    local_38 = DAT_803e67b0;
    *(undefined *)(DAT_803ddd54 + 0xfe) =
         *(undefined *)((int)&local_38 + (*(ushort *)(DAT_803ddd54 + 0xfa) >> 1 & 3));
    uVar12 = 0;
    iVar9 = 0;
    psVar11 = (short *)&DAT_803dc298;
    bVar1 = *(byte *)(DAT_803ddd54 + 0xfe);
    do {
      if ((((uint)bVar1 & 1 << iVar9) != 0) && (iVar10 = FUN_8001ffb4((int)*psVar11), iVar10 != 0))
      {
        uVar12 = uVar12 | 1 << iVar9 & 0xffU;
      }
      psVar11 = psVar11 + 1;
      iVar9 = iVar9 + 1;
    } while (iVar9 < 4);
    *(char *)(DAT_803ddd54 + 0x100) = (char)uVar12;
    (**(code **)(*DAT_803dcab8 + 0x54))
              (iVar7,iVar6,DAT_803ddd58 + 0x35c,(int)*(short *)(DAT_803ddd58 + 0x3f4),
               DAT_803ddd58 + 0x405,2,2,0);
    FUN_80213da0(iVar7,iVar6);
    FUN_8021419c(iVar7);
    (**(code **)(*DAT_803dcab8 + 0x2c))((double)FLOAT_803e67b8,iVar7,iVar6,0);
    FUN_80035dc8(iVar7,0x18,2,0x1fffff);
    (**(code **)(*DAT_803dca8c + 8))
              ((double)FLOAT_803db414,(double)FLOAT_803db414,iVar7,iVar6,&DAT_803ad1a0,&DAT_803ad170
              );
    *(undefined4 *)(iVar7 + 0x10) = *(undefined4 *)(DAT_803ddd54 + 0xec);
  }
  FUN_8028611c();
  return;
}

