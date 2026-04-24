// Function: FUN_801e6d08
// Entry: 801e6d08
// Size: 1052 bytes

void FUN_801e6d08(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  undefined4 local_28;
  int local_24;
  undefined4 local_20;
  uint uStack28;
  
  uVar12 = FUN_802860dc();
  iVar7 = (int)((ulonglong)uVar12 >> 0x20);
  iVar8 = (int)uVar12;
  uVar5 = FUN_8002b9ec();
  iVar10 = *(int *)(iVar7 + 0xb8);
  if (*(char *)(iVar8 + 0x27a) != '\0') {
    uStack28 = FUN_800221a0(500,1000);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(iVar10 + 0x9c0) = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5a00);
    *(byte *)(iVar10 + 0x9d4) = *(byte *)(iVar10 + 0x9d4) & 0xf7;
  }
  if ((*(byte *)(iVar10 + 0x9d4) & 8) == 0) {
    if ((*(short *)(iVar7 + 0xa0) != 0x12) && (*(short *)(iVar7 + 0xa0) != 0)) {
      FUN_80030334((double)FLOAT_803e59dc,iVar7,0,0);
      *(float *)(iVar8 + 0x2a0) = FLOAT_803e59e4;
    }
  }
  else if (*(char *)(iVar8 + 0x346) != '\0') {
    if ((*(short *)(iVar7 + 0xa0) != 0x11) || (*(float *)(iVar8 + 0x2a0) <= FLOAT_803e59dc)) {
      if (*(short *)(iVar7 + 0xa0) != 0) {
        FUN_80030334((double)FLOAT_803e59dc,iVar7,0,0);
      }
    }
    else {
      FUN_80030334(iVar7,0x12,0);
    }
    *(float *)(iVar8 + 0x2a0) = FLOAT_803e59e4;
    *(byte *)(iVar10 + 0x9d4) = *(byte *)(iVar10 + 0x9d4) & 0xf7;
    uStack28 = FUN_800221a0(500,1000);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(iVar10 + 0x9c0) = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5a00);
  }
  *(float *)(iVar10 + 0x9c0) = *(float *)(iVar10 + 0x9c0) - FLOAT_803db414;
  if ((*(float *)(iVar10 + 0x9c0) <= FLOAT_803e59dc) && ((*(byte *)(iVar10 + 0x9d4) & 8) == 0)) {
    FUN_8000bb18(iVar7,0x40d);
    if (*(short *)(iVar7 + 0xa0) == 0x12) {
      FUN_80030334((double)FLOAT_803e5a08,iVar7,0x11,0);
      *(float *)(iVar8 + 0x2a0) = FLOAT_803e5a0c;
    }
    else {
      iVar6 = FUN_800221a0(0,1);
      FUN_80030334((double)FLOAT_803e59dc,iVar7,(int)*(short *)(&DAT_803dc0a0 + iVar6 * 2),0);
      *(undefined4 *)(iVar8 + 0x2a0) = *(undefined4 *)(&DAT_803dc0a4 + iVar6 * 4);
    }
    *(byte *)(iVar10 + 0x9d4) = *(byte *)(iVar10 + 0x9d4) | 8;
  }
  iVar6 = FUN_8001ffb4(0x617);
  if (iVar6 == 0) {
    local_28 = 4;
    uVar5 = *(undefined4 *)(iVar10 + 0x9b0);
    iVar7 = FUN_800138c4(uVar5);
    if (iVar7 == 0) {
      FUN_80013958(uVar5,&local_28);
    }
    uVar5 = 7;
  }
  else {
    dVar11 = (double)FUN_801e7c4c(iVar7,uVar5,0);
    fVar1 = FLOAT_803e59dc;
    if ((double)FLOAT_803e5a18 < dVar11) {
      fVar1 = FLOAT_803e5a14;
    }
    *(float *)(iVar8 + 0x280) =
         FLOAT_803e5a10 * (fVar1 - *(float *)(iVar8 + 0x280)) * FLOAT_803db414 +
         *(float *)(iVar8 + 0x280);
    if (FLOAT_803e5a1c < *(float *)(iVar8 + 0x280)) {
      *(float *)(iVar8 + 0x280) = FLOAT_803e59dc;
    }
    *(float *)(iVar8 + 0x280) = FLOAT_803e59dc;
    iVar8 = FUN_80065e50((double)*(float *)(iVar7 + 0xc),(double)*(float *)(iVar7 + 0x10),
                         (double)*(float *)(iVar7 + 0x14),iVar7,&local_24,0,0);
    fVar4 = FLOAT_803e59e0;
    fVar3 = FLOAT_803e59dc;
    iVar6 = 0;
    fVar1 = FLOAT_803e5a20;
    if (0 < iVar8) {
      do {
        fVar2 = **(float **)(local_24 + iVar6) - *(float *)(iVar7 + 0x10);
        if (fVar2 < fVar3) {
          fVar2 = -fVar2;
        }
        if (fVar2 < fVar1) {
          *(float *)(iVar10 + 0x9bc) = fVar4 + **(float **)(local_24 + iVar6);
          fVar1 = fVar2;
        }
        iVar6 = iVar6 + 4;
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
    }
    uStack28 = (uint)*(ushort *)(iVar10 + 0x9ca);
    local_20 = 0x43300000;
    dVar11 = (double)FUN_80293e80((double)((FLOAT_803e59e8 *
                                           (float)((double)CONCAT44(0x43300000,uStack28) -
                                                  DOUBLE_803e59f8)) / FLOAT_803e59ec));
    *(float *)(iVar7 + 0x10) =
         (float)((double)*(float *)(iVar10 + 0x9b8) * dVar11 + (double)*(float *)(iVar10 + 0x9bc));
    uVar9 = (uint)*(ushort *)(iVar10 + 0x9ca) + (uint)DAT_803db410 * 0x100;
    if (0xffff < uVar9) {
      uStack28 = FUN_800221a0(0xf,0x23);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar10 + 0x9b8) =
           FLOAT_803e59f0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5a00);
    }
    *(short *)(iVar10 + 0x9ca) = (short)uVar9;
    iVar8 = FUN_80038024(iVar7);
    if (iVar8 != 0) {
      uVar5 = FUN_800221a0(0,2);
      (**(code **)(*DAT_803dca54 + 0x48))(uVar5,iVar7,0xffffffff);
    }
    uVar5 = 0;
  }
  FUN_80286128(uVar5);
  return;
}

