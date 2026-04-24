// Function: FUN_8021d910
// Entry: 8021d910
// Size: 1176 bytes

void FUN_8021d910(void)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_802860d8();
  iVar10 = (int)((ulonglong)uVar13 >> 0x20);
  iVar9 = (int)uVar13;
  iVar12 = *(int *)(iVar10 + 0xb8);
  iVar11 = -1;
  if (*(char *)(iVar9 + 0x27a) != '\0') {
    *(byte *)(iVar12 + 0xc49) = *(byte *)(iVar12 + 0xc49) & 0xbf | 0x40;
    uVar3 = FUN_800221a0(500,1000);
    *(float *)(iVar12 + 0xc30) =
         (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e6af8);
    *(undefined *)(iVar12 + 0xc4b) = 0;
    if (*(short *)(iVar10 + 0xa0) != 2) {
      iVar11 = 2;
      *(float *)(iVar9 + 0x2a0) = FLOAT_803e6aac;
    }
    FUN_80039264(iVar12 + 0xb48);
  }
  iVar4 = FUN_8001ffb4(0x9c9);
  iVar5 = FUN_8001ffb4(0x9c7);
  iVar6 = FUN_8001ffb4(0x9cb);
  iVar7 = FUN_8001ffb4(0x9cd);
  uVar3 = iVar5 + iVar4 + iVar6 + iVar7;
  iVar4 = FUN_8001ffb4(0x62b);
  if (iVar4 != 0) {
    FUN_800200e8(0x62f,1);
    FUN_80035e8c(iVar10);
    FUN_80035e30(iVar10,1);
    *(byte *)(*(int *)(iVar10 + 0x50) + 0x71) = *(byte *)(*(int *)(iVar10 + 0x50) + 0x71) & 0xfe;
    *(undefined *)(iVar12 + 0xc4b) = 0xff;
    *(ushort *)(iVar12 + 0xc40) = *(ushort *)(iVar12 + 0xc40) | 0x40;
    *(ushort *)(iVar12 + 0xc40) = *(ushort *)(iVar12 + 0xc40) | 0x20;
    *(byte *)(iVar12 + 0xc49) = *(byte *)(iVar12 + 0xc49) & 0xbf;
    (**(code **)(*DAT_803dca9c + 0xa8))(iVar12 + 0xa10,iVar10,0x3463a);
    iVar10 = *(int *)(iVar10 + 0xb8);
    *(byte *)(iVar10 + 0xc49) = *(byte *)(iVar10 + 0xc49) & 0xfe | 1;
    (**(code **)(*DAT_803dca68 + 0x58))(DAT_803dc320,0x5ce);
    (**(code **)(*DAT_803dca68 + 0x5c))((int)*(short *)(iVar10 + 0xc18));
    FUN_80039264(iVar12 + 0xb48);
    uVar8 = 7;
    goto LAB_8021dd90;
  }
  if (uVar3 == 4) {
    FUN_800200e8(0x62a,1);
    uVar8 = 0;
    goto LAB_8021dd90;
  }
  FUN_80039118(iVar10,iVar12 + 0xb48);
  *(float *)(iVar12 + 0xc30) =
       *(float *)(iVar12 + 0xc30) -
       (float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) - DOUBLE_803e6ad0);
  if ((*(short *)(iVar10 + 0xa0) != 9) && (*(short *)(iVar10 + 0xa0) != 0x11)) {
    FUN_8002208c((double)FLOAT_803e6ad8,(double)FLOAT_803e6adc,iVar12 + 0xc34);
    if (uVar3 == 0) {
      if (*(float *)(iVar12 + 0xc30) < FLOAT_803e6aa8) {
        *(float *)(iVar9 + 0x2a0) =
             FLOAT_803e6ae0 * (float)(4503601774854144.0 - DOUBLE_803e6af8) + FLOAT_803e6ab0;
        iVar11 = 9;
        uVar3 = FUN_800221a0(700,1000);
        *(float *)(iVar12 + 0xc30) =
             (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e6af8);
      }
    }
    else {
      iVar4 = FUN_80080100((4 - uVar3) * 10);
      if (iVar4 != 0) {
        *(float *)(iVar9 + 0x2a0) =
             FLOAT_803e6ae8 *
             (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e6af8) +
             FLOAT_803e6ae4;
        iVar11 = 9;
        iVar4 = FUN_800221a0(700,1000);
        *(float *)(iVar12 + 0xc30) =
             (float)((double)CONCAT44(0x43300000,iVar4 + uVar3 * -300 ^ 0x80000000) -
                    DOUBLE_803e6af8);
      }
    }
  }
  if ((*(char *)(iVar9 + 0x346) != '\0') && (*(short *)(iVar10 + 0xa0) != 2)) {
    iVar11 = 2;
    *(float *)(iVar9 + 0x2a0) = FLOAT_803e6aac;
  }
  if (iVar11 != -1) {
    FUN_8002f574(iVar10,0x78);
    FUN_80030334((double)FLOAT_803e6aa8,iVar10,iVar11,0);
  }
  iVar9 = FUN_8002b9ec();
  if (iVar9 == 0) {
LAB_8021dd7c:
    *(byte *)(iVar12 + 0x9fd) = *(byte *)(iVar12 + 0x9fd) & 0xfe;
  }
  else {
    fVar1 = *(float *)(iVar9 + 0x10) - *(float *)(iVar10 + 0x10);
    fVar2 = fVar1;
    if (fVar1 < FLOAT_803e6aa8) {
      fVar2 = -fVar1;
    }
    if (FLOAT_803e6aec <= fVar2) {
      if (fVar1 < FLOAT_803e6aa8) {
        fVar1 = -fVar1;
      }
      if (fVar1 <= FLOAT_803e6af0) goto LAB_8021dd7c;
    }
    *(byte *)(iVar12 + 0x9fd) = *(byte *)(iVar12 + 0x9fd) | 1;
    iVar11 = FUN_800221a0(0,100);
    if ((iVar11 == 0) && (*(short *)(iVar10 + 0xa0) != 9)) {
      fVar1 = *(float *)(iVar9 + 0x10) - *(float *)(iVar10 + 0x10);
      if (fVar1 < FLOAT_803e6aa8) {
        fVar1 = -fVar1;
      }
      if (fVar1 < FLOAT_803e6aec) {
        (**(code **)(*DAT_803dca54 + 0x48))(9,iVar10,0xffffffff);
      }
    }
  }
  uVar8 = 0;
LAB_8021dd90:
  FUN_80286124(uVar8);
  return;
}

