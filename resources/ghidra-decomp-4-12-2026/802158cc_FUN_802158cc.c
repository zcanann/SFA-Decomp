// Function: FUN_802158cc
// Entry: 802158cc
// Size: 740 bytes

void FUN_802158cc(void)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  undefined4 *puVar9;
  int iVar10;
  short *psVar11;
  uint uVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined4 local_38;
  float local_34;
  float local_30;
  float local_2c;
  
  uVar3 = FUN_80286834();
  if (*(int *)(uVar3 + 0xf4) == 0) {
    iVar2 = *(int *)(uVar3 + 0xb8);
    DAT_803de9d8 = iVar2;
    if (*(int *)(uVar3 + 0xf8) == 1) {
      FUN_8000a538((int *)0x28,1);
      *(undefined4 *)(uVar3 + 0xf8) = 2;
      *(undefined2 *)(iVar2 + 0x270) = 0xb;
      *(undefined *)(iVar2 + 0x27b) = 1;
    }
    FUN_80033a34(uVar3);
    uVar4 = FUN_8002bac4();
    *(undefined4 *)(iVar2 + 0x2d0) = uVar4;
    iVar5 = *(int *)(iVar2 + 0x2d0);
    if (iVar5 != 0) {
      local_34 = *(float *)(iVar5 + 0x18) - *(float *)(uVar3 + 0x18);
      local_30 = *(float *)(iVar5 + 0x1c) - *(float *)(uVar3 + 0x1c);
      local_2c = *(float *)(iVar5 + 0x20) - *(float *)(uVar3 + 0x20);
      dVar13 = FUN_80293900((double)(local_2c * local_2c + local_34 * local_34 + local_30 * local_30
                                    ));
      *(float *)(iVar2 + 0x2c0) = (float)dVar13;
    }
    FUN_8003b408(uVar3,DAT_803de9d8 + 0x3ac);
    uVar12 = 0;
    iVar5 = 0;
    psVar11 = (short *)&DAT_803dcef8;
    do {
      uVar6 = FUN_80020078((int)*psVar11);
      if (uVar6 != 0) {
        uVar12 = uVar12 | 1 << iVar5 & 0xffU;
      }
      psVar11 = psVar11 + 1;
      iVar5 = iVar5 + 1;
    } while (iVar5 < 4);
    *(char *)(DAT_803de9d4 + 0xff) = (char)uVar12;
    iVar5 = (*(ushort *)(DAT_803de9d4 + 0xfa) >> 1 & 3) * 4;
    dVar15 = (double)*(float *)(*(int *)(DAT_803de9d4 + 0xd0) + iVar5);
    dVar17 = (double)(float)((double)*(float *)(*(int *)(DAT_803de9d4 + 0xdc) + iVar5) - dVar15);
    dVar13 = (double)*(float *)(*(int *)(DAT_803de9d4 + 0xd8) + iVar5);
    dVar16 = (double)(float)((double)*(float *)(*(int *)(DAT_803de9d4 + 0xe4) + iVar5) - dVar13);
    if (ABS(dVar17) <= ABS(dVar16)) {
      dVar14 = (double)(float)((double)*(float *)(*(int *)(iVar2 + 0x2d0) + 0x14) - dVar13) / dVar16
      ;
    }
    else {
      dVar14 = (double)(float)((double)*(float *)(*(int *)(iVar2 + 0x2d0) + 0xc) - dVar15) / dVar17;
    }
    *(float *)(DAT_803de9d4 + 0xf4) = (float)dVar14;
    local_38 = DAT_803e7448;
    *(undefined *)(DAT_803de9d4 + 0xfe) =
         *(undefined *)((int)&local_38 + (*(ushort *)(DAT_803de9d4 + 0xfa) >> 1 & 3));
    uVar12 = 0;
    iVar5 = 0;
    psVar11 = (short *)&DAT_803dcf00;
    bVar1 = *(byte *)(DAT_803de9d4 + 0xfe);
    do {
      if ((((uint)bVar1 & 1 << iVar5) != 0) && (uVar6 = FUN_80020078((int)*psVar11), uVar6 != 0)) {
        uVar12 = uVar12 | 1 << iVar5 & 0xffU;
      }
      psVar11 = psVar11 + 1;
      iVar5 = iVar5 + 1;
    } while (iVar5 < 4);
    *(char *)(DAT_803de9d4 + 0x100) = (char)uVar12;
    iVar5 = DAT_803de9d8 + 0x35c;
    iVar7 = (int)*(short *)(DAT_803de9d8 + 0x3f4);
    iVar8 = DAT_803de9d8 + 0x405;
    puVar9 = (undefined4 *)0x2;
    iVar10 = 2;
    uVar4 = 0;
    dVar14 = (double)(**(code **)(*DAT_803dd738 + 0x54))(uVar3,iVar2);
    FUN_80214418(dVar14,dVar13,dVar15,dVar16,dVar17,in_f6,in_f7,in_f8,uVar3,iVar2,iVar5,iVar7,iVar8,
                 puVar9,iVar10,uVar4);
    FUN_80214814(uVar3);
    (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e7450,uVar3,iVar2,0);
    FUN_80035ec0(uVar3,0x18,2,0x1fffff);
    (**(code **)(*DAT_803dd70c + 8))
              ((double)FLOAT_803dc074,(double)FLOAT_803dc074,uVar3,iVar2,&DAT_803ade00,&DAT_803addd0
              );
    *(undefined4 *)(uVar3 + 0x10) = *(undefined4 *)(DAT_803de9d4 + 0xec);
  }
  FUN_80286880();
  return;
}

