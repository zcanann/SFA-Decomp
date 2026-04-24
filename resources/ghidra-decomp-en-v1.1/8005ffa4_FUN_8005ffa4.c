// Function: FUN_8005ffa4
// Entry: 8005ffa4
// Size: 1640 bytes

/* WARNING: Removing unreachable block (ram,0x800605ec) */
/* WARNING: Removing unreachable block (ram,0x8005ffb4) */

void FUN_8005ffa4(void)

{
  int iVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  byte bVar7;
  float *pfVar5;
  int iVar6;
  char cVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int *piVar12;
  undefined uVar13;
  int *piVar14;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps31_1;
  uint3 local_c8;
  undefined4 local_c4;
  undefined local_c0;
  undefined local_bf;
  undefined local_be [2];
  int local_bc;
  int local_b8;
  int local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float fStack_98;
  undefined4 uStack_94;
  undefined4 uStack_90;
  float afStack_8c [3];
  float local_80;
  float local_70;
  float local_60;
  undefined4 local_58;
  uint uStack_54;
  longlong local_50;
  undefined8 local_48;
  longlong local_40;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  FUN_8028683c();
  local_c4 = DAT_803e90c0;
  FUN_80259288(0);
  FUN_8000fb20();
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  FUN_80079b3c();
  FUN_8007965c();
  FUN_80079980();
  _local_c8 = local_c4;
  dVar15 = (double)FLOAT_803df84c;
  FUN_8025ca38(dVar15,dVar15,dVar15,dVar15,0,&local_c8);
  FUN_80078b28();
  uVar13 = 0xff;
  DAT_803dda90 = 0;
  DAT_803dda94 = 0;
  bVar7 = FUN_80089428(2);
  if ((bVar7 != 0) && ((DAT_803dda68 & 0x40) != 0)) {
    pfVar5 = (float *)FUN_8000f56c();
    FUN_80089a60(0,&fStack_98,&uStack_94,&uStack_90);
    local_a4 = pfVar5[8];
    local_a0 = pfVar5[9];
    local_9c = pfVar5[10];
    dVar15 = FUN_80247f90(&fStack_98,&local_a4);
    if ((double)FLOAT_803df84c < dVar15) {
      FUN_800893c0(afStack_8c);
      FUN_8000edcc((double)local_80,(double)local_70,(double)local_60,(double)FLOAT_803df854,
                   &local_a8,&local_ac,&local_b0);
      FUN_8000ea98((double)local_a8,(double)local_ac,(double)local_b0,&local_b4,&local_b8,&local_bc)
      ;
      DAT_803dda88 = local_b4 + -0x10;
      DAT_803dda90 = 0x20;
      DAT_803dda8c = local_b8 + -0x10;
      DAT_803dda94 = 0x20;
      if (DAT_803dda88 < 0) {
        DAT_803dda88 = 0;
      }
      else if (0x280 < DAT_803dda88) {
        DAT_803dda88 = 0x280;
      }
      if (DAT_803dda8c < 0) {
        DAT_803dda8c = 0;
      }
      else if (0x1e0 < DAT_803dda8c) {
        DAT_803dda8c = 0x1e0;
      }
      if (0x280 < DAT_803dda88 + 0x20) {
        DAT_803dda90 = 0x280 - DAT_803dda88;
      }
      if (0x1e0 < DAT_803dda8c + 0x20) {
        DAT_803dda94 = 0x1e0 - DAT_803dda8c;
      }
      uVar9 = 0;
      iVar10 = 0;
      piVar12 = &DAT_8030f1f4;
      do {
        iVar6 = FUN_8006ff74(local_b4 + *piVar12,local_b8 + piVar12[1],iVar10);
        if ((local_bc <= iVar6) && (cVar8 = FUN_8011f628(), cVar8 == '\0')) {
          uVar9 = uVar9 + 1;
        }
        piVar12 = piVar12 + 2;
        iVar10 = iVar10 + 1;
      } while (iVar10 < 5);
      local_58 = 0x43300000;
      fVar3 = (float)((double)CONCAT44(0x43300000,uVar9) - DOUBLE_803df8c8) / FLOAT_803df864 -
              FLOAT_803dda98;
      fVar4 = FLOAT_803df8b0;
      if ((fVar3 <= FLOAT_803df8b0) && (fVar4 = fVar3, fVar3 < FLOAT_803df8b4)) {
        fVar4 = FLOAT_803df8b4;
      }
      FLOAT_803dda98 = FLOAT_803dda98 + fVar4;
      dVar15 = (double)(float)(dVar15 * (double)FLOAT_803dda98);
      uStack_54 = uVar9;
      if ((double)FLOAT_803df84c < dVar15) {
        FUN_80247618(pfVar5,afStack_8c,afStack_8c);
        FUN_8025d80c(afStack_8c,0);
        FUN_8025d888(0);
        iVar10 = FUN_800893b8();
        FUN_8004c460(iVar10,0);
        FUN_80089b54(0,&local_c0,&local_bf,local_be);
        uStack_54 = (uint)bVar7;
        local_58 = 0x43300000;
        dVar15 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_54) -
                                                DOUBLE_803df8c8) * dVar15);
        local_50 = (longlong)(int)((double)FLOAT_803df87c * dVar15);
        FUN_80079b60(local_c0,local_bf,local_be[0],(char)(int)((double)FLOAT_803df87c * dVar15));
        iVar10 = (int)-(float)((double)FLOAT_803df8b8 * dVar15 - (double)FLOAT_803df858);
        local_48 = (double)(longlong)iVar10;
        uVar13 = (undefined)iVar10;
        dVar16 = (double)((float)((double)FLOAT_803df8bc * dVar15) * FLOAT_803df8c0);
        FUN_80259000(0x80,2,4);
        dVar15 = -dVar16;
        DAT_cc008000 = (float)dVar15;
        DAT_cc008000 = (float)dVar15;
        DAT_cc008000 = FLOAT_803df84c;
        DAT_cc008000 = FLOAT_803df84c;
        DAT_cc008000 = FLOAT_803df84c;
        DAT_cc008000 = (float)dVar16;
        DAT_cc008000 = (float)dVar15;
        DAT_cc008000 = FLOAT_803df84c;
        DAT_cc008000 = FLOAT_803df85c;
        DAT_cc008000 = FLOAT_803df84c;
        DAT_cc008000 = (float)dVar16;
        DAT_cc008000 = (float)dVar16;
        DAT_cc008000 = FLOAT_803df84c;
        DAT_cc008000 = FLOAT_803df85c;
        DAT_cc008000 = FLOAT_803df85c;
        DAT_cc008000 = (float)dVar15;
        DAT_cc008000 = (float)dVar16;
        DAT_cc008000 = FLOAT_803df84c;
        DAT_cc008000 = FLOAT_803df84c;
        DAT_cc008000 = FLOAT_803df85c;
      }
    }
  }
  DAT_803dc294 = uVar13;
  if (DAT_803dda86 != 0) {
    piVar14 = &DAT_80382c98;
    piVar12 = piVar14;
    for (iVar10 = 0; iVar10 < (int)(uint)DAT_803dda86; iVar10 = iVar10 + 1) {
      iVar11 = *piVar12;
      FUN_8000edcc((double)(*(float *)(iVar11 + 0x10) - FLOAT_803dda58),
                   (double)*(float *)(iVar11 + 0x14),
                   (double)(*(float *)(iVar11 + 0x18) - FLOAT_803dda5c),
                   (double)*(float *)(iVar11 + 0x2f4),&local_a8,&local_ac,&local_b0);
      FUN_8000ea98((double)local_a8,(double)local_ac,(double)local_b0,&local_b4,&local_b8,&local_bc)
      ;
      iVar6 = FUN_8006ff74(local_b4,local_b8,iVar11);
      if ((iVar6 < local_bc) || (cVar8 = FUN_8011f628(), cVar8 != '\0')) {
        *(undefined *)(iVar11 + 0x2fa) = 0xf0;
      }
      else {
        *(undefined *)(iVar11 + 0x2fa) = 0x10;
      }
      piVar12 = piVar12 + 1;
    }
    FUN_8025d888(0x3c);
    FUN_8007965c();
    FUN_80078b28();
    for (iVar10 = 0; iVar10 < (int)(uint)DAT_803dda86; iVar10 = iVar10 + 1) {
      iVar6 = *piVar14;
      if (*(char *)(iVar6 + 0x2f9) != '\0') {
        FUN_8004c460(*(int *)(iVar6 + 0x2e8),0);
        fVar3 = *(float *)(iVar6 + 0x138);
        local_48 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x2ec));
        iVar11 = (int)((float)(local_48 - DOUBLE_803df8c8) * fVar3);
        local_50 = (longlong)iVar11;
        uStack_54 = (uint)*(byte *)(iVar6 + 0x2ed);
        local_58 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803df8c8) * fVar3);
        local_40 = (longlong)iVar1;
        uStack_34 = (uint)*(byte *)(iVar6 + 0x2ee);
        local_38 = 0x43300000;
        iVar2 = (int)((float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df8c8) * fVar3);
        local_30 = (longlong)iVar2;
        FUN_80079b60((char)iVar11,(char)iVar1,(char)iVar2,
                     (char)((uint)*(byte *)(iVar6 + 0x2ef) * (uint)*(byte *)(iVar6 + 0x2f9) >> 8));
        FUN_80259000(0x80,2,4);
        DAT_cc008000 = *(float *)(iVar6 + 0x1c) - *(float *)(iVar6 + 0x2f0);
        DAT_cc008000 = *(float *)(iVar6 + 0x20) - *(float *)(iVar6 + 0x2f0);
        DAT_cc008000 = *(undefined4 *)(iVar6 + 0x24);
        DAT_cc008000 = FLOAT_803df84c;
        DAT_cc008000 = FLOAT_803df84c;
        DAT_cc008000 = *(float *)(iVar6 + 0x1c) + *(float *)(iVar6 + 0x2f0);
        DAT_cc008000 = *(float *)(iVar6 + 0x20) - *(float *)(iVar6 + 0x2f0);
        DAT_cc008000 = *(undefined4 *)(iVar6 + 0x24);
        DAT_cc008000 = FLOAT_803df85c;
        DAT_cc008000 = FLOAT_803df84c;
        DAT_cc008000 = *(float *)(iVar6 + 0x1c) + *(float *)(iVar6 + 0x2f0);
        DAT_cc008000 = *(float *)(iVar6 + 0x20) + *(float *)(iVar6 + 0x2f0);
        DAT_cc008000 = *(undefined4 *)(iVar6 + 0x24);
        DAT_cc008000 = FLOAT_803df85c;
        DAT_cc008000 = FLOAT_803df85c;
        DAT_cc008000 = *(float *)(iVar6 + 0x1c) - *(float *)(iVar6 + 0x2f0);
        DAT_cc008000 = *(float *)(iVar6 + 0x20) + *(float *)(iVar6 + 0x2f0);
        DAT_cc008000 = *(undefined4 *)(iVar6 + 0x24);
        DAT_cc008000 = FLOAT_803df84c;
        DAT_cc008000 = FLOAT_803df85c;
      }
      piVar14 = piVar14 + 1;
    }
    FUN_8025d888(0);
  }
  FUN_80286888();
  return;
}

