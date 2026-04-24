// Function: FUN_8008a9d8
// Entry: 8008a9d8
// Size: 1948 bytes

/* WARNING: Removing unreachable block (ram,0x8008b154) */
/* WARNING: Removing unreachable block (ram,0x8008b14c) */
/* WARNING: Removing unreachable block (ram,0x8008b144) */
/* WARNING: Removing unreachable block (ram,0x8008a9f8) */
/* WARNING: Removing unreachable block (ram,0x8008a9f0) */
/* WARNING: Removing unreachable block (ram,0x8008a9e8) */

void FUN_8008a9d8(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  undefined4 uVar5;
  short *psVar6;
  int iVar7;
  byte bVar8;
  double dVar9;
  double in_f29;
  double dVar10;
  double in_f30;
  double in_f31;
  double dVar11;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  undefined4 local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  ushort local_c0 [4];
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  ushort local_a8 [4];
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  undefined8 local_90;
  longlong local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  longlong local_60;
  undefined8 local_58;
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
  uVar12 = FUN_8028683c();
  uVar5 = (undefined4)((ulonglong)uVar12 >> 0x20);
  psVar6 = FUN_8000facc();
  local_d8 = DAT_802c2700;
  local_d4 = DAT_802c2704;
  local_d0 = DAT_802c2708;
  local_e4 = DAT_802c270c;
  local_e0 = DAT_802c2710;
  local_dc = DAT_802c2714;
  local_e8 = 0;
  local_9c = FLOAT_803dfcd8;
  local_98 = FLOAT_803dfcd8;
  local_94 = FLOAT_803dfcd8;
  local_a0 = FLOAT_803dfcdc;
  local_a8[2] = 0;
  local_a8[1] = 0;
  local_a8[0] = 0;
  local_b4 = FLOAT_803dfcd8;
  local_b0 = FLOAT_803dfcd8;
  local_ac = FLOAT_803dfcd8;
  local_b8 = FLOAT_803dfcdc;
  local_c0[2] = 0;
  local_c0[1] = 0;
  local_c0[0] = 0;
  (**(code **)(*DAT_803dd6d8 + 0x20))(&local_e8);
  if ((psVar6 != (short *)0x0) && (DAT_803dddac != 0)) {
    dVar9 = FUN_8000fc08();
    FUN_8000fc10((double)FLOAT_803dfd18,0);
    FUN_8000fb20();
    fVar1 = (*(float *)(DAT_803dddac + 0x20c) - FLOAT_803dfd04) / FLOAT_803dfd1c;
    fVar2 = FLOAT_803dfcd8;
    if ((FLOAT_803dfcd8 <= fVar1) && (fVar2 = fVar1, FLOAT_803dfcdc < fVar1)) {
      fVar2 = FLOAT_803dfcdc;
    }
    if (FLOAT_803dfd20 <= fVar2) {
      if (fVar2 <= FLOAT_803dfd28) {
        DAT_803ddda8 = 0xff;
      }
      else if (fVar2 <= FLOAT_803dfcdc) {
        DAT_803ddda8 = (undefined2)
                       (int)(FLOAT_803dfd24 * (FLOAT_803dfd20 - (fVar2 - FLOAT_803dfd28)));
      }
      else {
        DAT_803ddda8 = 0;
      }
    }
    else if (FLOAT_803dfcd8 <= fVar2) {
      DAT_803ddda8 = (undefined2)(int)(FLOAT_803dfd24 * fVar2);
    }
    else {
      DAT_803ddda8 = 0;
    }
    fVar1 = (*(float *)(DAT_803dddac + 0x20c) - FLOAT_803dfd04) / FLOAT_803dfd30;
    fVar3 = FLOAT_803dfcd8;
    if ((FLOAT_803dfcd8 <= fVar1) && (fVar3 = fVar1, FLOAT_803dfcdc < fVar1)) {
      fVar3 = FLOAT_803dfcdc - (fVar1 - FLOAT_803dfcdc);
    }
    dVar11 = -(double)(FLOAT_803dfd34 * fVar3 - FLOAT_803dfcdc);
    local_cc = FLOAT_803dfd38 * local_d8;
    local_c8 = FLOAT_803dfd38 * local_d4;
    local_c4 = FLOAT_803dfd38 * local_d0;
    dVar10 = (double)*(float *)(DAT_803dddac + 0x1c);
    local_90 = (double)(longlong)(int)(fVar2 * FLOAT_803dfd2c);
    local_a8[0] = (ushort)(int)(fVar2 * FLOAT_803dfd2c);
    FUN_80021b8c(local_a8,&local_cc);
    local_a0 = FLOAT_803dfcdc;
    local_88 = (longlong)(int)dVar10;
    local_a8[2] = (ushort)(int)dVar10;
    local_a8[1] = 0;
    local_a8[0] = 0;
    FUN_80021b8c(local_a8,&local_cc);
    dVar4 = DOUBLE_803dfd10;
    DAT_8030fe88 = local_cc;
    DAT_8030fe8c = local_c8;
    DAT_8030fe90 = local_c4;
    local_80 = (double)(longlong)(int)local_cc;
    local_78 = (double)CONCAT44(0x43300000,(int)(short)(int)local_cc ^ 0x80000000);
    *(float *)(DAT_803dddc8 + 6) = *(float *)(psVar6 + 0x22) + (float)(local_78 - DOUBLE_803dfd10);
    local_70 = (double)(longlong)(int)local_c8;
    local_68 = (double)CONCAT44(0x43300000,(int)(short)(int)local_c8 ^ 0x80000000);
    *(float *)(DAT_803dddc8 + 8) = *(float *)(psVar6 + 0x24) + (float)(local_68 - dVar4);
    local_60 = (longlong)(int)local_c4;
    local_58 = (double)CONCAT44(0x43300000,(int)(short)(int)local_c4 ^ 0x80000000);
    *(float *)(DAT_803dddc8 + 10) = *(float *)(psVar6 + 0x26) + (float)(local_58 - dVar4);
    *(float *)(DAT_803dddc8 + 4) = (float)((double)FLOAT_803dfd3c * dVar11);
    *DAT_803dddc8 = -*psVar6;
    DAT_803dddc8[1] = psVar6[1];
    DAT_803dddc8[2] = 0;
    *(char *)((int)DAT_803dddc8 + 0x37) = (char)DAT_803ddda8;
    fVar1 = *(float *)(DAT_803dddac + 0x20c);
    if (fVar1 < FLOAT_803dfd08) {
      fVar1 = fVar1 + FLOAT_803dfd40;
    }
    else {
      fVar1 = fVar1 - FLOAT_803dfd08;
    }
    fVar2 = fVar1 / FLOAT_803dfd30;
    fVar3 = FLOAT_803dfcd8;
    if ((FLOAT_803dfcd8 <= fVar2) && (fVar3 = fVar2, FLOAT_803dfcdc < fVar2)) {
      fVar3 = FLOAT_803dfcdc;
    }
    if (FLOAT_803dfd20 <= fVar3) {
      if (fVar3 <= FLOAT_803dfd28) {
        DAT_803dddaa = 0xff;
      }
      else if (fVar3 <= FLOAT_803dfcdc) {
        DAT_803dddaa = (undefined2)
                       (int)(FLOAT_803dfd24 * (FLOAT_803dfd20 - (fVar3 - FLOAT_803dfd28)));
      }
      else {
        DAT_803dddaa = 0;
      }
    }
    else if (FLOAT_803dfcd8 <= fVar3) {
      DAT_803dddaa = (undefined2)(int)(FLOAT_803dfd24 * fVar3);
    }
    else {
      DAT_803dddaa = 0;
    }
    fVar1 = fVar1 / FLOAT_803dfd44;
    fVar2 = FLOAT_803dfcd8;
    if ((FLOAT_803dfcd8 <= fVar1) && (fVar2 = fVar1, FLOAT_803dfcdc < fVar1)) {
      fVar2 = FLOAT_803dfcdc - (fVar1 - FLOAT_803dfcdc);
    }
    dVar11 = -(double)(FLOAT_803dfd34 * fVar2 - FLOAT_803dfcdc);
    local_cc = FLOAT_803dfd38 * local_e4;
    local_c8 = FLOAT_803dfd38 * local_e0;
    local_c4 = FLOAT_803dfd38 * local_dc;
    local_58 = (double)(longlong)(int)(fVar3 * FLOAT_803dfd2c);
    local_c0[0] = (ushort)(int)(fVar3 * FLOAT_803dfd2c);
    FUN_80021b8c(local_c0,&local_cc);
    local_b8 = FLOAT_803dfcdc;
    local_60 = (longlong)(int)dVar10;
    local_c0[2] = (ushort)(int)dVar10;
    local_c0[1] = 0;
    local_c0[0] = 0;
    FUN_80021b8c(local_c0,&local_cc);
    dVar4 = DOUBLE_803dfd10;
    DAT_8030fe94 = local_cc;
    DAT_8030fe98 = local_c8;
    DAT_8030fe9c = local_c4;
    local_68 = (double)(longlong)(int)local_cc;
    local_70 = (double)CONCAT44(0x43300000,(int)(short)(int)local_cc ^ 0x80000000);
    *(float *)(DAT_803dddcc + 6) = *(float *)(psVar6 + 0x22) + (float)(local_70 - DOUBLE_803dfd10);
    local_78 = (double)(longlong)(int)local_c8;
    local_80 = (double)CONCAT44(0x43300000,(int)(short)(int)local_c8 ^ 0x80000000);
    *(float *)(DAT_803dddcc + 8) = *(float *)(psVar6 + 0x24) + (float)(local_80 - dVar4);
    local_88 = (longlong)(int)local_c4;
    local_90 = (double)CONCAT44(0x43300000,(int)(short)(int)local_c4 ^ 0x80000000);
    *(float *)(DAT_803dddcc + 10) = *(float *)(psVar6 + 0x26) + (float)(local_90 - dVar4);
    *(float *)(DAT_803dddcc + 4) = (float)((double)FLOAT_803dfd3c * dVar11);
    *DAT_803dddcc = -*psVar6;
    DAT_803dddcc[1] = psVar6[1];
    bVar8 = 0;
    DAT_803dddcc[2] = 0;
    *(char *)((int)DAT_803dddcc + 0x37) = (char)DAT_803dddaa;
    if (*(char *)((int)DAT_803dddc8 + 0x37) != '\0') {
      if (DAT_803dddac != 0) {
        bVar8 = *(byte *)(DAT_803dddac + 0x209) >> 7;
      }
      if ((bVar8 == 0) && ((param_5 & 0xff) != 0)) {
        iVar7 = FUN_8002b660((int)DAT_803dddc8);
        *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
        FUN_8003ba50(uVar5,(int)uVar12,param_3,param_4,(int)DAT_803dddc8,1);
      }
    }
    if (*(char *)((int)DAT_803dddcc + 0x37) != '\0') {
      if (DAT_803dddac == 0) {
        bVar8 = 0;
      }
      else {
        bVar8 = *(byte *)(DAT_803dddac + 0x209) >> 7;
      }
      if ((bVar8 == 0) && ((param_5 & 0xff) != 0)) {
        iVar7 = FUN_8002b660((int)DAT_803dddcc);
        *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
        FUN_8003ba50(uVar5,(int)uVar12,param_3,param_4,(int)DAT_803dddcc,1);
      }
    }
    FUN_8000fc10(dVar9,0);
    FUN_8000fb20();
  }
  FUN_80286888();
  return;
}

