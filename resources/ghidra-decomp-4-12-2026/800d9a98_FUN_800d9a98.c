// Function: FUN_800d9a98
// Entry: 800d9a98
// Size: 1328 bytes

/* WARNING: Removing unreachable block (ram,0x800d9fa8) */
/* WARNING: Removing unreachable block (ram,0x800d9fa0) */
/* WARNING: Removing unreachable block (ram,0x800d9f98) */
/* WARNING: Removing unreachable block (ram,0x800d9f90) */
/* WARNING: Removing unreachable block (ram,0x800d9f88) */
/* WARNING: Removing unreachable block (ram,0x800d9ac8) */
/* WARNING: Removing unreachable block (ram,0x800d9ac0) */
/* WARNING: Removing unreachable block (ram,0x800d9ab8) */
/* WARNING: Removing unreachable block (ram,0x800d9ab0) */
/* WARNING: Removing unreachable block (ram,0x800d9aa8) */

void FUN_800d9a98(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined4 param_4,
                 int param_5,int param_6)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  ushort *puVar4;
  uint uVar5;
  int iVar6;
  uint *puVar7;
  float *pfVar8;
  double extraout_f1;
  double dVar9;
  double dVar10;
  double in_f27;
  double in_f28;
  double dVar11;
  double in_f29;
  double in_f30;
  double dVar12;
  double in_f31;
  double dVar13;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar14;
  ushort local_d8;
  ushort local_d6;
  ushort local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float afStack_c0 [16];
  undefined4 local_80;
  uint uStack_7c;
  longlong local_78;
  undefined4 local_70;
  uint uStack_6c;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
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
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  uVar14 = FUN_80286840();
  puVar4 = (ushort *)((ulonglong)uVar14 >> 0x20);
  puVar7 = (uint *)uVar14;
  bVar3 = true;
  DAT_803de0ce = 0;
  uVar5 = puVar7[0xb4];
  dVar11 = extraout_f1;
  if (uVar5 == 0) {
    puVar7[0xb0] = (uint)FLOAT_803e11f0;
  }
  else {
    fVar1 = *(float *)(uVar5 + 0xc) - *(float *)(puVar4 + 6);
    fVar2 = *(float *)(uVar5 + 0x14) - *(float *)(puVar4 + 10);
    dVar9 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    puVar7[0xb0] = (uint)(float)dVar9;
  }
  if (((*puVar7 & 0x8000) != 0) && (*(int *)(puVar4 + 0x60) == 0)) {
    FUN_800d93e8(puVar4,puVar7,param_6);
    dVar9 = DOUBLE_803e1218;
    uStack_7c = (int)*(short *)((int)puVar7 + 0x32e) ^ 0x80000000;
    local_80 = 0x43300000;
    iVar6 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e1218) + dVar11
                 );
    local_78 = (longlong)iVar6;
    *(short *)((int)puVar7 + 0x32e) = (short)iVar6;
    uStack_6c = (int)*(short *)((int)puVar7 + 0x32e) ^ 0x80000000;
    local_70 = 0x43300000;
    if (FLOAT_803e1244 < (float)((double)CONCAT44(0x43300000,uStack_6c) - dVar9)) {
      *(undefined2 *)((int)puVar7 + 0x32e) = 10000;
    }
  }
  *puVar7 = *puVar7 | 0x8000;
  if (puVar7[0x9f] != 0) {
    local_d8 = *puVar4;
    local_d6 = puVar4[1];
    local_d4 = puVar4[2];
    local_d0 = FLOAT_803e1208;
    local_cc = FLOAT_803e11f0;
    local_c8 = FLOAT_803e11f0;
    local_c4 = FLOAT_803e11f0;
    FUN_80021fac(afStack_c0,&local_d8);
    pfVar8 = (float *)puVar7[0x9f];
    FUN_80022790((double)FLOAT_803e11f0,(double)FLOAT_803e11f0,(double)FLOAT_803e1208,afStack_c0,
                 pfVar8,pfVar8 + 1,pfVar8 + 2);
    uVar5 = puVar7[0x9f];
    FUN_80022790((double)FLOAT_803e11f0,(double)FLOAT_803e1208,(double)FLOAT_803e11f0,afStack_c0,
                 (float *)(uVar5 + 0xc),(float *)(uVar5 + 0x10),(float *)(uVar5 + 0x14));
    uVar5 = puVar7[0x9f];
    FUN_80022790((double)FLOAT_803e1208,(double)FLOAT_803e11f0,(double)FLOAT_803e11f0,afStack_c0,
                 (float *)(uVar5 + 0x18),(float *)(uVar5 + 0x1c),(float *)(uVar5 + 0x20));
  }
  if ((*puVar7 & 0x1000000) == 0) {
    FUN_800d86a0(puVar4,(int)puVar7);
  }
  *puVar7 = *puVar7 & 0xffdfffff;
  *(undefined *)((int)puVar7 + 0x34d) = 0;
  DAT_803de0b4 = 0;
  *puVar7 = *puVar7 & 0xfff7ffff;
  *(undefined *)(puVar7 + 0xd3) = 0;
  DAT_803de0cf = 0;
  FUN_800d955c(puVar4,puVar7,param_5);
  dVar9 = DOUBLE_803e1218;
  uStack_6c = (int)*(short *)(puVar7 + 0xce) ^ 0x80000000;
  local_70 = 0x43300000;
  iVar6 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e1218) + dVar11);
  local_78 = (longlong)iVar6;
  *(short *)(puVar7 + 0xce) = (short)iVar6;
  uStack_7c = (int)*(short *)(puVar7 + 0xce) ^ 0x80000000;
  local_80 = 0x43300000;
  if (FLOAT_803e1244 < (float)((double)CONCAT44(0x43300000,uStack_7c) - dVar9)) {
    *(undefined2 *)(puVar7 + 0xce) = 10000;
  }
  FLOAT_803de0c8 = *(float *)(puVar4 + 6);
  FLOAT_803de0c4 = *(float *)(puVar4 + 10);
  iVar6 = FUN_8005b478((double)*(float *)(puVar4 + 0xc),(double)*(float *)(puVar4 + 0xe));
  if ((iVar6 == -1) && (*(int *)(puVar4 + 0x18) == 0)) {
    *puVar7 = *puVar7 | 0x200000;
    bVar3 = false;
  }
  if ((*puVar7 & 0x1000000) == 0) {
    FUN_800d8534(dVar11,puVar4,puVar7);
  }
  iVar6 = DAT_803de0b0;
  if (DAT_803de0b0 != 0) {
    dVar13 = (double)(*(float *)(DAT_803de0b0 + 0xc) - FLOAT_803de0c8);
    dVar12 = (double)(*(float *)(DAT_803de0b0 + 0x14) - FLOAT_803de0c4);
    dVar9 = FUN_80293900((double)(float)(dVar13 * dVar13 + (double)(float)(dVar12 * dVar12)));
    if (dVar9 < (double)FLOAT_803e123c) {
      dVar10 = FUN_80293900((double)((*(float *)(puVar4 + 6) - FLOAT_803de0c8) *
                                     (*(float *)(puVar4 + 6) - FLOAT_803de0c8) +
                                    (*(float *)(puVar4 + 10) - FLOAT_803de0c4) *
                                    (*(float *)(puVar4 + 10) - FLOAT_803de0c4)));
      if (dVar10 < (double)FLOAT_803e1234) {
        dVar10 = (double)FLOAT_803e1234;
      }
      if ((double)FLOAT_803e1208 <= dVar9) {
        if (dVar9 < dVar10) {
          dVar10 = dVar9;
        }
        *(float *)(puVar4 + 6) =
             (float)((double)(float)(dVar13 / dVar9) * dVar10 + (double)FLOAT_803de0c8);
        *(float *)(puVar4 + 10) =
             (float)((double)(float)(dVar12 / dVar9) * dVar10 + (double)FLOAT_803de0c4);
      }
      else {
        *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(iVar6 + 0xc);
        *(undefined4 *)(puVar4 + 10) = *(undefined4 *)(iVar6 + 0x14);
      }
    }
  }
  DAT_803de0b0 = 0;
  if ((((*puVar7 & 0x1000000) == 0) && ((*puVar7 & 0x400000) == 0)) && (bVar3)) {
    (**(code **)(*DAT_803dd728 + 0x10))(dVar11,puVar4,puVar7 + 1);
    (**(code **)(*DAT_803dd728 + 0x14))(puVar4,puVar7 + 1);
    (**(code **)(*DAT_803dd728 + 0x18))(param_2,puVar4,puVar7 + 1);
    if ((*(byte *)(puVar7 + 0x99) & 0x10) == 0) {
      *puVar7 = *puVar7 & 0xfffbffff;
    }
    else {
      *puVar7 = *puVar7 | 0x40000;
    }
    if ((*puVar7 & 0x800000) != 0) {
      if (((*(byte *)(puVar7 + 0x99) & 2) != 0) || (*(char *)((int)puVar7 + 0x262) != '\0')) {
        *(float *)(puVar4 + 0x12) =
             (float)((double)(*(float *)(puVar4 + 6) - *(float *)(*(int *)(puVar4 + 0x2a) + 0x10)) /
                    dVar11);
        *(float *)(puVar4 + 0x16) =
             (float)((double)(*(float *)(puVar4 + 10) - *(float *)(*(int *)(puVar4 + 0x2a) + 0x18))
                    / dVar11);
      }
      *puVar7 = *puVar7 & 0xff7fffff;
    }
  }
  FUN_8028688c();
  return;
}

