// Function: FUN_8008a74c
// Entry: 8008a74c
// Size: 1948 bytes

/* WARNING: Removing unreachable block (ram,0x8008aec0) */
/* WARNING: Removing unreachable block (ram,0x8008aeb8) */
/* WARNING: Removing unreachable block (ram,0x8008aec8) */

void FUN_8008a74c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
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
  undefined4 uVar9;
  undefined8 uVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
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
  undefined2 local_c0;
  undefined2 local_be;
  undefined2 local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  undefined2 local_a8;
  undefined2 local_a6;
  undefined2 local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  double local_90;
  longlong local_88;
  double local_80;
  double local_78;
  double local_70;
  double local_68;
  longlong local_60;
  double local_58;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar13 = FUN_802860d8();
  uVar5 = (undefined4)((ulonglong)uVar13 >> 0x20);
  psVar6 = (short *)FUN_8000faac();
  local_d8 = DAT_802c1f80;
  local_d4 = DAT_802c1f84;
  local_d0 = DAT_802c1f88;
  local_e4 = DAT_802c1f8c;
  local_e0 = DAT_802c1f90;
  local_dc = DAT_802c1f94;
  local_e8 = 0;
  local_9c = FLOAT_803df058;
  local_98 = FLOAT_803df058;
  local_94 = FLOAT_803df058;
  local_a0 = FLOAT_803df05c;
  local_a4 = 0;
  local_a6 = 0;
  local_a8 = 0;
  local_b4 = FLOAT_803df058;
  local_b0 = FLOAT_803df058;
  local_ac = FLOAT_803df058;
  local_b8 = FLOAT_803df05c;
  local_bc = 0;
  local_be = 0;
  local_c0 = 0;
  (**(code **)(*DAT_803dca58 + 0x20))(&local_e8);
  if ((psVar6 != (short *)0x0) && (DAT_803dd12c != 0)) {
    uVar10 = FUN_8000fbe8();
    FUN_8000fbf0((double)FLOAT_803df098,0);
    FUN_8000fb00();
    fVar1 = (*(float *)(DAT_803dd12c + 0x20c) - FLOAT_803df084) / FLOAT_803df09c;
    fVar2 = FLOAT_803df058;
    if ((FLOAT_803df058 <= fVar1) && (fVar2 = fVar1, FLOAT_803df05c < fVar1)) {
      fVar2 = FLOAT_803df05c;
    }
    if (FLOAT_803df0a0 <= fVar2) {
      if (fVar2 <= FLOAT_803df0a8) {
        DAT_803dd128 = 0xff;
      }
      else if (fVar2 <= FLOAT_803df05c) {
        DAT_803dd128 = (undefined2)
                       (int)(FLOAT_803df0a4 * (FLOAT_803df0a0 - (fVar2 - FLOAT_803df0a8)));
      }
      else {
        DAT_803dd128 = 0;
      }
    }
    else if (FLOAT_803df058 <= fVar2) {
      DAT_803dd128 = (undefined2)(int)(FLOAT_803df0a4 * fVar2);
    }
    else {
      DAT_803dd128 = 0;
    }
    fVar1 = (*(float *)(DAT_803dd12c + 0x20c) - FLOAT_803df084) / FLOAT_803df0b0;
    fVar3 = FLOAT_803df058;
    if ((FLOAT_803df058 <= fVar1) && (fVar3 = fVar1, FLOAT_803df05c < fVar1)) {
      fVar3 = FLOAT_803df05c - (fVar1 - FLOAT_803df05c);
    }
    dVar12 = -(double)(FLOAT_803df0b4 * fVar3 - FLOAT_803df05c);
    local_cc = FLOAT_803df0b8 * local_d8;
    local_c8 = FLOAT_803df0b8 * local_d4;
    local_c4 = FLOAT_803df0b8 * local_d0;
    dVar11 = (double)*(float *)(DAT_803dd12c + 0x1c);
    local_90 = (double)(longlong)(int)(fVar2 * FLOAT_803df0ac);
    local_a8 = (undefined2)(int)(fVar2 * FLOAT_803df0ac);
    FUN_80021ac8(&local_a8,&local_cc);
    local_a0 = FLOAT_803df05c;
    local_88 = (longlong)(int)dVar11;
    local_a4 = (undefined2)(int)dVar11;
    local_a6 = 0;
    local_a8 = 0;
    FUN_80021ac8(&local_a8,&local_cc);
    dVar4 = DOUBLE_803df090;
    DAT_8030f2c8 = local_cc;
    DAT_8030f2cc = local_c8;
    DAT_8030f2d0 = local_c4;
    local_80 = (double)(longlong)(int)local_cc;
    local_78 = (double)CONCAT44(0x43300000,(int)(short)(int)local_cc ^ 0x80000000);
    *(float *)(DAT_803dd148 + 6) = *(float *)(psVar6 + 0x22) + (float)(local_78 - DOUBLE_803df090);
    local_70 = (double)(longlong)(int)local_c8;
    local_68 = (double)CONCAT44(0x43300000,(int)(short)(int)local_c8 ^ 0x80000000);
    *(float *)(DAT_803dd148 + 8) = *(float *)(psVar6 + 0x24) + (float)(local_68 - dVar4);
    local_60 = (longlong)(int)local_c4;
    local_58 = (double)CONCAT44(0x43300000,(int)(short)(int)local_c4 ^ 0x80000000);
    *(float *)(DAT_803dd148 + 10) = *(float *)(psVar6 + 0x26) + (float)(local_58 - dVar4);
    *(float *)(DAT_803dd148 + 4) = (float)((double)FLOAT_803df0bc * dVar12);
    *DAT_803dd148 = -*psVar6;
    DAT_803dd148[1] = psVar6[1];
    DAT_803dd148[2] = 0;
    *(char *)((int)DAT_803dd148 + 0x37) = (char)DAT_803dd128;
    fVar1 = *(float *)(DAT_803dd12c + 0x20c);
    if (fVar1 < FLOAT_803df088) {
      fVar1 = fVar1 + FLOAT_803df0c0;
    }
    else {
      fVar1 = fVar1 - FLOAT_803df088;
    }
    fVar2 = fVar1 / FLOAT_803df0b0;
    fVar3 = FLOAT_803df058;
    if ((FLOAT_803df058 <= fVar2) && (fVar3 = fVar2, FLOAT_803df05c < fVar2)) {
      fVar3 = FLOAT_803df05c;
    }
    if (FLOAT_803df0a0 <= fVar3) {
      if (fVar3 <= FLOAT_803df0a8) {
        DAT_803dd12a = 0xff;
      }
      else if (fVar3 <= FLOAT_803df05c) {
        DAT_803dd12a = (undefined2)
                       (int)(FLOAT_803df0a4 * (FLOAT_803df0a0 - (fVar3 - FLOAT_803df0a8)));
      }
      else {
        DAT_803dd12a = 0;
      }
    }
    else if (FLOAT_803df058 <= fVar3) {
      DAT_803dd12a = (undefined2)(int)(FLOAT_803df0a4 * fVar3);
    }
    else {
      DAT_803dd12a = 0;
    }
    fVar1 = fVar1 / FLOAT_803df0c4;
    fVar2 = FLOAT_803df058;
    if ((FLOAT_803df058 <= fVar1) && (fVar2 = fVar1, FLOAT_803df05c < fVar1)) {
      fVar2 = FLOAT_803df05c - (fVar1 - FLOAT_803df05c);
    }
    dVar12 = -(double)(FLOAT_803df0b4 * fVar2 - FLOAT_803df05c);
    local_cc = FLOAT_803df0b8 * local_e4;
    local_c8 = FLOAT_803df0b8 * local_e0;
    local_c4 = FLOAT_803df0b8 * local_dc;
    local_58 = (double)(longlong)(int)(fVar3 * FLOAT_803df0ac);
    local_c0 = (undefined2)(int)(fVar3 * FLOAT_803df0ac);
    FUN_80021ac8(&local_c0,&local_cc);
    local_b8 = FLOAT_803df05c;
    local_60 = (longlong)(int)dVar11;
    local_bc = (undefined2)(int)dVar11;
    local_be = 0;
    local_c0 = 0;
    FUN_80021ac8(&local_c0,&local_cc);
    dVar4 = DOUBLE_803df090;
    DAT_8030f2d4 = local_cc;
    DAT_8030f2d8 = local_c8;
    DAT_8030f2dc = local_c4;
    local_68 = (double)(longlong)(int)local_cc;
    local_70 = (double)CONCAT44(0x43300000,(int)(short)(int)local_cc ^ 0x80000000);
    *(float *)(DAT_803dd14c + 6) = *(float *)(psVar6 + 0x22) + (float)(local_70 - DOUBLE_803df090);
    local_78 = (double)(longlong)(int)local_c8;
    local_80 = (double)CONCAT44(0x43300000,(int)(short)(int)local_c8 ^ 0x80000000);
    *(float *)(DAT_803dd14c + 8) = *(float *)(psVar6 + 0x24) + (float)(local_80 - dVar4);
    local_88 = (longlong)(int)local_c4;
    local_90 = (double)CONCAT44(0x43300000,(int)(short)(int)local_c4 ^ 0x80000000);
    *(float *)(DAT_803dd14c + 10) = *(float *)(psVar6 + 0x26) + (float)(local_90 - dVar4);
    *(float *)(DAT_803dd14c + 4) = (float)((double)FLOAT_803df0bc * dVar12);
    *DAT_803dd14c = -*psVar6;
    DAT_803dd14c[1] = psVar6[1];
    bVar8 = 0;
    DAT_803dd14c[2] = 0;
    *(char *)((int)DAT_803dd14c + 0x37) = (char)DAT_803dd12a;
    if (*(char *)((int)DAT_803dd148 + 0x37) != '\0') {
      if (DAT_803dd12c != 0) {
        bVar8 = *(byte *)(DAT_803dd12c + 0x209) >> 7;
      }
      if ((bVar8 == 0) && ((param_5 & 0xff) != 0)) {
        iVar7 = FUN_8002b588();
        *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
        FUN_8003b958(uVar5,(int)uVar13,param_3,param_4,DAT_803dd148,1);
      }
    }
    if (*(char *)((int)DAT_803dd14c + 0x37) != '\0') {
      if (DAT_803dd12c == 0) {
        bVar8 = 0;
      }
      else {
        bVar8 = *(byte *)(DAT_803dd12c + 0x209) >> 7;
      }
      if ((bVar8 == 0) && ((param_5 & 0xff) != 0)) {
        iVar7 = FUN_8002b588();
        *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
        FUN_8003b958(uVar5,(int)uVar13,param_3,param_4,DAT_803dd14c,1);
      }
    }
    FUN_8000fbf0(uVar10,0);
    FUN_8000fb00();
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  FUN_80286124();
  return;
}

