// Function: FUN_8019443c
// Entry: 8019443c
// Size: 608 bytes

/* WARNING: Removing unreachable block (ram,0x80194674) */
/* WARNING: Removing unreachable block (ram,0x80194664) */
/* WARNING: Removing unreachable block (ram,0x8019465c) */
/* WARNING: Removing unreachable block (ram,0x8019466c) */
/* WARNING: Removing unreachable block (ram,0x8019467c) */

void FUN_8019443c(void)

{
  float fVar1;
  float fVar2;
  undefined2 *puVar3;
  int iVar4;
  uint *puVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f27;
  double dVar10;
  undefined8 in_f28;
  double dVar11;
  undefined8 in_f29;
  double dVar12;
  undefined8 in_f30;
  double dVar13;
  undefined8 in_f31;
  undefined8 uVar14;
  float local_a8;
  float local_a4;
  float local_a0;
  undefined2 local_9c;
  undefined2 local_9a;
  undefined2 local_98;
  float local_90;
  float local_8c;
  float local_88;
  undefined4 local_80;
  uint uStack124;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  uVar14 = FUN_802860d4();
  puVar3 = (undefined2 *)((ulonglong)uVar14 >> 0x20);
  iVar4 = (int)uVar14;
  iVar7 = *(int *)(puVar3 + 0x26);
  iVar6 = 6;
  dVar10 = (double)FLOAT_803e3fd0;
  dVar11 = (double)FLOAT_803e3fd4;
  dVar12 = (double)FLOAT_803e3fd8;
  dVar13 = (double)FLOAT_803e3fdc;
  dVar9 = DOUBLE_803e3ff0;
  do {
    uStack124 = FUN_800221a0(0xffffff9c,100);
    uStack124 = uStack124 ^ 0x80000000;
    local_80 = 0x43300000;
    local_a8 = (float)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack124) - dVar9));
    local_a4 = (float)dVar11;
    local_a0 = (float)dVar11;
    local_98 = FUN_800221a0(0xffff8001,0x8000);
    local_9a = 0;
    local_9c = 0;
    FUN_80021ac8(&local_9c,&local_a8);
    local_a0 = (float)((double)local_a0 - dVar12);
    FUN_80021ac8(puVar3,&local_a8);
    local_98 = *(undefined2 *)(iVar7 + 0x1c);
    local_9c = *puVar3;
    local_90 = *(float *)(puVar3 + 0xc) + local_a8;
    local_8c = (float)(dVar13 + (double)(*(float *)(puVar3 + 0xe) + local_a4));
    local_88 = *(float *)(puVar3 + 0x10) + local_a0;
    (**(code **)(*DAT_803dca88 + 8))(puVar3,0xca,&local_9c,0x200001,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(puVar3,0xcb,&local_9c,0x200001,0xffffffff,0);
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  puVar5 = *(uint **)(puVar3 + 0x5c);
  fVar1 = *(float *)(iVar4 + 0x10) - *(float *)(puVar3 + 8);
  if ((fVar1 < FLOAT_803e3fe0) || (FLOAT_803e3fe4 < fVar1)) {
    dVar9 = (double)FLOAT_803e3fd4;
  }
  else {
    fVar1 = *(float *)(iVar4 + 0xc) - *(float *)(puVar3 + 6);
    fVar2 = *(float *)(iVar4 + 0x14) - *(float *)(puVar3 + 10);
    if (fVar1 * fVar1 + fVar2 * fVar2 <= FLOAT_803e3fe8) {
      *puVar5 = *puVar5 + 0x3c;
      uStack124 = *puVar5 ^ 0x80000000;
      local_80 = 0x43300000;
      dVar9 = (double)((float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e3ff0) /
                      FLOAT_803e3fec);
    }
    else {
      dVar9 = (double)FLOAT_803e3fd4;
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  __psq_l0(auStack72,uVar8);
  __psq_l1(auStack72,uVar8);
  FUN_80286120(dVar9);
  return;
}

