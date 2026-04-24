// Function: FUN_80207250
// Entry: 80207250
// Size: 792 bytes

void FUN_80207250(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  char cVar7;
  char cVar8;
  char cVar9;
  short *psVar10;
  undefined8 uVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar4 = FUN_8028683c();
  psVar10 = *(short **)(uVar4 + 0xb8);
  iVar5 = FUN_8002bac4();
  iVar6 = 0;
  cVar9 = '\0';
  cVar8 = '\0';
  cVar7 = '\0';
  fVar1 = *(float *)(iVar5 + 0xc) - *(float *)(uVar4 + 0xc);
  dVar12 = (double)fVar1;
  fVar2 = *(float *)(iVar5 + 0x10) - *(float *)(uVar4 + 0x10);
  dVar14 = (double)fVar2;
  fVar3 = *(float *)(iVar5 + 0x14) - *(float *)(uVar4 + 0x14);
  dVar13 = (double)fVar3;
  DAT_803de970 = DAT_803de970 + 1;
  if (dVar12 <= (double)FLOAT_803e70d0) {
    uStack_1c = (int)*psVar10 ^ 0x80000000;
    local_20 = 0x43300000;
    if (-(double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e70d8) < dVar12) {
      iVar6 = 1;
      cVar9 = '\x01';
    }
  }
  if ((double)FLOAT_803e70d0 < dVar12) {
    uStack_1c = (int)*psVar10 ^ 0x80000000;
    local_20 = 0x43300000;
    if (dVar12 < (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e70d8)) {
      iVar6 = iVar6 + 1;
      cVar9 = cVar9 + -1;
    }
  }
  if (dVar13 <= (double)FLOAT_803e70d0) {
    uStack_1c = (int)psVar10[1] ^ 0x80000000;
    local_20 = 0x43300000;
    if (-(double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e70d8) < dVar13) {
      iVar6 = iVar6 + 1;
      cVar7 = '\x01';
    }
  }
  if ((double)FLOAT_803e70d0 < dVar13) {
    uStack_1c = (int)psVar10[1] ^ 0x80000000;
    local_20 = 0x43300000;
    if (dVar13 < (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e70d8)) {
      iVar6 = iVar6 + 1;
      cVar7 = cVar7 + -1;
    }
  }
  if (dVar14 <= (double)FLOAT_803e70d0) {
    uStack_1c = (int)psVar10[2] ^ 0x80000000;
    local_20 = 0x43300000;
    if (-(double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e70d8) < dVar14) {
      iVar6 = iVar6 + 1;
      cVar8 = '\x01';
    }
  }
  if ((double)FLOAT_803e70d0 < dVar14) {
    uStack_1c = (int)psVar10[2] ^ 0x80000000;
    local_20 = 0x43300000;
    if (dVar14 < (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e70d8)) {
      iVar6 = iVar6 + 1;
      cVar8 = cVar8 + -1;
    }
  }
  if (iVar6 == 3) {
    local_30 = FLOAT_803e70e0;
    local_34 = 0;
    local_36 = 0;
    local_38 = 0;
    if (cVar9 != *(char *)(psVar10 + 8)) {
      local_38 = 0x3fff;
    }
    local_2c = fVar1;
    local_28 = fVar2;
    local_24 = fVar3;
    iVar6 = FUN_80297300(iVar5);
    if (iVar6 == 0x1d7) {
      if (0x14 < DAT_803de970) {
        DAT_803de970 = 0;
        FUN_800201ac(0x468,1);
        FUN_8000bb38(uVar4,0x1c9);
      }
      (**(code **)(*DAT_803dd708 + 8))(iVar5,0x397,0,2,0xffffffff,0);
    }
    else {
      uVar11 = FUN_800201ac(0x468,1);
      FUN_800379bc(uVar11,dVar12,dVar13,dVar14,in_f5,in_f6,in_f7,in_f8,iVar5,0x60004,uVar4,2,in_r7,
                   in_r8,in_r9,in_r10);
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x399,&local_38,2,0xffffffff,0);
      FUN_8000bb38(uVar4,0x1c9);
    }
  }
  *(char *)(psVar10 + 8) = cVar9;
  *(char *)((int)psVar10 + 0x11) = cVar8;
  *(char *)(psVar10 + 9) = cVar7;
  FUN_80286888();
  return;
}

