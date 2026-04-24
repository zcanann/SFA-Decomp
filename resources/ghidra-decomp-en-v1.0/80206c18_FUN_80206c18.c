// Function: FUN_80206c18
// Entry: 80206c18
// Size: 792 bytes

void FUN_80206c18(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  char cVar7;
  char cVar8;
  char cVar9;
  short *psVar10;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack28;
  
  iVar4 = FUN_802860d8();
  psVar10 = *(short **)(iVar4 + 0xb8);
  iVar5 = FUN_8002b9ec();
  iVar6 = 0;
  cVar9 = '\0';
  cVar8 = '\0';
  cVar7 = '\0';
  fVar1 = *(float *)(iVar5 + 0xc) - *(float *)(iVar4 + 0xc);
  fVar2 = *(float *)(iVar5 + 0x10) - *(float *)(iVar4 + 0x10);
  fVar3 = *(float *)(iVar5 + 0x14) - *(float *)(iVar4 + 0x14);
  DAT_803ddcf0 = DAT_803ddcf0 + 1;
  if (fVar1 <= FLOAT_803e6438) {
    uStack28 = (int)*psVar10 ^ 0x80000000;
    local_20 = 0x43300000;
    if (-(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6440) < fVar1) {
      iVar6 = 1;
      cVar9 = '\x01';
    }
  }
  if (FLOAT_803e6438 < fVar1) {
    uStack28 = (int)*psVar10 ^ 0x80000000;
    local_20 = 0x43300000;
    if (fVar1 < (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6440)) {
      iVar6 = iVar6 + 1;
      cVar9 = cVar9 + -1;
    }
  }
  if (fVar3 <= FLOAT_803e6438) {
    uStack28 = (int)psVar10[1] ^ 0x80000000;
    local_20 = 0x43300000;
    if (-(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6440) < fVar3) {
      iVar6 = iVar6 + 1;
      cVar7 = '\x01';
    }
  }
  if (FLOAT_803e6438 < fVar3) {
    uStack28 = (int)psVar10[1] ^ 0x80000000;
    local_20 = 0x43300000;
    if (fVar3 < (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6440)) {
      iVar6 = iVar6 + 1;
      cVar7 = cVar7 + -1;
    }
  }
  if (fVar2 <= FLOAT_803e6438) {
    uStack28 = (int)psVar10[2] ^ 0x80000000;
    local_20 = 0x43300000;
    if (-(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6440) < fVar2) {
      iVar6 = iVar6 + 1;
      cVar8 = '\x01';
    }
  }
  if (FLOAT_803e6438 < fVar2) {
    uStack28 = (int)psVar10[2] ^ 0x80000000;
    local_20 = 0x43300000;
    if (fVar2 < (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6440)) {
      iVar6 = iVar6 + 1;
      cVar8 = cVar8 + -1;
    }
  }
  if (iVar6 == 3) {
    local_30 = FLOAT_803e6448;
    local_34 = 0;
    local_36 = 0;
    local_38 = 0;
    if (cVar9 != *(char *)(psVar10 + 8)) {
      local_38 = 0x3fff;
    }
    local_2c = fVar1;
    local_28 = fVar2;
    local_24 = fVar3;
    iVar6 = FUN_80296ba0(iVar5);
    if (iVar6 == 0x1d7) {
      if (0x14 < DAT_803ddcf0) {
        DAT_803ddcf0 = 0;
        FUN_800200e8(0x468,1);
        FUN_8000bb18(iVar4,0x1c9);
      }
      (**(code **)(*DAT_803dca88 + 8))(iVar5,0x397,0,2,0xffffffff,0);
    }
    else {
      FUN_800200e8(0x468,1);
      FUN_800378c4(iVar5,0x60004,iVar4,2);
      (**(code **)(*DAT_803dca88 + 8))(iVar4,0x399,&local_38,2,0xffffffff,0);
      FUN_8000bb18(iVar4,0x1c9);
    }
  }
  *(char *)(psVar10 + 8) = cVar9;
  *(char *)((int)psVar10 + 0x11) = cVar8;
  *(char *)(psVar10 + 9) = cVar7;
  FUN_80286124();
  return;
}

