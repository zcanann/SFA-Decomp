// Function: FUN_80206968
// Entry: 80206968
// Size: 688 bytes

void FUN_80206968(void)

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
  double local_28;
  
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
  if (fVar1 <= FLOAT_803e6438) {
    local_28 = (double)CONCAT44(0x43300000,(int)*psVar10 ^ 0x80000000);
    if (-(float)(local_28 - DOUBLE_803e6440) < fVar1) {
      iVar6 = 1;
      cVar9 = '\x01';
    }
  }
  if (FLOAT_803e6438 < fVar1) {
    local_28 = (double)CONCAT44(0x43300000,(int)*psVar10 ^ 0x80000000);
    if (fVar1 < (float)(local_28 - DOUBLE_803e6440)) {
      iVar6 = iVar6 + 1;
      cVar9 = cVar9 + -1;
    }
  }
  if (fVar3 <= FLOAT_803e6438) {
    local_28 = (double)CONCAT44(0x43300000,(int)psVar10[1] ^ 0x80000000);
    if (-(float)(local_28 - DOUBLE_803e6440) < fVar3) {
      iVar6 = iVar6 + 1;
      cVar7 = '\x01';
    }
  }
  if (FLOAT_803e6438 < fVar3) {
    local_28 = (double)CONCAT44(0x43300000,(int)psVar10[1] ^ 0x80000000);
    if (fVar3 < (float)(local_28 - DOUBLE_803e6440)) {
      iVar6 = iVar6 + 1;
      cVar7 = cVar7 + -1;
    }
  }
  if (fVar2 <= FLOAT_803e6438) {
    local_28 = (double)CONCAT44(0x43300000,(int)psVar10[2] ^ 0x80000000);
    if (-(float)(local_28 - DOUBLE_803e6440) < fVar2) {
      iVar6 = iVar6 + 1;
      cVar8 = '\x01';
    }
  }
  if (FLOAT_803e6438 < fVar2) {
    local_28 = (double)CONCAT44(0x43300000,(int)psVar10[2] ^ 0x80000000);
    if (fVar2 < (float)(local_28 - DOUBLE_803e6440)) {
      iVar6 = iVar6 + 1;
      cVar8 = cVar8 + -1;
    }
  }
  if (-1 < psVar10[3]) {
    psVar10[3] = psVar10[3] - (short)(int)FLOAT_803db414;
  }
  if ((iVar6 == 3) && (psVar10[3] < 1)) {
    iVar4 = FUN_80296ba0(iVar5);
    if (iVar4 == 0x1d7) {
      FUN_800200e8(0x468,1);
      (**(code **)(*DAT_803dca88 + 8))(iVar5,0x397,0,2,0xffffffff,0);
    }
    else {
      FUN_80036450(iVar5,0,0x14,2,0);
    }
    FUN_8000bb18(iVar5,0x1ca);
    psVar10[3] = 200;
  }
  *(char *)(psVar10 + 8) = cVar9;
  *(char *)((int)psVar10 + 0x11) = cVar8;
  *(char *)(psVar10 + 9) = cVar7;
  FUN_80286124();
  return;
}

