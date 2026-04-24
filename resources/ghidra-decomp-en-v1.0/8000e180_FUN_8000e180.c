// Function: FUN_8000e180
// Entry: 8000e180
// Size: 408 bytes

/* WARNING: Removing unreachable block (ram,0x8000e2f8) */

void FUN_8000e180(void)

{
  int iVar1;
  bool bVar2;
  int iVar3;
  short **ppsVar4;
  short *psVar5;
  char cVar6;
  undefined4 uVar7;
  undefined8 in_f31;
  double dVar8;
  undefined8 uVar9;
  short *local_58 [4];
  short local_48;
  short local_46;
  short local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar9 = FUN_802860d8();
  iVar1 = (int)uVar9 * 0x40;
  iVar3 = iVar1 + -0x7fcc87f0;
  bVar2 = false;
  cVar6 = '\0';
  ppsVar4 = local_58;
  for (psVar5 = (short *)((ulonglong)uVar9 >> 0x20); psVar5 != (short *)0x0;
      psVar5 = *(short **)(psVar5 + 0x18)) {
    *ppsVar4 = psVar5;
    ppsVar4 = ppsVar4 + 1;
    cVar6 = cVar6 + '\x01';
    dVar8 = (double)*(float *)(psVar5 + 4);
    if ((psVar5[0x58] & 8U) == 0) {
      *(float *)(psVar5 + 4) = FLOAT_803de5f0;
    }
    if (bVar2) {
      FUN_80021ee8(&DAT_80337fd0,psVar5);
      FUN_80022404(iVar3,&DAT_80337fd0,iVar3);
    }
    else {
      FUN_80021ee8(iVar3,psVar5);
    }
    *(float *)(psVar5 + 4) = (float)dVar8;
    bVar2 = true;
  }
  ppsVar4 = local_58 + cVar6;
  while ('\0' < cVar6) {
    ppsVar4 = ppsVar4 + -1;
    cVar6 = cVar6 + -1;
    psVar5 = *ppsVar4;
    local_3c = -*(float *)(psVar5 + 6);
    local_38 = -*(float *)(psVar5 + 8);
    local_34 = -*(float *)(psVar5 + 10);
    if ((psVar5[0x58] & 8U) == 0) {
      local_40 = FLOAT_803de5f0;
    }
    else {
      local_40 = FLOAT_803de5f0 / *(float *)(psVar5 + 4);
    }
    local_48 = -*psVar5;
    local_46 = -psVar5[1];
    local_44 = -psVar5[2];
    FUN_80021ba0(iVar1 + -0x7fcc8f70,&local_48);
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286124();
  return;
}

