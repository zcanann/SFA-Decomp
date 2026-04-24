// Function: FUN_80234c2c
// Entry: 80234c2c
// Size: 304 bytes

/* WARNING: Removing unreachable block (ram,0x80234c80) */
/* WARNING: Removing unreachable block (ram,0x80234d3c) */

void FUN_80234c2c(void)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  int local_38;
  int local_34 [11];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar2 = FUN_802860d4();
  psVar7 = *(short **)(iVar2 + 0xb8);
  uVar3 = FUN_8001ffb4((int)*psVar7);
  uVar3 = uVar3 & 0xff;
  if (uVar3 != *(byte *)((int)psVar7 + 9)) {
    if (*(char *)(psVar7 + 4) == '\x01') {
      dVar10 = (double)*(float *)(psVar7 + 2);
      piVar4 = (int *)FUN_80036f50(0x35,&local_38);
      iVar6 = 0;
      uVar1 = countLeadingZeros(uVar3);
      for (; iVar6 < local_38; iVar6 = iVar6 + 1) {
        iVar5 = *piVar4;
        dVar9 = (double)FUN_80021704(iVar2 + 0x18,iVar5 + 0x18);
        if (dVar9 < dVar10) {
          FUN_80233b0c(iVar5,uVar1 >> 5 & 0xff);
        }
        piVar4 = piVar4 + 1;
      }
    }
    else if (*(char *)(psVar7 + 4) == '\0') {
      dVar10 = (double)*(float *)(psVar7 + 2);
      piVar4 = (int *)FUN_80036f50(0x35,local_34);
      for (iVar6 = 0; iVar6 < local_34[0]; iVar6 = iVar6 + 1) {
        iVar5 = *piVar4;
        dVar9 = (double)FUN_80021704(iVar2 + 0x18,iVar5 + 0x18);
        if (dVar9 < dVar10) {
          FUN_80233b0c(iVar5,uVar3);
        }
        piVar4 = piVar4 + 1;
      }
    }
  }
  *(char *)((int)psVar7 + 9) = (char)uVar3;
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286120();
  return;
}

