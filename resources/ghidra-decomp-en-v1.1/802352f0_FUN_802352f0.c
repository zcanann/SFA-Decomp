// Function: FUN_802352f0
// Entry: 802352f0
// Size: 304 bytes

/* WARNING: Removing unreachable block (ram,0x80235400) */
/* WARNING: Removing unreachable block (ram,0x80235344) */
/* WARNING: Removing unreachable block (ram,0x80235300) */

void FUN_802352f0(void)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  double dVar8;
  double in_f31;
  double dVar9;
  double in_ps31_1;
  int local_38;
  int local_34 [11];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar2 = FUN_80286838();
  psVar7 = *(short **)(iVar2 + 0xb8);
  uVar3 = FUN_80020078((int)*psVar7);
  if ((uVar3 & 0xff) != (uint)*(byte *)((int)psVar7 + 9)) {
    if (*(char *)(psVar7 + 4) == '\x01') {
      dVar9 = (double)*(float *)(psVar7 + 2);
      piVar4 = FUN_80037048(0x35,&local_38);
      iVar6 = 0;
      uVar1 = countLeadingZeros(uVar3 & 0xff);
      for (; iVar6 < local_38; iVar6 = iVar6 + 1) {
        iVar5 = *piVar4;
        dVar8 = (double)FUN_800217c8((float *)(iVar2 + 0x18),(float *)(iVar5 + 0x18));
        if (dVar8 < dVar9) {
          FUN_802341d0(iVar5,(char)(uVar1 >> 5));
        }
        piVar4 = piVar4 + 1;
      }
    }
    else if (*(char *)(psVar7 + 4) == '\0') {
      dVar9 = (double)*(float *)(psVar7 + 2);
      piVar4 = FUN_80037048(0x35,local_34);
      for (iVar6 = 0; iVar6 < local_34[0]; iVar6 = iVar6 + 1) {
        iVar5 = *piVar4;
        dVar8 = (double)FUN_800217c8((float *)(iVar2 + 0x18),(float *)(iVar5 + 0x18));
        if (dVar8 < dVar9) {
          FUN_802341d0(iVar5,(char)uVar3);
        }
        piVar4 = piVar4 + 1;
      }
    }
  }
  *(char *)((int)psVar7 + 9) = (char)uVar3;
  FUN_80286884();
  return;
}

