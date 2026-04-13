// Function: FUN_8003a9ac
// Entry: 8003a9ac
// Size: 268 bytes

void FUN_8003a9ac(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  int iVar7;
  int iVar8;
  uint *puVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286838();
  iVar2 = (int)((ulonglong)uVar10 >> 0x20);
  puVar9 = (uint *)uVar10;
  iVar7 = 0;
  for (iVar8 = 0; iVar8 < param_3; iVar8 = iVar8 + 1) {
    psVar6 = (short *)0x0;
    iVar3 = *(int *)(iVar2 + 0x50);
    if (iVar3 != 0) {
      iVar4 = 0;
      iVar5 = 0;
      for (uVar1 = (uint)*(byte *)(iVar3 + 0x5a); uVar1 != 0; uVar1 = uVar1 - 1) {
        if ((*(char *)(*(int *)(iVar3 + 0x10) + *(char *)(iVar2 + 0xad) + iVar4 + 1) != -1) &&
           (*puVar9 == (uint)*(byte *)(*(int *)(iVar3 + 0x10) + iVar4))) {
          psVar6 = (short *)(*(int *)(iVar2 + 0x6c) + iVar5);
        }
        iVar4 = *(char *)(iVar3 + 0x55) + iVar4 + 1;
        iVar5 = iVar5 + 0x12;
      }
    }
    iVar3 = FUN_80039ab8(param_4,(int)psVar6);
    iVar4 = FUN_8003992c((double)FLOAT_803df658,(double)FLOAT_803df65c,param_4 + 0x30,psVar6);
    iVar7 = iVar7 + iVar3 + iVar4;
    puVar9 = puVar9 + 1;
    param_4 = param_4 + 0x60;
  }
  countLeadingZeros(param_3 * 2 - iVar7);
  FUN_80286884();
  return;
}

