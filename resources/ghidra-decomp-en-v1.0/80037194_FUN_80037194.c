// Function: FUN_80037194
// Entry: 80037194
// Size: 108 bytes

int FUN_80037194(int param_1)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  byte *pbVar4;
  int iVar5;
  
  iVar5 = 0;
  piVar3 = &DAT_803428f8;
  uVar1 = (uint)DAT_803dcbf0;
  while( true ) {
    if (uVar1 == 0) {
      return 0;
    }
    if (*piVar3 == param_1) break;
    piVar3 = piVar3 + 1;
    iVar5 = iVar5 + 1;
    uVar1 = uVar1 - 1;
  }
  iVar2 = 0;
  pbVar4 = &DAT_80342cf8;
  while( true ) {
    if (iVar5 < (int)(uint)*pbVar4) {
      return iVar2;
    }
    if (0x54 < iVar2) break;
    pbVar4 = pbVar4 + 1;
    iVar2 = iVar2 + 1;
  }
  return iVar2;
}

