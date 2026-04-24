// Function: FUN_800257d0
// Entry: 800257d0
// Size: 176 bytes

uint FUN_800257d0(uint param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  
  if (param_2 == 0) {
    for (uVar2 = param_3 << 2; (uVar2 & 7) != 0; uVar2 = uVar2 + 1) {
    }
    FUN_80048f48(0x31,DAT_803dcb60,(param_1 & 0xfffffffc) << 2,0x20);
    iVar1 = (param_1 & 3) * 4;
    uVar2 = uVar2 + (*(int *)(DAT_803dcb60 + iVar1 + 4) - *(int *)(DAT_803dcb60 + iVar1));
  }
  else {
    for (uVar2 = param_3 * 2 + 8; (uVar2 & 7) != 0; uVar2 = uVar2 + 1) {
    }
  }
  return uVar2;
}

