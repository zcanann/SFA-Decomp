// Function: FUN_800608f4
// Entry: 800608f4
// Size: 324 bytes

void FUN_800608f4(int param_1,int param_2)

{
  undefined4 uVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  
  iVar6 = *(int *)(DAT_803dce80 + param_2 * 4);
  uVar5 = *(int *)(DAT_803dce80 + param_2 * 4 + 4) - iVar6;
  if (0 < (int)uVar5) {
    uVar1 = FUN_80023cc8(uVar5,5,0);
    *(undefined4 *)(param_1 + 0x70) = uVar1;
    FUN_80048f48(0x28,*(undefined4 *)(param_1 + 0x70),iVar6,uVar5);
  }
  *(short *)(param_1 + 0x9c) = (short)(uVar5 / 0x14);
  iVar6 = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(ushort *)(param_1 + 0x9c); iVar4 = iVar4 + 1) {
    psVar2 = (short *)(*(int *)(param_1 + 0x70) + iVar6);
    if ((((*psVar2 < 0) || (psVar2[1] < 0)) || (0x280 < *psVar2)) || (0x280 < psVar2[1])) {
      *(undefined *)((int)psVar2 + 0xf) = 0x40;
    }
    iVar3 = *(int *)(param_1 + 0x70) + iVar6;
    if (((*(short *)(iVar3 + 8) < 0) || (*(short *)(iVar3 + 10) < 0)) ||
       ((0x280 < *(short *)(iVar3 + 8) || (0x280 < *(short *)(iVar3 + 10))))) {
      *(undefined *)(iVar3 + 0xf) = 0x40;
    }
    iVar6 = iVar6 + 0x14;
  }
  *(undefined4 *)(param_1 + 0x74) = 0;
  *(undefined2 *)(param_1 + 0x9e) = 0;
  *(ushort *)(param_1 + 4) = *(ushort *)(param_1 + 4) & 0xffbf;
  return;
}

