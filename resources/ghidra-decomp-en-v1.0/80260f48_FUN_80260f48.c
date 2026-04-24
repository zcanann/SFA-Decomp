// Function: FUN_80260f48
// Entry: 80260f48
// Size: 576 bytes

int FUN_80260f48(int param_1,uint *param_2)

{
  ushort uVar1;
  uint uVar2;
  ushort *puVar3;
  ushort **ppuVar4;
  ushort **ppuVar5;
  ushort uVar6;
  ushort uVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  ushort *local_24;
  int local_20;
  ushort *local_1c [4];
  
  ppuVar4 = local_1c;
  ppuVar5 = &local_24;
  iVar9 = 0;
  uVar8 = 0;
  uVar2 = 0;
  do {
    *ppuVar4 = (ushort *)(*(int *)(param_1 + 0x80) + (uVar2 + 1) * 0x2000);
    uVar7 = 0;
    *ppuVar5 = *ppuVar4 + 0xfe0;
    uVar6 = 0;
    puVar3 = *ppuVar4;
    iVar10 = 0x1ff;
    do {
      uVar6 = uVar6 + *puVar3 + puVar3[1] + puVar3[2] + puVar3[3] + puVar3[4] + puVar3[5] +
              puVar3[6] + puVar3[7];
      uVar7 = uVar7 + ~*puVar3 + ~puVar3[1] + ~puVar3[2] + ~puVar3[3] + ~puVar3[4] + ~puVar3[5] +
              ~puVar3[6] + ~puVar3[7];
      puVar3 = puVar3 + 8;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    iVar10 = 6;
    do {
      uVar1 = *puVar3;
      puVar3 = puVar3 + 1;
      uVar6 = uVar6 + uVar1;
      uVar7 = uVar7 + ~uVar1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    if (uVar6 == 0xffff) {
      uVar6 = 0;
    }
    if (uVar7 == 0xffff) {
      uVar7 = 0;
    }
    if ((uVar6 != (*ppuVar5)[0x1e]) || (uVar7 != (*ppuVar5)[0x1f])) {
      *(undefined4 *)(param_1 + 0x84) = 0;
      iVar9 = iVar9 + 1;
      uVar8 = uVar2;
    }
    uVar2 = uVar2 + 1;
    ppuVar4 = ppuVar4 + 1;
    ppuVar5 = ppuVar5 + 1;
  } while ((int)uVar2 < 2);
  if (iVar9 == 0) {
    if (*(ushort **)(param_1 + 0x84) == (ushort *)0x0) {
      uVar8 = (uint)(-1 < (int)(short)local_24[0x1d] - (int)*(short *)(local_20 + 0x3a));
      *(ushort **)(param_1 + 0x84) = local_1c[uVar8];
      FUN_80003494(local_1c[uVar8],local_1c[uVar8 ^ 1],0x2000);
    }
    else {
      uVar8 = (uint)(*(ushort **)(param_1 + 0x84) != local_1c[0]);
    }
  }
  if (param_2 != (uint *)0x0) {
    *param_2 = uVar8;
  }
  return iVar9;
}

