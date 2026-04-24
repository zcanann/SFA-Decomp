// Function: FUN_802616ac
// Entry: 802616ac
// Size: 576 bytes

int FUN_802616ac(int param_1,uint *param_2)

{
  ushort uVar1;
  uint uVar2;
  ushort *puVar3;
  uint *puVar4;
  uint *puVar5;
  short sVar6;
  short sVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  uint local_24 [6];
  
  puVar4 = local_24 + 2;
  puVar5 = local_24;
  iVar9 = 0;
  uVar8 = 0;
  uVar2 = 0;
  do {
    *puVar4 = *(int *)(param_1 + 0x80) + (uVar2 + 1) * 0x2000;
    sVar7 = 0;
    *puVar5 = *puVar4 + 0x1fc0;
    sVar6 = 0;
    puVar3 = (ushort *)*puVar4;
    iVar10 = 0x1ff;
    do {
      sVar6 = sVar6 + *puVar3 + puVar3[1] + puVar3[2] + puVar3[3] + puVar3[4] + puVar3[5] +
              puVar3[6] + puVar3[7];
      sVar7 = sVar7 + ~*puVar3 + ~puVar3[1] + ~puVar3[2] + ~puVar3[3] + ~puVar3[4] + ~puVar3[5] +
              ~puVar3[6] + ~puVar3[7];
      puVar3 = puVar3 + 8;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    iVar10 = 6;
    do {
      uVar1 = *puVar3;
      puVar3 = puVar3 + 1;
      sVar6 = sVar6 + uVar1;
      sVar7 = sVar7 + ~uVar1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    if (sVar6 == -1) {
      sVar6 = 0;
    }
    if (sVar7 == -1) {
      sVar7 = 0;
    }
    if ((sVar6 != *(short *)(*puVar5 + 0x3c)) || (sVar7 != *(short *)(*puVar5 + 0x3e))) {
      *(undefined4 *)(param_1 + 0x84) = 0;
      iVar9 = iVar9 + 1;
      uVar8 = uVar2;
    }
    uVar2 = uVar2 + 1;
    puVar4 = puVar4 + 1;
    puVar5 = puVar5 + 1;
  } while ((int)uVar2 < 2);
  if (iVar9 == 0) {
    if (*(int *)(param_1 + 0x84) == 0) {
      uVar8 = (uint)(-1 < (int)*(short *)(local_24[0] + 0x3a) - (int)*(short *)(local_24[1] + 0x3a))
      ;
      *(uint *)(param_1 + 0x84) = local_24[uVar8 + 2];
      FUN_80003494(local_24[uVar8 + 2],local_24[(uVar8 ^ 1) + 2],0x2000);
    }
    else {
      uVar8 = (uint)(*(int *)(param_1 + 0x84) != local_24[2]);
    }
  }
  if (param_2 != (uint *)0x0) {
    *param_2 = uVar8;
  }
  return iVar9;
}

