// Function: FUN_802436fc
// Entry: 802436fc
// Size: 820 bytes

int FUN_802436fc(int param_1,char *param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  ushort uVar7;
  uint uVar5;
  uint uVar6;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined2 local_24;
  undefined2 uStack_22;
  undefined2 local_20;
  undefined2 uStack_1e;
  
  DAT_803deaac = 0;
  uVar7 = FUN_80243618();
  if (uVar7 == 1) {
    FUN_80243670((uint)param_2,0x4d000,0x1aff00);
  }
  else {
    FUN_80243670((uint)param_2,0x3000,0x1fcf00);
  }
  if (((*param_2 == 'Y') && (param_2[1] == 'a')) && (param_2[2] == 'y')) {
    iVar12 = *(int *)(param_2 + 4);
  }
  else {
    iVar12 = 0;
  }
  if (iVar12 != 0) {
    FUN_802434a4((int)param_2,param_1);
    uVar2 = DAT_803e82ac;
    uVar1 = DAT_803e82a8;
    DAT_803deab0 = param_1 + (uint)*(ushort *)(param_1 + 0x22);
    DAT_803deab4 = (uint)*(ushort *)(param_1 + 0x1a) * (uint)*(ushort *)(param_1 + 0x1c);
    if (1 < DAT_803dd1b0) {
      if (DAT_800000cc == 0) {
        uVar7 = DAT_cc00206e;
        DAT_803dd1b0 = (ushort)((uVar7 & 2) != 0);
      }
      else {
        DAT_803dd1b0 = 0;
      }
    }
    DAT_803deaa8 = param_1;
    if (DAT_803dd1b0 == 1) {
      uVar5 = FUN_80243308(0x54);
      local_24 = (undefined2)((uint)uVar1 >> 0x10);
      iVar11 = uVar5 - ((int)uVar5 / DAT_803deab4) * DAT_803deab4;
      iVar10 = iVar11 / (int)(uint)*(ushort *)(DAT_803deaa8 + 0x1a);
      iVar9 = iVar10 * (uint)*(ushort *)(DAT_803deaa8 + 0x12);
      uVar6 = (iVar11 - iVar10 * (uint)*(ushort *)(DAT_803deaa8 + 0x1a)) *
              (uint)*(ushort *)(DAT_803deaa8 + 0x10);
      uVar3 = iVar9 + 4;
      uVar4 = uVar6 + (((int)uVar6 >> 3) + (uint)((int)uVar6 < 0 && (uVar6 & 7) != 0)) * -8;
      iVar8 = DAT_803deaa8 + *(int *)(DAT_803deaa8 + 0x24) +
              ((uint)(((int)uVar5 / DAT_803deab4) * *(int *)(DAT_803deaa8 + 0x14)) >> 1);
      iVar10 = (((int)uVar6 >> 3) + (uint)((int)uVar6 < 0 && (uVar6 & 7) != 0)) * 0x10;
      iVar11 = ((int)uVar4 >> 2) + (uint)((int)uVar4 < 0 && (uVar4 & 3) != 0);
      *(undefined2 *)
       (iVar8 + (((int)(uint)*(ushort *)(DAT_803deaa8 + 0x1e) >> 3) * 0x20 >> 1) *
                (((int)uVar3 >> 3) + (uint)((int)uVar3 < 0 && (uVar3 & 7) != 0)) + iVar10 +
        (uVar3 + (((int)uVar3 >> 3) + (uint)((int)uVar3 < 0 && (uVar3 & 7) != 0)) * -8) * 2 + iVar11
       ) = local_24;
      uVar5 = iVar9 + 5;
      uVar4 = iVar9 + 6;
      uVar3 = iVar9 + 7;
      uStack_22 = (undefined2)uVar1;
      *(undefined2 *)
       (iVar8 + (((int)(uint)*(ushort *)(DAT_803deaa8 + 0x1e) >> 3) * 0x20 >> 1) *
                (((int)uVar5 >> 3) + (uint)((int)uVar5 < 0 && (uVar5 & 7) != 0)) + iVar10 +
        (uVar5 + (((int)uVar5 >> 3) + (uint)((int)uVar5 < 0 && (uVar5 & 7) != 0)) * -8) * 2 + iVar11
       ) = uStack_22;
      local_20 = (undefined2)((uint)uVar2 >> 0x10);
      *(undefined2 *)
       (iVar8 + (((int)(uint)*(ushort *)(DAT_803deaa8 + 0x1e) >> 3) * 0x20 >> 1) *
                (((int)uVar4 >> 3) + (uint)((int)uVar4 < 0 && (uVar4 & 7) != 0)) + iVar10 +
        (uVar4 + (((int)uVar4 >> 3) + (uint)((int)uVar4 < 0 && (uVar4 & 7) != 0)) * -8) * 2 + iVar11
       ) = local_20;
      uStack_1e = (undefined2)uVar2;
      *(undefined2 *)
       (iVar8 + (((int)(uint)*(ushort *)(DAT_803deaa8 + 0x1e) >> 3) * 0x20 >> 1) *
                (((int)uVar3 >> 3) + (uint)((int)uVar3 < 0 && (uVar3 & 7) != 0)) + iVar10 +
        (uVar3 + (((int)uVar3 >> 3) + (uint)((int)uVar3 < 0 && (uVar3 & 7) != 0)) * -8) * 2 + iVar11
       ) = uStack_1e;
    }
  }
  return iVar12;
}

