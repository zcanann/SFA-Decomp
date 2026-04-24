// Function: FUN_80243004
// Entry: 80243004
// Size: 820 bytes

int FUN_80243004(int param_1,char *param_2)

{
  ushort uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  short sVar8;
  int iVar6;
  uint uVar7;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined2 local_24;
  undefined2 uStack34;
  undefined2 local_20;
  undefined2 uStack30;
  
  DAT_803dde2c = 0;
  sVar8 = FUN_80242f20();
  if (sVar8 == 1) {
    FUN_80242f78(param_2,0x4d000,0x1aff00);
  }
  else {
    FUN_80242f78(param_2,0x3000,0x1fcf00);
  }
  if (((*param_2 == 'Y') && (param_2[1] == 'a')) && (param_2[2] == 'y')) {
    iVar12 = *(int *)(param_2 + 4);
  }
  else {
    iVar12 = 0;
  }
  if (iVar12 != 0) {
    FUN_80242dac(param_2,param_1);
    uVar3 = DAT_803e7614;
    uVar2 = DAT_803e7610;
    DAT_803dde30 = param_1 + (uint)*(ushort *)(param_1 + 0x22);
    DAT_803dde34 = (uint)*(ushort *)(param_1 + 0x1a) * (uint)*(ushort *)(param_1 + 0x1c);
    if (1 < DAT_803dc548) {
      if (DAT_800000cc == 0) {
        uVar1 = read_volatile_2(DAT_cc00206e);
        DAT_803dc548 = (ushort)((uVar1 & 2) != 0);
      }
      else {
        DAT_803dc548 = 0;
      }
    }
    DAT_803dde28 = param_1;
    if (DAT_803dc548 == 1) {
      iVar6 = FUN_80242c10(0x54);
      local_24 = (undefined2)((uint)uVar2 >> 0x10);
      iVar11 = iVar6 - (iVar6 / DAT_803dde34) * DAT_803dde34;
      iVar10 = iVar11 / (int)(uint)*(ushort *)(DAT_803dde28 + 0x1a);
      iVar9 = iVar10 * (uint)*(ushort *)(DAT_803dde28 + 0x12);
      uVar7 = (iVar11 - iVar10 * (uint)*(ushort *)(DAT_803dde28 + 0x1a)) *
              (uint)*(ushort *)(DAT_803dde28 + 0x10);
      uVar4 = iVar9 + 4;
      uVar5 = uVar7 + (((int)uVar7 >> 3) + (uint)((int)uVar7 < 0 && (uVar7 & 7) != 0)) * -8;
      iVar11 = DAT_803dde28 + *(int *)(DAT_803dde28 + 0x24) +
               ((uint)((iVar6 / DAT_803dde34) * *(int *)(DAT_803dde28 + 0x14)) >> 1);
      iVar6 = (((int)uVar7 >> 3) + (uint)((int)uVar7 < 0 && (uVar7 & 7) != 0)) * 0x10;
      iVar10 = ((int)uVar5 >> 2) + (uint)((int)uVar5 < 0 && (uVar5 & 3) != 0);
      *(undefined2 *)
       (iVar11 + (((int)(uint)*(ushort *)(DAT_803dde28 + 0x1e) >> 3) * 0x20 >> 1) *
                 (((int)uVar4 >> 3) + (uint)((int)uVar4 < 0 && (uVar4 & 7) != 0)) + iVar6 +
        (uVar4 + (((int)uVar4 >> 3) + (uint)((int)uVar4 < 0 && (uVar4 & 7) != 0)) * -8) * 2 + iVar10
       ) = local_24;
      uVar7 = iVar9 + 5;
      uVar5 = iVar9 + 6;
      uVar4 = iVar9 + 7;
      uStack34 = (undefined2)uVar2;
      *(undefined2 *)
       (iVar11 + (((int)(uint)*(ushort *)(DAT_803dde28 + 0x1e) >> 3) * 0x20 >> 1) *
                 (((int)uVar7 >> 3) + (uint)((int)uVar7 < 0 && (uVar7 & 7) != 0)) + iVar6 +
        (uVar7 + (((int)uVar7 >> 3) + (uint)((int)uVar7 < 0 && (uVar7 & 7) != 0)) * -8) * 2 + iVar10
       ) = uStack34;
      local_20 = (undefined2)((uint)uVar3 >> 0x10);
      *(undefined2 *)
       (iVar11 + (((int)(uint)*(ushort *)(DAT_803dde28 + 0x1e) >> 3) * 0x20 >> 1) *
                 (((int)uVar5 >> 3) + (uint)((int)uVar5 < 0 && (uVar5 & 7) != 0)) + iVar6 +
        (uVar5 + (((int)uVar5 >> 3) + (uint)((int)uVar5 < 0 && (uVar5 & 7) != 0)) * -8) * 2 + iVar10
       ) = local_20;
      uStack30 = (undefined2)uVar3;
      *(undefined2 *)
       (iVar11 + (((int)(uint)*(ushort *)(DAT_803dde28 + 0x1e) >> 3) * 0x20 >> 1) *
                 (((int)uVar4 >> 3) + (uint)((int)uVar4 < 0 && (uVar4 & 7) != 0)) + iVar6 +
        (uVar4 + (((int)uVar4 >> 3) + (uint)((int)uVar4 < 0 && (uVar4 & 7) != 0)) * -8) * 2 + iVar10
       ) = uStack30;
    }
  }
  return iVar12;
}

