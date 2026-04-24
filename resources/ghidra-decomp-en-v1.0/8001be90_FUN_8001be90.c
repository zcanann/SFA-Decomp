// Function: FUN_8001be90
// Entry: 8001be90
// Size: 1820 bytes

void FUN_8001be90(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined2 uVar1;
  undefined2 uVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  uint uVar7;
  undefined2 *puVar8;
  int iVar9;
  undefined4 uVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  undefined8 uVar14;
  uint local_88;
  uint local_84;
  int local_80;
  undefined auStack124 [4];
  int local_78;
  int local_74;
  int local_70;
  int local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  
  uVar14 = FUN_802860d0();
  puVar8 = (undefined2 *)((ulonglong)uVar14 >> 0x20);
  iVar9 = (int)uVar14;
  uVar1 = *(undefined2 *)(param_3 + 0x18);
  uVar2 = *(undefined2 *)(param_3 + 0x1a);
  if ((*(ushort *)(param_3 + 0x1c) & 1) == 0) {
    *(ushort *)(param_3 + 0x1c) = *(ushort *)(param_3 + 0x1c) | 1;
    switch(*(undefined *)(param_3 + 0x13)) {
    case 0:
      uStack36 = (int)*(short *)(param_3 + 0x14) ^ 0x80000000;
      local_28 = 0x43300000;
      uStack44 = (int)*(short *)(param_3 + 0x16) ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803de748),
                   (double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de748),
                   DAT_803dca28,0xff,0x100,*(undefined2 *)(param_3 + 8),
                   *(undefined2 *)(param_3 + 10),0);
      break;
    case 1:
      local_68 = DAT_803de740;
      FUN_800753b8((int)*(short *)(param_3 + 0x14),(int)*(short *)(param_3 + 0x16),
                   (int)*(short *)(param_3 + 0x14) + (uint)*(ushort *)(param_3 + 8),
                   (int)*(short *)(param_3 + 0x16) + (uint)*(ushort *)(param_3 + 10),&local_68);
      break;
    case 2:
      uVar12 = (uint)*(short *)(param_3 + 0x14);
      uVar7 = (uint)*(ushort *)(param_3 + 8);
      iVar9 = (int)*(short *)(param_3 + 0x16);
      uVar13 = (int)uVar7 >> 1;
      if (0xc < uVar13) {
        uVar13 = 0xc;
      }
      iVar11 = uVar7 + uVar13 * -2;
      if (iVar11 < 0) {
        iVar11 = 0;
      }
      FUN_8025d324(0,0,0x280,0x1e0);
      uStack36 = uVar12 - 0x34 ^ 0x80000000;
      local_28 = 0x43300000;
      uStack44 = iVar9 - 0x23U ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803de748),
                   (double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de748),
                   DAT_8033be40,*(undefined *)(param_3 + 0x1e),0x100);
      uStack52 = uVar12 + uVar7 ^ 0x80000000;
      local_38 = 0x43300000;
      uStack60 = iVar9 - 0x23U ^ 0x80000000;
      local_40 = 0x43300000;
      FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803de748),
                   (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803de748),
                   DAT_8033be50,*(undefined *)(param_3 + 0x1e),0x100);
      if (uVar13 != 0) {
        uStack36 = uVar12 ^ 0x80000000;
        local_28 = 0x43300000;
        uStack44 = iVar9 - 0x13U ^ 0x80000000;
        local_30 = 0x43300000;
        FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803de748),
                     (double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de748),
                     DAT_8033be44,*(undefined *)(param_3 + 0x1e),0x100,uVar13,0x3a,0);
        uStack52 = (uVar12 + uVar7) - uVar13 ^ 0x80000000;
        local_38 = 0x43300000;
        uStack60 = iVar9 - 0x13U ^ 0x80000000;
        local_40 = 0x43300000;
        FUN_80075fc8((double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803de748),
                     (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803de748),
                     DAT_8033be4c,*(undefined *)(param_3 + 0x1e),0x100,uVar13,0x3a,0xc - uVar13,0);
      }
      if (iVar11 != 0) {
        uStack36 = uVar12 + uVar13 ^ 0x80000000;
        local_28 = 0x43300000;
        uStack44 = iVar9 - 0x13U ^ 0x80000000;
        local_30 = 0x43300000;
        FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803de748),
                     (double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de748),
                     DAT_8033be48,*(undefined *)(param_3 + 0x1e),0x100,iVar11,0x3a,0);
      }
      break;
    case 3:
      uVar10 = FUN_800173dc();
      if (puVar8 == (undefined2 *)0x0) {
        if (iVar9 != 0) {
          uVar7 = param_3 + 0x7fd38c00;
          FUN_800164b0(iVar9,((int)uVar7 >> 5) + (uint)((int)uVar7 < 0 && (uVar7 & 0x1f) != 0),
                       &local_88,&local_84,&local_80,auStack124);
        }
      }
      else {
        FUN_8001628c(*puVar8,0,0,&local_88,&local_84,&local_80,auStack124);
      }
      FUN_80017434(uVar10);
      uStack36 = local_88 - 0x16 ^ 0x80000000;
      local_28 = 0x43300000;
      uStack44 = local_80 - 9U ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803de748),
                   (double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de748),
                   DAT_8033be54,*(undefined *)(param_3 + 0x1e),0x100);
      uStack52 = local_88 ^ 0x80000000;
      local_38 = 0x43300000;
      uStack60 = local_80 - 9U ^ 0x80000000;
      local_40 = 0x43300000;
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803de748),
                   (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803de748),
                   DAT_8033be58,*(undefined *)(param_3 + 0x1e),0x100,local_84 - local_88,0x24,0);
      uStack68 = local_84 ^ 0x80000000;
      local_48 = 0x43300000;
      uStack76 = local_80 - 9U ^ 0x80000000;
      local_50 = 0x43300000;
      FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803de748),
                   (double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803de748),
                   DAT_8033be5c,*(undefined *)(param_3 + 0x1e),0x100);
      break;
    case 4:
      FUN_8001c5ac();
      break;
    case 5:
      goto LAB_8001c594;
    case 6:
      if (puVar8 == (undefined2 *)0x0) goto LAB_8001c594;
      uVar10 = FUN_800173dc();
      if (puVar8 == (undefined2 *)0x0) {
        if (iVar9 != 0) {
          uVar7 = param_3 + 0x7fd38c00;
          FUN_800164b0(iVar9,((int)uVar7 >> 5) + (uint)((int)uVar7 < 0 && (uVar7 & 0x1f) != 0),
                       &local_78,&local_74,&local_70,&local_6c);
        }
      }
      else {
        FUN_8001628c(*puVar8,0,0,&local_78,&local_74,&local_70,&local_6c);
      }
      FUN_80017434(uVar10);
      iVar9 = local_74 - local_78 >> 1;
      iVar11 = local_6c - local_70 >> 1;
      uStack44 = local_78 + iVar9;
      uStack36 = local_70 + iVar11;
      uStack92 = local_78 - DAT_803db3ec ^ 0x80000000;
      local_60 = 0x43300000;
      uStack84 = local_70 - DAT_803db3ec ^ 0x80000000;
      local_58 = 0x43300000;
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803de748),
                   (double)(float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803de748),
                   DAT_803dca24,0xff,0x100,iVar9 + DAT_803db3ec,iVar11 + DAT_803db3ec,0);
      uStack76 = uStack44 ^ 0x80000000;
      local_50 = 0x43300000;
      uStack68 = local_70 - DAT_803db3ec ^ 0x80000000;
      local_48 = 0x43300000;
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803de748),
                   (double)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803de748),
                   DAT_803dca24,0xff,0x100,iVar9 + DAT_803db3ec,iVar11 + DAT_803db3ec,1);
      uStack60 = local_78 - DAT_803db3ec ^ 0x80000000;
      local_40 = 0x43300000;
      uStack52 = uStack36 ^ 0x80000000;
      local_38 = 0x43300000;
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803de748),
                   (double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803de748),
                   DAT_803dca24,0xff,0x100,iVar9 + DAT_803db3ec,iVar11 + DAT_803db3ec,2);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      FUN_8007681c((double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803de748),
                   (double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803de748),
                   DAT_803dca24,0xff,0x100,iVar9 + DAT_803db3ec,iVar11 + DAT_803db3ec,3);
      break;
    case 7:
      iVar9 = FUN_80019bf0();
      if (iVar9 == 3) {
        local_64 = DAT_803de740;
        FUN_800753b8((int)*(short *)(param_3 + 0x14),(int)*(short *)(param_3 + 0x16),
                     (int)*(short *)(param_3 + 0x14) + (uint)*(ushort *)(param_3 + 8),
                     (int)*(short *)(param_3 + 0x16) + (uint)*(ushort *)(param_3 + 10),&local_64);
      }
      else {
        sVar5 = *(short *)(param_3 + 10);
        sVar6 = *(short *)(param_3 + 8);
        sVar3 = *(short *)(param_3 + 0x16);
        sVar4 = *(short *)(param_3 + 0x14);
        FUN_8025d324(0,0,0x280,0x1e0);
        FUN_8012c6ac((int)sVar4,(int)sVar3,(int)sVar6,(int)sVar5,0xff,1);
      }
    }
    *(undefined2 *)(param_3 + 0x18) = uVar1;
    *(undefined2 *)(param_3 + 0x1a) = uVar2;
  }
LAB_8001c594:
  FUN_8028611c();
  return;
}

