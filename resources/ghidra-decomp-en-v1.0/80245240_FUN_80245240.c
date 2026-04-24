// Function: FUN_80245240
// Entry: 80245240
// Size: 776 bytes

/* WARNING: Removing unreachable block (ram,0x802452b4) */
/* WARNING: Removing unreachable block (ram,0x802453dc) */

uint FUN_80245240(int param_1,uint param_2)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  ushort *puVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  uint local_20 [3];
  
  if (param_1 != 0) {
    if (param_2 == 0) {
      if (2 < (DAT_803ad3f3 & 3)) {
        DAT_803ad3f3 = DAT_803ad3f3 & 0xfc;
      }
      DAT_803ad3e2 = 0;
      DAT_803ad3e0 = 0;
      puVar7 = &DAT_803ad3ec;
      iVar10 = 4;
      do {
        DAT_803ad3e0 = DAT_803ad3e0 + *puVar7;
        uVar1 = *puVar7;
        puVar7 = puVar7 + 1;
        DAT_803ad3e2 = DAT_803ad3e2 + ~uVar1;
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
    }
    if (param_2 < DAT_803ad420) {
      DAT_803ad420 = param_2;
    }
    uVar2 = DAT_803ad420;
    iVar8 = 0x40 - DAT_803ad420;
    iVar9 = (int)&DAT_803ad3e0 + DAT_803ad420;
    iVar10 = FUN_802544d0(0,1,&LAB_80244edc);
    if (iVar10 == 0) {
      DAT_803ad42c = 0;
    }
    else {
      iVar10 = FUN_80253dd0(0,1,3);
      if (iVar10 == 0) {
        FUN_802545c4(0);
        DAT_803ad42c = 0;
      }
      else {
        local_20[0] = uVar2 * 0x40 + 0x100 | 0xa0000000;
        uVar6 = FUN_8025327c(0,local_20,4,1,0);
        uVar2 = countLeadingZeros(uVar6);
        uVar6 = FUN_80253664(0);
        uVar3 = countLeadingZeros(uVar6);
        uVar6 = FUN_802534d8(0,iVar9,iVar8,1);
        uVar4 = countLeadingZeros(uVar6);
        uVar6 = FUN_80253efc(0);
        uVar5 = countLeadingZeros(uVar6);
        FUN_802545c4(0);
        uVar2 = countLeadingZeros((uVar2 | uVar3 | uVar4 | uVar5) >> 5);
        DAT_803ad42c = uVar2 >> 5;
      }
    }
    if (DAT_803ad42c != 0) {
      DAT_803ad420 = 0x40;
    }
  }
  DAT_803ad428 = 0;
  FUN_802437a4(DAT_803ad424);
  return DAT_803ad42c;
}

