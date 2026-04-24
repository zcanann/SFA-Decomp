// Function: FUN_80245938
// Entry: 80245938
// Size: 776 bytes

/* WARNING: Removing unreachable block (ram,0x802459ac) */
/* WARNING: Removing unreachable block (ram,0x80245ad4) */

uint FUN_80245938(int param_1,uint param_2)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  ushort *puVar7;
  int iVar8;
  byte *pbVar9;
  int iVar10;
  uint local_20 [3];
  
  if (param_1 != 0) {
    if (param_2 == 0) {
      if (2 < (DAT_803ae053 & 3)) {
        DAT_803ae053 = DAT_803ae053 & 0xfc;
      }
      DAT_803ae042 = 0;
      DAT_803ae040 = 0;
      puVar7 = &DAT_803ae04c;
      iVar10 = 4;
      do {
        DAT_803ae040 = DAT_803ae040 + *puVar7;
        uVar1 = *puVar7;
        puVar7 = puVar7 + 1;
        DAT_803ae042 = DAT_803ae042 + ~uVar1;
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
    }
    if (param_2 < DAT_803ae080) {
      DAT_803ae080 = param_2;
    }
    uVar2 = DAT_803ae080;
    iVar8 = 0x40 - DAT_803ae080;
    pbVar9 = (byte *)((int)&DAT_803ae040 + DAT_803ae080);
    iVar10 = FUN_80254c34(0,1,-0x7fdbaa2c);
    if (iVar10 == 0) {
      DAT_803ae08c = 0;
    }
    else {
      iVar10 = FUN_80254534(0,1,3);
      if (iVar10 == 0) {
        FUN_80254d28(0);
        DAT_803ae08c = 0;
      }
      else {
        local_20[0] = uVar2 * 0x40 + 0x100 | 0xa0000000;
        uVar6 = FUN_802539e0(0,(byte *)local_20,4,1,0);
        uVar2 = countLeadingZeros(uVar6);
        uVar6 = FUN_80253dc8(0);
        uVar3 = countLeadingZeros(uVar6);
        uVar6 = FUN_80253c3c(0,pbVar9,iVar8,1);
        uVar4 = countLeadingZeros(uVar6);
        uVar6 = FUN_80254660(0);
        uVar5 = countLeadingZeros(uVar6);
        FUN_80254d28(0);
        uVar2 = countLeadingZeros((uVar2 | uVar3 | uVar4 | uVar5) >> 5);
        DAT_803ae08c = uVar2 >> 5;
      }
    }
    if (DAT_803ae08c != 0) {
      DAT_803ae080 = 0x40;
    }
  }
  DAT_803ae088 = 0;
  FUN_80243e9c();
  return DAT_803ae08c;
}

