// Function: FUN_8027c168
// Entry: 8027c168
// Size: 932 bytes

undefined4 FUN_8027c168(byte param_1,byte param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  uint *puVar8;
  uint uVar9;
  
  DAT_803deffc = param_2;
  DAT_803deffd = param_1;
  DAT_803def90 = FUN_80284bac();
  DAT_803defb0 = FUN_802852d0();
  if ((DAT_803defb0 != 0) && (DAT_803defbc = FUN_802852d0(), DAT_803defbc != 0)) {
    FUN_800033a8(DAT_803defbc,0,0x280);
    FUN_802420e0(DAT_803defbc,0x280);
    DAT_803defc4 = FUN_802852d0();
    if ((DAT_803defc4 != 0) && (DAT_803defc0 = FUN_802852d0(), DAT_803defc0 != 0)) {
      FUN_802420b0(DAT_803defc0,(uint)DAT_803deffd << 6);
      iVar7 = 0;
      uVar9 = DAT_803defc0;
      for (uVar6 = 0; uVar6 < DAT_803deffd; uVar6 = uVar6 + 1) {
        *(undefined *)(DAT_803defc4 + iVar7 + 0xec) = 0;
        *(undefined *)(DAT_803defc4 + iVar7 + 0xed) = 0;
        *(undefined *)(DAT_803defc4 + iVar7 + 0xee) = 0;
        *(undefined *)(DAT_803defc4 + iVar7 + 0xe4) = 0xff;
        *(undefined *)(DAT_803defc4 + iVar7 + 0xe5) = 0xff;
        *(undefined *)(DAT_803defc4 + iVar7 + 0xe6) = 0xff;
        *(undefined *)(DAT_803defc4 + iVar7 + 0xe7) = 0xff;
        uVar2 = FUN_802852d0();
        *(undefined4 *)(DAT_803defc4 + iVar7) = uVar2;
        FUN_800033a8(*(int *)(DAT_803defc4 + iVar7),0,0xbc);
        uVar2 = FUN_802852d0();
        *(undefined4 *)(DAT_803defc4 + iVar7 + 4) = uVar2;
        *(short *)(*(int *)(DAT_803defc4 + iVar7) + 4) =
             (short)((uint)*(int *)(DAT_803defc4 + iVar7) >> 0x10);
        *(short *)(*(int *)(DAT_803defc4 + iVar7) + 6) = (short)*(int *)(DAT_803defc4 + iVar7);
        *(short *)(*(int *)(DAT_803defc4 + iVar7) + 0x4e) =
             (short)((uint)((int *)(DAT_803defc4 + iVar7))[1] >> 0x10);
        *(short *)(*(int *)(DAT_803defc4 + iVar7) + 0x50) =
             (short)((int *)(DAT_803defc4 + iVar7))[1];
        *(short *)(*(int *)(DAT_803defc4 + iVar7) + 0x38) = (short)(uVar9 >> 0x10);
        *(short *)(*(int *)(DAT_803defc4 + iVar7) + 0x3a) = (short)uVar9;
        *(uint *)(DAT_803defc4 + iVar7 + 8) = uVar9;
        uVar9 = uVar9 + 0x40;
        *(undefined4 *)(DAT_803defc4 + iVar7 + 0xe8) = 0xffffffff;
        FUN_80242178(*(uint *)(DAT_803defc4 + iVar7),0xbc);
        iVar5 = iVar7 + 0x28;
        *(undefined4 *)(DAT_803defc4 + iVar7 + 0x24) = 0;
        iVar4 = iVar7 + 0x2c;
        iVar3 = iVar7 + 0x30;
        iVar1 = iVar7 + 0x34;
        iVar7 = iVar7 + 0xf4;
        *(undefined4 *)(DAT_803defc4 + iVar5) = 0;
        *(undefined4 *)(DAT_803defc4 + iVar4) = 0;
        *(undefined4 *)(DAT_803defc4 + iVar3) = 0;
        *(undefined4 *)(DAT_803defc4 + iVar1) = 0;
      }
      puVar8 = &DAT_803cce40;
      uVar9 = 0;
      while( true ) {
        if (DAT_803deffc <= uVar9) {
          FUN_8027c620(0,1,(uint)(param_3 != 0));
          DAT_803defb8 = FUN_802852d0();
          if (DAT_803defb8 == 0) {
            return 0;
          }
          FUN_8027c50c();
          return 1;
        }
        *(undefined *)(puVar8 + 0x14) = 0;
        uVar6 = FUN_802852d0();
        *puVar8 = uVar6;
        if (uVar6 == 0) {
          return 0;
        }
        uVar6 = FUN_802852d0();
        puVar8[10] = uVar6;
        if (uVar6 == 0) break;
        FUN_800033a8(puVar8[10],0,0x3c00);
        FUN_80242148(puVar8[10],0x3c00);
        puVar8[0xb] = puVar8[10] + 0x780;
        puVar8[0xc] = puVar8[0xb] + 0x780;
        puVar8[0xd] = puVar8[0xc] + 0x780;
        puVar8[0xe] = puVar8[0xd] + 0x780;
        puVar8[0xf] = puVar8[0xe] + 0x780;
        puVar8[0x10] = puVar8[0xf] + 0x780;
        puVar8[0x11] = puVar8[0x10] + 0x780;
        FUN_800033a8(*puVar8,0,0x36);
        puVar8[3] = 0;
        puVar8[2] = 0;
        puVar8[1] = 0;
        puVar8[6] = 0;
        puVar8[5] = 0;
        puVar8[4] = 0;
        puVar8[9] = 0;
        puVar8[8] = 0;
        puVar8[7] = 0;
        FUN_80242148(*puVar8,0x36);
        puVar8 = puVar8 + 0x2f;
        uVar9 = uVar9 + 1;
      }
      return 0;
    }
  }
  return 0;
}

