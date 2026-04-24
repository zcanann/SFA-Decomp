// Function: FUN_8027ba04
// Entry: 8027ba04
// Size: 932 bytes

undefined4 FUN_8027ba04(byte param_1,byte param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  int *piVar9;
  
  DAT_803de37c = param_2;
  DAT_803de37d = param_1;
  DAT_803de310 = FUN_80284448();
  DAT_803de330 = FUN_80284b6c(0x800);
  if ((DAT_803de330 != 0) && (DAT_803de33c = FUN_80284b6c(0x280), DAT_803de33c != 0)) {
    FUN_800033a8(DAT_803de33c,0,0x280);
    FUN_802419e8(DAT_803de33c,0x280);
    DAT_803de344 = FUN_80284b6c((uint)DAT_803de37d * 0xf4);
    if ((DAT_803de344 != 0) &&
       (DAT_803de340 = FUN_80284b6c((uint)DAT_803de37d << 6), DAT_803de340 != 0)) {
      FUN_802419b8(DAT_803de340,(uint)DAT_803de37d << 6);
      iVar8 = 0;
      iVar4 = DAT_803de340;
      for (uVar7 = 0; uVar7 < DAT_803de37d; uVar7 = uVar7 + 1) {
        *(undefined *)(DAT_803de344 + iVar8 + 0xec) = 0;
        *(undefined *)(DAT_803de344 + iVar8 + 0xed) = 0;
        *(undefined *)(DAT_803de344 + iVar8 + 0xee) = 0;
        *(undefined *)(DAT_803de344 + iVar8 + 0xe4) = 0xff;
        *(undefined *)(DAT_803de344 + iVar8 + 0xe5) = 0xff;
        *(undefined *)(DAT_803de344 + iVar8 + 0xe6) = 0xff;
        *(undefined *)(DAT_803de344 + iVar8 + 0xe7) = 0xff;
        uVar2 = FUN_80284b6c(0xbc);
        *(undefined4 *)(DAT_803de344 + iVar8) = uVar2;
        FUN_800033a8(*(undefined4 *)(DAT_803de344 + iVar8),0,0xbc);
        uVar2 = FUN_80284b6c(0x80);
        *(undefined4 *)(DAT_803de344 + iVar8 + 4) = uVar2;
        *(short *)(*(int *)(DAT_803de344 + iVar8) + 4) =
             (short)((uint)*(int *)(DAT_803de344 + iVar8) >> 0x10);
        *(short *)(*(int *)(DAT_803de344 + iVar8) + 6) = (short)*(int *)(DAT_803de344 + iVar8);
        *(short *)(*(int *)(DAT_803de344 + iVar8) + 0x4e) =
             (short)((uint)((int *)(DAT_803de344 + iVar8))[1] >> 0x10);
        *(short *)(*(int *)(DAT_803de344 + iVar8) + 0x50) =
             (short)((int *)(DAT_803de344 + iVar8))[1];
        *(short *)(*(int *)(DAT_803de344 + iVar8) + 0x38) = (short)((uint)iVar4 >> 0x10);
        *(short *)(*(int *)(DAT_803de344 + iVar8) + 0x3a) = (short)iVar4;
        *(int *)(DAT_803de344 + iVar8 + 8) = iVar4;
        iVar4 = iVar4 + 0x40;
        *(undefined4 *)(DAT_803de344 + iVar8 + 0xe8) = 0xffffffff;
        FUN_80241a80(*(undefined4 *)(DAT_803de344 + iVar8),0xbc);
        iVar6 = iVar8 + 0x28;
        *(undefined4 *)(DAT_803de344 + iVar8 + 0x24) = 0;
        iVar5 = iVar8 + 0x2c;
        iVar3 = iVar8 + 0x30;
        iVar1 = iVar8 + 0x34;
        iVar8 = iVar8 + 0xf4;
        *(undefined4 *)(DAT_803de344 + iVar6) = 0;
        *(undefined4 *)(DAT_803de344 + iVar5) = 0;
        *(undefined4 *)(DAT_803de344 + iVar3) = 0;
        *(undefined4 *)(DAT_803de344 + iVar1) = 0;
      }
      piVar9 = &DAT_803cc1e0;
      uVar7 = 0;
      while( true ) {
        if (DAT_803de37c <= uVar7) {
          FUN_8027bebc(0,1,param_3 != 0);
          DAT_803de338 = FUN_80284b6c(0x100);
          if (DAT_803de338 == 0) {
            return 0;
          }
          FUN_8027bda8();
          return 1;
        }
        *(undefined *)(piVar9 + 0x14) = 0;
        iVar4 = FUN_80284b6c(0x36);
        *piVar9 = iVar4;
        if (iVar4 == 0) {
          return 0;
        }
        iVar4 = FUN_80284b6c(0x3c00);
        piVar9[10] = iVar4;
        if (iVar4 == 0) break;
        FUN_800033a8(piVar9[10],0,0x3c00);
        FUN_80241a50(piVar9[10],0x3c00);
        piVar9[0xb] = piVar9[10] + 0x780;
        piVar9[0xc] = piVar9[0xb] + 0x780;
        piVar9[0xd] = piVar9[0xc] + 0x780;
        piVar9[0xe] = piVar9[0xd] + 0x780;
        piVar9[0xf] = piVar9[0xe] + 0x780;
        piVar9[0x10] = piVar9[0xf] + 0x780;
        piVar9[0x11] = piVar9[0x10] + 0x780;
        FUN_800033a8(*piVar9,0,0x36);
        piVar9[3] = 0;
        piVar9[2] = 0;
        piVar9[1] = 0;
        piVar9[6] = 0;
        piVar9[5] = 0;
        piVar9[4] = 0;
        piVar9[9] = 0;
        piVar9[8] = 0;
        piVar9[7] = 0;
        FUN_80241a50(*piVar9,0x36);
        piVar9 = piVar9 + 0x2f;
        uVar7 = uVar7 + 1;
      }
      return 0;
    }
  }
  return 0;
}

