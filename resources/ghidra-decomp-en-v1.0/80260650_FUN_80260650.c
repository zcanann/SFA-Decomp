// Function: FUN_80260650
// Entry: 80260650
// Size: 280 bytes

undefined4 FUN_80260650(int param_1,uint param_2)

{
  undefined4 uVar1;
  int iVar2;
  short *psVar3;
  int iVar4;
  ushort uVar5;
  ushort uVar6;
  ushort uVar7;
  uint uVar8;
  ushort unaff_r31;
  
  iVar2 = param_1 * 0x110;
  if ((&DAT_803af1e0)[param_1 * 0x44] == 0) {
    uVar1 = 0xfffffffd;
  }
  else {
    iVar4 = *(int *)(&DAT_803af268 + iVar2);
    if (*(ushort *)(iVar4 + 6) < param_2) {
      uVar1 = 0xfffffff7;
    }
    else {
      *(ushort *)(iVar4 + 6) = *(ushort *)(iVar4 + 6) - (short)param_2;
      uVar5 = *(ushort *)(iVar4 + 8);
      uVar8 = 0;
      uVar7 = 0xffff;
      while (param_2 != 0) {
        uVar8 = uVar8 + 1;
        if ((int)(*(ushort *)(&DAT_803af1f0 + iVar2) - 5) < (int)(uVar8 & 0xffff)) {
          return 0xfffffffa;
        }
        uVar5 = uVar5 + 1;
        if ((uVar5 < 5) || ((uint)*(ushort *)(&DAT_803af1f0 + iVar2) <= (uint)uVar5)) {
          uVar5 = 5;
        }
        psVar3 = (short *)(iVar4 + (uint)uVar5 * 2);
        if (*psVar3 == 0) {
          uVar6 = uVar5;
          if (uVar7 != 0xffff) {
            *(ushort *)(iVar4 + (uint)unaff_r31 * 2) = uVar5;
            uVar6 = uVar7;
          }
          *psVar3 = -1;
          param_2 = param_2 - 1;
          unaff_r31 = uVar5;
          uVar7 = uVar6;
        }
      }
      *(ushort *)(iVar4 + 8) = uVar5;
      *(ushort *)(&DAT_803af29e + iVar2) = uVar7;
      uVar1 = FUN_80260804(param_1,iVar4);
    }
  }
  return uVar1;
}

