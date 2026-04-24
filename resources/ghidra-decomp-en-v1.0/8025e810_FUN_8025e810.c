// Function: FUN_8025e810
// Entry: 8025e810
// Size: 436 bytes

undefined4 FUN_8025e810(int param_1,int param_2,int param_3)

{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;
  
  uVar2 = FUN_8024377c();
  iVar5 = param_1 * 0x110;
  if ((&DAT_803af1e0)[param_1 * 0x44] == 0) {
    uVar7 = 0xfffffffd;
    goto LAB_8025e9a4;
  }
  if (param_2 != 0) {
    *(int *)(&DAT_803af2a8 + iVar5) = param_2;
  }
  if (param_3 != 0) {
    *(int *)(&DAT_803af2ac + iVar5) = param_3;
  }
  *(undefined **)(&DAT_803af2bc + iVar5) = &LAB_8025e700;
  iVar3 = FUN_802544d0(param_1,0,&LAB_8025e150);
  if (iVar3 == 0) {
    uVar7 = 0xffffffff;
    goto LAB_8025e9a4;
  }
  *(undefined4 *)(&DAT_803af2bc + iVar5) = 0;
  iVar3 = FUN_80253dd0(param_1,0,4);
  if (iVar3 == 0) {
    FUN_802545c4(param_1);
    uVar7 = 0xfffffffd;
    goto LAB_8025e9a4;
  }
  FUN_80241044(&DAT_803af2c0 + iVar5);
  bVar1 = (&DAT_803af274)[iVar5];
  if (bVar1 != 0xf3) {
    if (bVar1 < 0xf3) {
      if (bVar1 == 0xf1) {
LAB_8025e93c:
        uVar4 = *(uint *)(&DAT_803af1ec + iVar5);
        uVar6 = (DAT_800000f8 >> 2) * 2;
        uVar4 = ((int)uVar4 >> 0xd) + (uint)((int)uVar4 < 0 && (uVar4 & 0x1fff) != 0);
        iVar3 = ((int)uVar4 >> 0x1f) * uVar6 + (int)((ulonglong)uVar4 * (ulonglong)uVar6 >> 0x20);
        FUN_80240fdc(&DAT_803af2c0 + iVar5,iVar3,iVar3,uVar4 * uVar6,&LAB_8025e430);
      }
      else if (0xf0 < bVar1) {
        FUN_80240fdc(&DAT_803af2c0 + iVar5,0x10624dd3,0,((DAT_800000f8 >> 2) / 1000) * 100,
                     &LAB_8025e430);
      }
    }
    else if (bVar1 < 0xf5) goto LAB_8025e93c;
  }
  uVar7 = 0;
LAB_8025e9a4:
  FUN_802437a4(uVar2);
  return uVar7;
}

