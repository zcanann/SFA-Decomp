// Function: FUN_8026220c
// Entry: 8026220c
// Size: 416 bytes

undefined4 FUN_8026220c(int param_1,undefined4 param_2,undefined4 param_3,undefined *param_4)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  
  if ((param_1 < 0) || (1 < param_1)) {
    uVar1 = 0xffffff80;
  }
  else if ((DAT_800030e3 & 0x80) == 0) {
    iVar4 = param_1 * 0x110;
    piVar5 = &DAT_803af1e0 + param_1 * 0x44;
    uVar1 = FUN_8024377c();
    if ((&DAT_803af1e4)[param_1 * 0x44] == -1) {
      FUN_802437a4(uVar1);
      uVar1 = 0xffffffff;
    }
    else if ((*piVar5 == 0) && (uVar2 = FUN_802546a0(param_1), (uVar2 & 8) != 0)) {
      FUN_802437a4(uVar1);
      uVar1 = 0xfffffffe;
    }
    else {
      (&DAT_803af1e4)[param_1 * 0x44] = 0xffffffff;
      (&DAT_803af260)[param_1 * 0x44] = param_2;
      *(undefined4 *)(&DAT_803af2a4 + iVar4) = param_3;
      if (param_4 == (undefined *)0x0) {
        param_4 = &DAT_8025de80;
      }
      *(undefined **)(&DAT_803af2b0 + iVar4) = param_4;
      *(undefined4 *)(&DAT_803af2ac + iVar4) = 0;
      if ((*piVar5 == 0) && (iVar3 = FUN_80253c08(param_1,&LAB_8025deb8), iVar3 == 0)) {
        (&DAT_803af1e4)[param_1 * 0x44] = 0xfffffffd;
        FUN_802437a4(uVar1);
        uVar1 = 0xfffffffd;
      }
      else {
        (&DAT_803af204)[param_1 * 0x44] = 0;
        *piVar5 = 1;
        FUN_802538e4(param_1,0);
        FUN_80241044(&DAT_803af2c0 + iVar4);
        *(undefined4 *)(&DAT_803af264 + iVar4) = 0;
        *(undefined4 *)(&DAT_803af268 + iVar4) = 0;
        FUN_802437a4(uVar1);
        *(code **)(&DAT_803af2bc + iVar4) = FUN_802620d4;
        iVar3 = FUN_802544d0(param_1,0,&LAB_8025e150);
        if (iVar3 == 0) {
          uVar1 = 0;
        }
        else {
          *(undefined4 *)(&DAT_803af2bc + iVar4) = 0;
          uVar1 = FUN_80261cc4(param_1);
        }
      }
    }
  }
  else {
    uVar1 = 0xfffffffd;
  }
  return uVar1;
}

