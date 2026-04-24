// Function: FUN_80252d80
// Entry: 80252d80
// Size: 452 bytes

int FUN_80252d80(uint param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  undefined8 uVar8;
  
  uVar3 = FUN_8024377c();
  piVar6 = (int *)(&DAT_8032e254 + param_1 * 4);
  iVar5 = *piVar6;
  uVar8 = FUN_80246c70();
  iVar1 = param_1 * 8;
  piVar7 = (int *)(&DAT_803ae320 + iVar1);
  uVar4 = (uint)uVar8 - *(uint *)(&DAT_803ae324 + iVar1);
  uVar2 = (int)((ulonglong)uVar8 >> 0x20) -
          ((uint)((uint)uVar8 < *(uint *)(&DAT_803ae324 + iVar1)) + *piVar7);
  if ((DAT_8032e244 & 0x80 >> (param_1 & 0x3f)) == 0) {
    if (((uint)(((DAT_800000f8 >> 2) / 1000) * 0x32 < uVar4) + (uVar2 ^ 0x80000000) < 0x80000001) &&
       (iVar5 != 8)) {
      FUN_802437a4(uVar3);
      return iVar5;
    }
    if ((uint)(((DAT_800000f8 >> 2) / 1000) * 0x4b < uVar4) + (uVar2 ^ 0x80000000) < 0x80000001) {
      *piVar6 = 0x80;
    }
    else {
      *piVar6 = 0x80;
      iVar5 = 0x80;
    }
  }
  else {
    if (iVar5 != 8) {
      uVar8 = FUN_80246c70();
      *(int *)(&DAT_803ae324 + iVar1) = (int)uVar8;
      *piVar7 = (int)((ulonglong)uVar8 >> 0x20);
      FUN_802437a4(uVar3);
      return iVar5;
    }
    *piVar6 = 0x80;
    iVar5 = 0x80;
  }
  uVar8 = FUN_80246c70();
  *(int *)(&DAT_803ae324 + iVar1) = (int)uVar8;
  *piVar7 = (int)((ulonglong)uVar8 >> 0x20);
  FUN_8025297c(param_1,&DAT_803de084,1,piVar6,3,&LAB_80252ae8,0,
               ((DAT_800000f8 >> 2) / 0x1e848) * 0x41 >> 3);
  FUN_802437a4(uVar3);
  return iVar5;
}

