// Function: FUN_80253d14
// Entry: 80253d14
// Size: 188 bytes

undefined4 FUN_80253d14(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = param_1 * 0x40;
  uVar2 = FUN_8024377c();
  if ((*(uint *)(&DAT_803ae40c + iVar1) & 8) == 0) {
    FUN_802437a4(uVar2);
    uVar2 = 1;
  }
  else if (((*(uint *)(&DAT_803ae40c + iVar1) & 0x10) == 0) ||
          (*(int *)(&DAT_803ae418 + iVar1) != 0)) {
    *(uint *)(&DAT_803ae40c + iVar1) = *(uint *)(&DAT_803ae40c + iVar1) & 0xfffffff7;
    FUN_80243b44(0x500000 >> param_1 * 3);
    FUN_802437a4(uVar2);
    uVar2 = 1;
  }
  else {
    FUN_802437a4(uVar2);
    uVar2 = 0;
  }
  return uVar2;
}

