// Function: FUN_80254478
// Entry: 80254478
// Size: 188 bytes

undefined4 FUN_80254478(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = param_1 * 0x40;
  FUN_80243e74();
  if ((*(uint *)(&DAT_803af06c + iVar1) & 8) == 0) {
    FUN_80243e9c();
    uVar2 = 1;
  }
  else if (((*(uint *)(&DAT_803af06c + iVar1) & 0x10) == 0) ||
          (*(int *)(&DAT_803af078 + iVar1) != 0)) {
    *(uint *)(&DAT_803af06c + iVar1) = *(uint *)(&DAT_803af06c + iVar1) & 0xfffffff7;
    FUN_8024423c(0x500000 >> param_1 * 3);
    FUN_80243e9c();
    uVar2 = 1;
  }
  else {
    FUN_80243e9c();
    uVar2 = 0;
  }
  return uVar2;
}

