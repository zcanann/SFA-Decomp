// Function: FUN_80271fd0
// Entry: 80271fd0
// Size: 232 bytes

undefined4 FUN_80271fd0(uint param_1,byte param_2,byte param_3)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  
  uVar3 = 0;
  uVar1 = FUN_80279c00(param_1);
  while ((uVar1 != 0xffffffff &&
         (iVar4 = (uVar1 & 0xff) * 0x404, uVar1 == *(uint *)(DAT_803deee8 + iVar4 + 0xf4)))) {
    iVar2 = DAT_803deee8 + iVar4;
    if ((*(uint *)(iVar2 + 0x118) & 2) == 0) {
      FUN_80281a9c(param_2,(byte)uVar1,*(byte *)(iVar2 + 0x122),param_3);
    }
    else {
      FUN_80281a9c(param_2,(byte)uVar1,*(byte *)(iVar2 + 0x20b),param_3);
    }
    uVar3 = 1;
    uVar1 = *(uint *)(DAT_803deee8 + iVar4 + 0xec);
  }
  return uVar3;
}

