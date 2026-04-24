// Function: FUN_8027186c
// Entry: 8027186c
// Size: 232 bytes

undefined4 FUN_8027186c(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  
  uVar4 = 0;
  uVar2 = FUN_8027949c();
  while( true ) {
    if (uVar2 == 0xffffffff) {
      return uVar4;
    }
    uVar1 = uVar2 & 0xff;
    iVar5 = uVar1 * 0x404;
    if (uVar2 != *(uint *)(DAT_803de268 + iVar5 + 0xf4)) break;
    iVar3 = DAT_803de268 + iVar5;
    if ((*(uint *)(iVar3 + 0x118) & 2) == 0) {
      FUN_80281338(param_2,uVar1,*(undefined *)(iVar3 + 0x122),param_3);
    }
    else {
      FUN_80281338(param_2,uVar1,*(undefined *)(iVar3 + 0x20b),param_3);
    }
    uVar4 = 1;
    uVar2 = *(uint *)(DAT_803de268 + iVar5 + 0xec);
  }
  return uVar4;
}

