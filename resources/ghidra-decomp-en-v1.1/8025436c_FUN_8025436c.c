// Function: FUN_8025436c
// Entry: 8025436c
// Size: 268 bytes

undefined4 FUN_8025436c(int param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  byte abStack_24 [16];
  
  iVar1 = param_1 * 0x40;
  iVar2 = FUN_802540c4(param_1);
  if ((iVar2 != 0) && ((&DAT_803af080)[param_1 * 0x10] == 0)) {
    FUN_80254e44(param_1,0,abStack_24);
  }
  FUN_80243e74();
  if ((&DAT_803af080)[param_1 * 0x10] == 0) {
    FUN_80243e9c();
    uVar3 = 0;
  }
  else {
    FUN_80243e74();
    if (((*(uint *)(&DAT_803af06c + iVar1) & 8) == 0) && (iVar2 = FUN_802540c4(param_1), iVar2 != 0)
       ) {
      FUN_80254000(param_1,1,0,0);
      *(undefined4 *)(&DAT_803af068 + iVar1) = param_2;
      FUN_802442c4(0x100000 >> param_1 * 3);
      *(uint *)(&DAT_803af06c + iVar1) = *(uint *)(&DAT_803af06c + iVar1) | 8;
      FUN_80243e9c();
      uVar3 = 1;
    }
    else {
      FUN_80243e9c();
      uVar3 = 0;
    }
    FUN_80243e9c();
  }
  return uVar3;
}

