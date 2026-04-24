// Function: FUN_800e9d34
// Entry: 800e9d34
// Size: 356 bytes

void FUN_800e9d34(undefined4 param_1,undefined4 param_2,undefined param_3,int param_4)

{
  bool bVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 uVar4;
  undefined extraout_var;
  
  puVar2 = (undefined4 *)FUN_802860dc();
  bVar1 = false;
  if (DAT_803dd49c == 0) {
    DAT_803dd49c = FUN_80023cc8(0x6ec,0xffff00ff,0);
    if (DAT_803dd49c == 0) goto LAB_800e9e80;
  }
  if (param_4 != 0) {
    FUN_800200e8(0x970,1);
    FUN_8002b9ec();
    iVar3 = FUN_80296ae8();
    if (1 < iVar3) {
      uVar4 = FUN_8002b9ec();
      FUN_80296afc(uVar4,0xffffffff);
      bVar1 = true;
    }
  }
  FUN_80003494(DAT_803dd49c,&DAT_803a32a8,0x6ec);
  *(undefined4 *)(DAT_803dd49c + (uint)*(byte *)(DAT_803dd49c + 0x20) * 0x10 + 0x684) = *puVar2;
  *(undefined4 *)(DAT_803dd49c + (uint)*(byte *)(DAT_803dd49c + 0x20) * 0x10 + 0x688) = puVar2[1];
  *(undefined4 *)(DAT_803dd49c + (uint)*(byte *)(DAT_803dd49c + 0x20) * 0x10 + 0x68c) = puVar2[2];
  *(undefined *)(DAT_803dd49c + (uint)*(byte *)(DAT_803dd49c + 0x20) * 0x10 + 0x690) = extraout_var;
  *(undefined *)(DAT_803dd49c + (uint)DAT_803a32c8 * 0x10 + 0x691) = param_3;
  FUN_800200e8(0x970,0);
  if ((param_4 != 0) && (bVar1)) {
    uVar4 = FUN_8002b9ec();
    FUN_80296afc(uVar4,1);
  }
LAB_800e9e80:
  FUN_80286128();
  return;
}

