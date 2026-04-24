// Function: FUN_80254d28
// Entry: 80254d28
// Size: 220 bytes

undefined4 FUN_80254d28(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  code *pcVar4;
  
  iVar1 = param_1 * 0x40;
  FUN_80243e74();
  if ((*(uint *)(&DAT_803af06c + iVar1) & 0x10) == 0) {
    FUN_80243e9c();
    uVar3 = 0;
  }
  else {
    *(uint *)(&DAT_803af06c + iVar1) = *(uint *)(&DAT_803af06c + iVar1) & 0xffffffef;
    FUN_802538ec(param_1,(int *)(&DAT_803af060 + iVar1));
    if (0 < *(int *)(&DAT_803af084 + iVar1)) {
      iVar2 = *(int *)(&DAT_803af084 + iVar1) + -1;
      pcVar4 = *(code **)(&DAT_803af08c + iVar1);
      *(int *)(&DAT_803af084 + iVar1) = iVar2;
      if (0 < iVar2) {
        FUN_8028fa2c((uint)(&DAT_803af088 + iVar1),(uint)(&DAT_803af090 + iVar1),
                     *(int *)(&DAT_803af084 + iVar1) << 3);
      }
      (*pcVar4)(param_1,0);
    }
    FUN_80243e9c();
    uVar3 = 1;
  }
  return uVar3;
}

