// Function: FUN_80253c08
// Entry: 80253c08
// Size: 268 bytes

undefined4 FUN_80253c08(int param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined auStack36 [16];
  
  iVar1 = param_1 * 0x40;
  iVar2 = FUN_80253960(param_1);
  if ((iVar2 != 0) && ((&DAT_803ae420)[param_1 * 0x10] == 0)) {
    FUN_802546e0(param_1,0,auStack36);
  }
  uVar3 = FUN_8024377c();
  if ((&DAT_803ae420)[param_1 * 0x10] == 0) {
    FUN_802437a4(uVar3);
    uVar4 = 0;
  }
  else {
    uVar4 = FUN_8024377c();
    if (((*(uint *)(&DAT_803ae40c + iVar1) & 8) == 0) && (iVar2 = FUN_80253960(param_1), iVar2 != 0)
       ) {
      FUN_8025389c(param_1,1,0,0);
      *(undefined4 *)(&DAT_803ae408 + iVar1) = param_2;
      FUN_80243bcc(0x100000 >> param_1 * 3);
      *(uint *)(&DAT_803ae40c + iVar1) = *(uint *)(&DAT_803ae40c + iVar1) | 8;
      FUN_802437a4(uVar4);
      uVar4 = 1;
    }
    else {
      FUN_802437a4(uVar4);
      uVar4 = 0;
    }
    FUN_802437a4(uVar3);
  }
  return uVar4;
}

