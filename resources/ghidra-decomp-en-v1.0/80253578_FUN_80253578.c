// Function: FUN_80253578
// Entry: 80253578
// Size: 236 bytes

undefined4 FUN_80253578(int param_1,uint param_2,undefined4 param_3,int param_4,undefined4 param_5)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = param_1 * 0x40;
  uVar2 = FUN_8024377c();
  if (((*(uint *)(&DAT_803ae40c + iVar1) & 3) == 0) && ((*(uint *)(&DAT_803ae40c + iVar1) & 4) != 0)
     ) {
    *(undefined4 *)(&DAT_803ae404 + iVar1) = param_5;
    if (*(int *)(&DAT_803ae404 + iVar1) != 0) {
      FUN_8025389c(param_1,0,1,0);
      FUN_80243bcc(0x200000 >> param_1 * 3);
    }
    param_1 = param_1 * 0x14;
    *(uint *)(&DAT_803ae40c + iVar1) = *(uint *)(&DAT_803ae40c + iVar1) | 1;
    *(uint *)(&DAT_cc006804 + param_1) = param_2 & 0x3ffffe0;
    *(undefined4 *)(&DAT_cc006808 + param_1) = param_3;
    *(uint *)(&DAT_cc00680c + param_1) = param_4 << 2 | 3;
    FUN_802437a4(uVar2);
    uVar2 = 1;
  }
  else {
    FUN_802437a4(uVar2);
    uVar2 = 0;
  }
  return uVar2;
}

