// Function: FUN_8025282c
// Entry: 8025282c
// Size: 196 bytes

int FUN_8025282c(int param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  
  uVar1 = FUN_8024377c();
  uVar2 = FUN_80252544(param_1);
  if ((uVar2 & 0x20) != 0) {
    *(undefined4 *)(&DAT_803ae3c0 + param_1 * 8) = *(undefined4 *)(&DAT_cc006404 + param_1 * 0xc);
    *(undefined4 *)(&DAT_803ae3c4 + param_1 * 8) = *(undefined4 *)(&DAT_cc006408 + param_1 * 0xc);
    *(undefined4 *)(&DAT_803ae3b0 + param_1 * 4) = 1;
  }
  iVar3 = *(int *)(&DAT_803ae3b0 + param_1 * 4);
  *(undefined4 *)(&DAT_803ae3b0 + param_1 * 4) = 0;
  if (iVar3 != 0) {
    *param_2 = *(undefined4 *)(&DAT_803ae3c0 + param_1 * 8);
    param_2[1] = *(undefined4 *)(&DAT_803ae3c4 + param_1 * 8);
  }
  FUN_802437a4(uVar1);
  return iVar3;
}

