// Function: FUN_80262970
// Entry: 80262970
// Size: 416 bytes

int FUN_80262970(int param_1,undefined4 param_2,undefined4 param_3,undefined *param_4)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  
  if ((param_1 < 0) || (1 < param_1)) {
    iVar1 = -0x80;
  }
  else if ((DAT_800030e3 & 0x80) == 0) {
    iVar1 = param_1 * 0x110;
    piVar4 = &DAT_803afe40 + param_1 * 0x44;
    FUN_80243e74();
    if ((&DAT_803afe44)[param_1 * 0x44] == -1) {
      FUN_80243e9c();
      iVar1 = -1;
    }
    else if ((*piVar4 == 0) && (uVar2 = FUN_80254e04(param_1), (uVar2 & 8) != 0)) {
      FUN_80243e9c();
      iVar1 = -2;
    }
    else {
      (&DAT_803afe44)[param_1 * 0x44] = 0xffffffff;
      (&DAT_803afec0)[param_1 * 0x44] = param_2;
      *(undefined4 *)(&DAT_803aff04 + iVar1) = param_3;
      if (param_4 == (undefined *)0x0) {
        param_4 = &DAT_8025e5e4;
      }
      *(undefined **)(&DAT_803aff10 + iVar1) = param_4;
      *(undefined4 *)(&DAT_803aff0c + iVar1) = 0;
      if ((*piVar4 == 0) && (iVar3 = FUN_8025436c(param_1,&LAB_8025e61c), iVar3 == 0)) {
        (&DAT_803afe44)[param_1 * 0x44] = 0xfffffffd;
        FUN_80243e9c();
        iVar1 = -3;
      }
      else {
        (&DAT_803afe64)[param_1 * 0x44] = 0;
        *piVar4 = 1;
        FUN_80254048(param_1,0);
        FUN_8024173c((int *)(&DAT_803aff20 + iVar1));
        *(undefined4 *)(&DAT_803afec4 + iVar1) = 0;
        *(undefined4 *)(&DAT_803afec8 + iVar1) = 0;
        FUN_80243e9c();
        *(code **)(&DAT_803aff1c + iVar1) = FUN_80262838;
        iVar3 = FUN_80254c34(param_1,0,-0x7fda174c);
        if (iVar3 == 0) {
          iVar1 = 0;
        }
        else {
          *(undefined4 *)(&DAT_803aff1c + iVar1) = 0;
          iVar1 = FUN_80262428(param_1);
        }
      }
    }
  }
  else {
    iVar1 = -3;
  }
  return iVar1;
}

