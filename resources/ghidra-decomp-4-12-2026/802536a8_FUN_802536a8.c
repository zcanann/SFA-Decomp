// Function: FUN_802536a8
// Entry: 802536a8
// Size: 312 bytes

int FUN_802536a8(uint param_1,undefined *param_2)

{
  int iVar1;
  undefined *puVar2;
  int iVar3;
  
  FUN_80243e74();
  iVar3 = FUN_802534e4(param_1);
  if ((*(uint *)(&DAT_8032eeac + param_1 * 4) & 0x80) == 0) {
    (*(code *)param_2)(param_1,iVar3);
  }
  else {
    iVar1 = param_1 * 0x10;
    puVar2 = *(undefined **)(&DAT_803aefc0 + iVar1);
    if (puVar2 != param_2) {
      if (puVar2 == (undefined *)0x0) {
        *(undefined **)(&DAT_803aefc0 + iVar1) = param_2;
      }
      else if (*(undefined **)(&DAT_803aefc4 + iVar1) != param_2) {
        if (*(undefined **)(&DAT_803aefc4 + iVar1) == (undefined *)0x0) {
          *(undefined **)(&DAT_803aefc4 + iVar1) = param_2;
        }
        else if (*(undefined **)(&DAT_803aefc8 + iVar1) != param_2) {
          if (*(undefined **)(&DAT_803aefc8 + iVar1) == (undefined *)0x0) {
            *(undefined **)(&DAT_803aefc8 + iVar1) = param_2;
          }
          else if ((*(undefined **)(&DAT_803aefcc + iVar1) != param_2) &&
                  (*(undefined **)(&DAT_803aefcc + iVar1) == (undefined *)0x0)) {
            *(undefined **)(&DAT_803aefcc + iVar1) = param_2;
          }
        }
      }
    }
  }
  FUN_80243e9c();
  return iVar3;
}

