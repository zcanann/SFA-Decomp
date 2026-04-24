// Function: FUN_80048964
// Entry: 80048964
// Size: 244 bytes

void FUN_80048964(uint param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 int param_5,int param_6,int param_7)

{
  int iVar1;
  undefined4 uVar2;
  
  if (DAT_8035f524 != 0) {
    if ((param_7 == 1) && (param_6 != 0)) {
      iVar1 = DAT_8035f524 + (param_1 & 0xffffff) * 2 + *(int *)(param_6 + param_5 * 4) + 4;
      uVar2 = *(undefined4 *)(iVar1 + 8);
      *param_3 = *(undefined4 *)(iVar1 + 4);
      *param_4 = uVar2;
    }
    else if ((param_7 == 2) && (param_6 != 0)) {
      FUN_80003494(param_6,DAT_8035f524 + (param_1 & 0xffffff) * 2,(param_5 + 1) * 4);
    }
    else {
      iVar1 = DAT_8035f524 + (param_1 & 0xffffff) * 2;
      uVar2 = *(undefined4 *)(iVar1 + 0xc);
      *param_3 = *(undefined4 *)(iVar1 + 8);
      iVar1 = FUN_80291614(&DAT_803db5c4,iVar1,3);
      if (iVar1 == 0) {
        *param_4 = 0xffffffff;
      }
      else {
        *param_4 = uVar2;
      }
    }
  }
  return;
}

