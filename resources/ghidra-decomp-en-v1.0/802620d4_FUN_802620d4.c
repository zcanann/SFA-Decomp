// Function: FUN_802620d4
// Entry: 802620d4
// Size: 312 bytes

void FUN_802620d4(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  code *pcVar3;
  
  iVar2 = param_1 * 0x110;
  if (param_2 != -3) {
    if (-4 < param_2) {
      if (param_2 == 1) {
        *(code **)(&DAT_803af2bc + iVar2) = FUN_802620d4;
        iVar1 = FUN_802544d0(param_1,0,&LAB_8025e150);
        if (iVar1 == 0) {
          return;
        }
        *(undefined4 *)(&DAT_803af2bc + iVar2) = 0;
        param_2 = FUN_80261cc4(param_1);
      }
      else {
        if ((0 < param_2) || (param_2 < 0)) goto LAB_802621c0;
        iVar1 = (&DAT_803af204)[param_1 * 0x44];
        (&DAT_803af204)[param_1 * 0x44] = iVar1 + 1;
        if (6 < iVar1 + 1) {
          param_2 = FUN_8026140c(&DAT_803af1e0 + param_1 * 0x44);
          goto LAB_802621c0;
        }
        param_2 = FUN_80261cc4(param_1);
      }
      if (-1 < param_2) {
        return;
      }
      goto LAB_802621c0;
    }
    if (param_2 != -5) goto LAB_802621c0;
  }
  FUN_802623f4(param_1,param_2);
LAB_802621c0:
  pcVar3 = *(code **)(&DAT_803af2b0 + iVar2);
  *(undefined4 *)(&DAT_803af2b0 + iVar2) = 0;
  FUN_8025ee80(&DAT_803af1e0 + param_1 * 0x44,param_2);
  (*pcVar3)(param_1,param_2);
  return;
}

