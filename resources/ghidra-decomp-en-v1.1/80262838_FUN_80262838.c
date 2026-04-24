// Function: FUN_80262838
// Entry: 80262838
// Size: 312 bytes

void FUN_80262838(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  code *pcVar3;
  
  iVar2 = param_1 * 0x110;
  if (param_2 != -3) {
    if (-4 < param_2) {
      if (param_2 == 1) {
        *(code **)(&DAT_803aff1c + iVar2) = FUN_80262838;
        iVar1 = FUN_80254c34(param_1,0,-0x7fda174c);
        if (iVar1 == 0) {
          return;
        }
        *(undefined4 *)(&DAT_803aff1c + iVar2) = 0;
        param_2 = FUN_80262428(param_1);
      }
      else {
        if ((0 < param_2) || (param_2 < 0)) goto LAB_80262924;
        iVar1 = (&DAT_803afe64)[param_1 * 0x44];
        (&DAT_803afe64)[param_1 * 0x44] = iVar1 + 1;
        if (6 < iVar1 + 1) {
          param_2 = FUN_80261b70((int)(&DAT_803afe40 + param_1 * 0x44));
          goto LAB_80262924;
        }
        param_2 = FUN_80262428(param_1);
      }
      if (-1 < param_2) {
        return;
      }
      goto LAB_80262924;
    }
    if (param_2 != -5) goto LAB_80262924;
  }
  FUN_80262b58(param_1,param_2);
LAB_80262924:
  pcVar3 = *(code **)(&DAT_803aff10 + iVar2);
  *(undefined4 *)(&DAT_803aff10 + iVar2) = 0;
  FUN_8025f5e4(&DAT_803afe40 + param_1 * 0x44,param_2);
  (*pcVar3)(param_1,param_2);
  return;
}

