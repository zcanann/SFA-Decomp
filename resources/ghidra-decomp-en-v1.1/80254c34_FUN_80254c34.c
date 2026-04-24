// Function: FUN_80254c34
// Entry: 80254c34
// Size: 244 bytes

undefined4 FUN_80254c34(int param_1,int param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  
  iVar1 = param_1 * 0x40;
  piVar5 = (int *)(&DAT_803af060 + iVar1);
  FUN_80243e74();
  if ((*(uint *)(&DAT_803af06c + iVar1) & 0x10) == 0) {
    *(uint *)(&DAT_803af06c + iVar1) = *(uint *)(&DAT_803af06c + iVar1) | 0x10;
    *(int *)(&DAT_803af078 + iVar1) = param_2;
    FUN_802538ec(param_1,piVar5);
    FUN_80243e9c();
    uVar3 = 1;
  }
  else {
    if (param_3 != 0) {
      iVar4 = *(int *)(&DAT_803af084 + iVar1);
      piVar2 = piVar5;
      iVar6 = iVar4;
      if (0 < iVar4) {
        do {
          if (piVar2[10] == param_2) {
            FUN_80243e9c();
            return 0;
          }
          piVar2 = piVar2 + 2;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      piVar5[iVar4 * 2 + 0xb] = param_3;
      piVar5[*(int *)(&DAT_803af084 + iVar1) * 2 + 10] = param_2;
      *(int *)(&DAT_803af084 + iVar1) = *(int *)(&DAT_803af084 + iVar1) + 1;
    }
    FUN_80243e9c();
    uVar3 = 0;
  }
  return uVar3;
}

