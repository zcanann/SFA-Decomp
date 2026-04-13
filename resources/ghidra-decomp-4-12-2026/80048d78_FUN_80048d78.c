// Function: FUN_80048d78
// Entry: 80048d78
// Size: 380 bytes

void FUN_80048d78(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  ulonglong uVar6;
  
  uVar6 = FUN_80286840();
  puVar3 = (undefined4 *)uVar6;
  iVar5 = -1;
  if (((DAT_803600e0 == 0) || (DAT_803600dc == 0)) && ((DAT_80360168 == 0 || (DAT_80360164 == 0))))
  {
    *param_3 = 0;
    *puVar3 = 0;
  }
  else {
    FUN_80243e74();
    uVar1 = DAT_803dd900;
    FUN_80243e9c();
    if (((DAT_803600dc == 0) || ((uVar6 & 0x1000000000000000) == 0)) || ((uVar1 & 0x10000) != 0)) {
      if (((DAT_80360164 == 0) || ((uVar6 & 0x2000000000000000) == 0)) || ((uVar1 & 0x40000) != 0))
      {
        if ((DAT_803600dc == 0) || ((uVar1 & 0x10000) != 0)) {
          if ((DAT_80360164 != 0) && ((uVar1 & 0x40000) == 0)) {
            iVar5 = 0x47;
          }
        }
        else {
          iVar5 = 0x25;
        }
      }
      else {
        iVar5 = 0x47;
      }
    }
    else {
      iVar5 = 0x25;
    }
    iVar4 = (&DAT_80360048)[iVar5] + ((uint)(uVar6 >> 0x20) & 0xffffff);
    iVar5 = FUN_80291d74(iVar4,-0x7fc23de0,3);
    if (iVar5 == 0) {
      uVar2 = *(undefined4 *)(iVar4 + 0xc);
      *param_3 = *(undefined4 *)(iVar4 + 8);
      *puVar3 = uVar2;
    }
    else {
      *param_3 = 0;
      *puVar3 = 0;
    }
  }
  FUN_8028688c();
  return;
}

