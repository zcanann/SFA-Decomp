// Function: FUN_80048d78
// Entry: 80048d78
// Size: 408 bytes

void FUN_80048d78(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  ulonglong uVar6;
  
  uVar6 = FUN_802860dc();
  puVar3 = (undefined4 *)uVar6;
  iVar5 = -1;
  if (((DAT_8035f450 == 0) || (DAT_8035f454 == 0)) && ((DAT_8035f534 == 0 || (DAT_8035f538 == 0))))
  {
    *param_3 = 0;
    *puVar3 = 0;
  }
  else {
    FUN_8024377c();
    uVar1 = DAT_803dcc80;
    FUN_802437a4();
    if (((DAT_8035f454 == 0) || ((uVar6 & 0x8000000000000000) == 0)) || ((uVar1 & 0x1000000) != 0))
    {
      if (((DAT_8035f538 == 0) || ((uVar6 & 0x2000000000000000) == 0)) || ((uVar1 & 0x4000000) != 0)
         ) {
        if ((DAT_8035f454 == 0) || ((uVar1 & 0x1000000) != 0)) {
          if ((DAT_8035f538 != 0) && ((uVar1 & 0x4000000) == 0)) {
            iVar5 = 0x54;
          }
        }
        else {
          iVar5 = 0x1b;
        }
      }
      else {
        iVar5 = 0x54;
      }
    }
    else {
      iVar5 = 0x1b;
    }
    if ((uVar6 & 0xf000000000000000) == 0) {
      *param_3 = 0;
      *puVar3 = 0;
    }
    else {
      iVar4 = (&DAT_8035f3e8)[iVar5] + ((uint)(uVar6 >> 0x20) & 0xffffff);
      iVar5 = FUN_80291614(iVar4,&DAT_803db5c0,3);
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
  }
  FUN_80286128();
  return;
}

