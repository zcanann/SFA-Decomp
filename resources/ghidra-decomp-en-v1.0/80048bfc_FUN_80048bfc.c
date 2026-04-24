// Function: FUN_80048bfc
// Entry: 80048bfc
// Size: 380 bytes

void FUN_80048bfc(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

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
  if (((DAT_8035f480 == 0) || (DAT_8035f47c == 0)) && ((DAT_8035f508 == 0 || (DAT_8035f504 == 0))))
  {
    *param_3 = 0;
    *puVar3 = 0;
  }
  else {
    FUN_8024377c();
    uVar1 = DAT_803dcc80;
    FUN_802437a4();
    if (((DAT_8035f47c == 0) || ((uVar6 & 0x1000000000000000) == 0)) || ((uVar1 & 0x10000) != 0)) {
      if (((DAT_8035f504 == 0) || ((uVar6 & 0x2000000000000000) == 0)) || ((uVar1 & 0x40000) != 0))
      {
        if ((DAT_8035f47c == 0) || ((uVar1 & 0x10000) != 0)) {
          if ((DAT_8035f504 != 0) && ((uVar1 & 0x40000) == 0)) {
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
  FUN_80286128();
  return;
}

