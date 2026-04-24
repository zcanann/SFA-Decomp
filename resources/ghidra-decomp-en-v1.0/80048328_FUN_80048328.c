// Function: FUN_80048328
// Entry: 80048328
// Size: 436 bytes

void FUN_80048328(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int *piVar5;
  undefined8 uVar6;
  undefined auStack1048 [1048];
  
  uVar6 = FUN_802860dc();
  iVar4 = (int)uVar6;
  if ((param_3 == 0) && ((&DAT_8035f208)[iVar4] == 0)) {
    FUN_8028f688(auStack1048,s__s_romlist_zlb_802cc524,(&PTR_s_frontend_802cb940)[iVar4]);
    iVar1 = FUN_800240d8(DAT_803dcc8c);
    iVar2 = FUN_80248b9c(auStack1048,iVar1);
    if (iVar2 != 0) {
      uVar3 = FUN_80023cc8(*(undefined4 *)(iVar1 + 0x34),0x7d7d7d7d,0);
      (&DAT_8035f208)[iVar4] = uVar3;
      DAT_803dcc74 = 1;
      FUN_80248eac(iVar1,(&DAT_8035f208)[iVar4],*(undefined4 *)(iVar1 + 0x34),0,FUN_800425d8,2);
    }
  }
  else {
    if ((&DAT_8035f208)[iVar4] == 0) {
      FUN_8028f688(auStack1048,s__s_romlist_zlb_802cc524,(&PTR_s_frontend_802cb940)[iVar4]);
      iVar1 = FUN_800240d8(DAT_803dcc8c);
      iVar2 = FUN_80248b9c(auStack1048,iVar1);
      if (iVar2 == 0) goto LAB_800484c4;
      uVar3 = FUN_80023cc8(*(undefined4 *)(iVar1 + 0x34),0x7d7d7d7d,0);
      (&DAT_8035f208)[iVar4] = uVar3;
      FUN_80015850(iVar1,(&DAT_8035f208)[iVar4],*(undefined4 *)(iVar1 + 0x34),0);
      FUN_80248c64(iVar1);
      FUN_80024134(DAT_803dcc8c,iVar1);
    }
    piVar5 = (int *)(DAT_8035f45c + (int)((ulonglong)uVar6 >> 0x20));
    if (*piVar5 == -0x5310113) {
      FUN_8004b658((&DAT_8035f208)[iVar4] + 0x10,piVar5[3],param_3,piVar5 + 1);
      FUN_80241a1c(param_3,piVar5[1]);
    }
  }
LAB_800484c4:
  FUN_80286128();
  return;
}

