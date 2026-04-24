// Function: FUN_8028aa8c
// Entry: 8028aa8c
// Size: 420 bytes

int FUN_8028aa8c(undefined4 param_1,int *param_2,uint param_3,int param_4,int param_5)

{
  bool bVar1;
  int iVar2;
  uint unaff_r29;
  int unaff_r30;
  int iVar3;
  char local_38;
  byte local_37 [19];
  
  param_4 = param_4 + 1;
  iVar3 = 0;
  bVar1 = true;
  *param_2 = -1;
LAB_8028abec:
  if (((param_4 == 0) || (*param_2 != -1)) || (iVar3 != 0)) {
    if (*param_2 == -1) {
      iVar3 = 0x800;
    }
    return iVar3;
  }
  iVar3 = FUN_80286cfc(param_1);
  if (iVar3 == 0) {
    if (param_5 != 0) {
      unaff_r29 = 0;
    }
LAB_8028aae0:
    iVar2 = FUN_80287a18();
    *param_2 = iVar2;
    if (*param_2 == -1) goto code_r0x8028aaf4;
    goto LAB_8028ab10;
  }
  goto LAB_8028abe8;
code_r0x8028aaf4:
  if (param_5 == 0) goto LAB_8028aae0;
  unaff_r29 = unaff_r29 + 1;
  if (unaff_r29 < 0x4c4b3ec) goto LAB_8028aae0;
LAB_8028ab10:
  if (*param_2 != -1) {
    bVar1 = false;
    unaff_r30 = FUN_8028779c();
    FUN_802876c8(unaff_r30,0);
    iVar3 = FUN_802872c8(unaff_r30,local_37);
    if ((iVar3 != 0) || (0x7f < local_37[0])) goto LAB_8028ab60;
    FUN_80287930(*param_2);
    *param_2 = -1;
    goto LAB_8028aae0;
  }
LAB_8028ab60:
  if (*param_2 != -1) {
    if (*(uint *)(unaff_r30 + 8) < param_3) {
      bVar1 = true;
    }
    if ((iVar3 == 0) && (!bVar1)) {
      iVar3 = FUN_802872c8(unaff_r30,&local_38);
    }
    if (((iVar3 == 0) && (!bVar1)) && ((local_37[0] != 0x80 || (local_38 != '\0')))) {
      bVar1 = true;
    }
    if ((iVar3 != 0) || (bVar1)) {
      FUN_80287738(*param_2);
      *param_2 = -1;
    }
  }
LAB_8028abe8:
  param_4 = param_4 + -1;
  goto LAB_8028abec;
}

