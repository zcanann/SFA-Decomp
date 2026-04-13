// Function: FUN_8028b1f0
// Entry: 8028b1f0
// Size: 420 bytes

int FUN_8028b1f0(int param_1,int *param_2,uint param_3,int param_4,int param_5)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint unaff_r29;
  undefined *unaff_r30;
  int iVar4;
  char local_38;
  byte local_37 [19];
  
  iVar3 = param_4 + 1;
  iVar4 = 0;
  bVar1 = true;
  *param_2 = -1;
LAB_8028b350:
  if (((iVar3 == 0) || (*param_2 != -1)) || (iVar4 != 0)) {
    if (*param_2 == -1) {
      iVar4 = 0x800;
    }
    return iVar4;
  }
  iVar4 = FUN_80287460(param_1);
  if (iVar4 == 0) {
    if (param_5 != 0) {
      unaff_r29 = 0;
    }
LAB_8028b244:
    iVar2 = FUN_8028817c();
    *param_2 = iVar2;
    iVar2 = *param_2;
    if (iVar2 == -1) goto code_r0x8028b258;
    goto LAB_8028b274;
  }
  goto LAB_8028b34c;
code_r0x8028b258:
  if ((param_5 == 0) || (unaff_r29 = unaff_r29 + 1, unaff_r29 < 0x4c4b3ec)) goto LAB_8028b244;
LAB_8028b274:
  if (iVar2 != -1) {
    bVar1 = false;
    unaff_r30 = FUN_80287f00(iVar2);
    FUN_80287e2c((int)unaff_r30,0);
    iVar4 = FUN_80287a2c((int)unaff_r30,(int)local_37);
    if ((iVar4 != 0) || (0x7f < local_37[0])) goto LAB_8028b2c4;
    FUN_80288094(*param_2);
    *param_2 = -1;
    goto LAB_8028b244;
  }
LAB_8028b2c4:
  if (*param_2 != -1) {
    if (*(uint *)(unaff_r30 + 8) < param_3) {
      bVar1 = true;
    }
    if ((iVar4 == 0) && (!bVar1)) {
      iVar4 = FUN_80287a2c((int)unaff_r30,(int)&local_38);
    }
    if (((iVar4 == 0) && (!bVar1)) && ((local_37[0] != 0x80 || (local_38 != '\0')))) {
      bVar1 = true;
    }
    if ((iVar4 != 0) || (bVar1)) {
      FUN_80287e9c(*param_2);
      *param_2 = -1;
    }
  }
LAB_8028b34c:
  iVar3 = iVar3 + -1;
  goto LAB_8028b350;
}

