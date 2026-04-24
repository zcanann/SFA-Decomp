// Function: FUN_8005bc3c
// Entry: 8005bc3c
// Size: 456 bytes

void FUN_8005bc3c(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  uint *puVar8;
  
  iVar2 = FUN_8028683c();
  iVar3 = FUN_8002e1f4((undefined4 *)0x0,(undefined4 *)0x0);
  puVar8 = &DAT_8038753c;
  for (iVar7 = 1; iVar7 < DAT_803ddb2e; iVar7 = iVar7 + 1) {
    iVar6 = *(int *)(iVar3 + (*puVar8 & 0x3ff) * 4);
    uVar4 = *(uint *)(*(int *)(iVar6 + 0x50) + 0x44);
    if (((uVar4 & 0x800) == 0) && ((*(byte *)(*(int *)(iVar6 + 0x50) + 0x5f) & 0x10) == 0)) {
      if ((uVar4 & 0x800000) == 0) {
        (**(code **)(*DAT_803dd6fc + 0x1c))(0,0,0,1,iVar6);
      }
      FUN_8003ba50(0,0,0,0,iVar6,1);
      iVar5 = *(int *)(iVar6 + 100);
      if ((iVar5 == 0) || (*(int *)(iVar5 + 0xc) == 0)) {
        if ((*(short *)(*(int *)(iVar6 + 0x50) + 0x48) == 3) &&
           (((*(ushort *)(iVar6 + 6) & 0x4000) == 0 && ((*(uint *)(iVar5 + 0x30) & 4) != 0)))) {
          FUN_8005d2cc(iVar6,0x13,0);
          (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 3;
          DAT_803ddab0 = DAT_803ddab0 + 1;
        }
      }
      else {
        FUN_8005d2cc(iVar6,0x13,0);
        (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 2;
        DAT_803ddab0 = DAT_803ddab0 + 1;
      }
    }
    else if ((*(char *)(iVar2 + (*puVar8 & 0x3ff)) != '\0') && (DAT_803dda70 < 0x14)) {
      piVar1 = &DAT_80382e34 + DAT_803dda70;
      DAT_803dda70 = DAT_803dda70 + 1;
      *piVar1 = iVar6;
    }
    puVar8 = puVar8 + 1;
  }
  FUN_80286888();
  return;
}

