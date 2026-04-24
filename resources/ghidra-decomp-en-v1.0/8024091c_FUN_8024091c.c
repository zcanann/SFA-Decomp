// Function: FUN_8024091c
// Entry: 8024091c
// Size: 640 bytes

/* WARNING: Removing unreachable block (ram,0x80240a8c) */
/* WARNING: Removing unreachable block (ram,0x80240a90) */
/* WARNING: Removing unreachable block (ram,0x80240ad4) */

void FUN_8024091c(void)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  int *piVar5;
  
  uVar1 = DAT_80240c5c;
  if (DAT_80000060 == 0) {
    FUN_80246e04(s_Installing_OSDBIntegrator_8032c484);
    FUN_80003494(&DAT_80000060,&LAB_80240b9c,0x24);
    FUN_80241a50(&DAT_80000060,0x24);
    sync(0);
    FUN_80241ae0(&DAT_80000060,0x24);
  }
  piVar5 = &DAT_8032c448;
  for (uVar4 = 0; (uVar4 & 0xff) < 0xf; uVar4 = uVar4 + 1) {
    if (((DAT_803ddddc == (uint *)0x0) || (*DAT_803ddddc < 2)) ||
       (iVar2 = FUN_80246de8(uVar4), iVar2 == 0)) {
      DAT_80240c5c = uVar1 | uVar4 & 0xff;
      iVar2 = FUN_80246de8(uVar4);
      if (iVar2 == 0) {
        puVar3 = &DAT_80240c4c;
        iVar2 = 1;
        do {
          *puVar3 = 0x60000000;
          puVar3 = puVar3 + 1;
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
      }
      else {
        FUN_80246e04(s_____OSINIT__exception__d_vectore_8032c4d0,uVar4 & 0xff);
        FUN_80003494(&DAT_80240c4c,&DAT_80240bc0,4);
      }
      iVar2 = *piVar5 + -0x80000000;
      FUN_80003494(iVar2,&DAT_80240bf4,0x98);
      FUN_80241a50(iVar2,0x98);
      sync(0);
      FUN_80241ae0(iVar2,0x98);
    }
    else {
      FUN_80246e04(s_____OSINIT__exception__d_command_8032c4a0,uVar4 & 0xff);
    }
    piVar5 = piVar5 + 1;
  }
  DAT_803dddec = &DAT_80003000;
  for (uVar4 = 0; (uVar4 & 0xff) < 0xf; uVar4 = uVar4 + 1) {
    FUN_80240bc4(uVar4,&LAB_80240c90);
  }
  DAT_80240c5c = uVar1;
  FUN_80246e04(s_Exceptions_initialized____8032c500);
  return;
}

