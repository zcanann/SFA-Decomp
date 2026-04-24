// Function: FUN_80241014
// Entry: 80241014
// Size: 640 bytes

/* WARNING: Removing unreachable block (ram,0x80241184) */
/* WARNING: Removing unreachable block (ram,0x80241188) */
/* WARNING: Removing unreachable block (ram,0x802411cc) */

void FUN_80241014(void)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  
  uVar1 = DAT_80241354;
  if (DAT_80000060 == 0) {
    FUN_80247568();
    FUN_80003494(0x80000060,0x80241294,0x24);
    FUN_80242148(0x80000060,0x24);
    sync(0);
    FUN_802421d8(0x80000060,0x24);
  }
  piVar5 = &DAT_8032d0a0;
  for (uVar4 = 0; (uVar4 & 0xff) < 0xf; uVar4 = uVar4 + 1) {
    if (((DAT_803dea5c == (uint *)0x0) || (*DAT_803dea5c < 2)) ||
       (uVar2 = FUN_8024754c(uVar4), uVar2 == 0)) {
      DAT_80241354 = uVar1 | uVar4 & 0xff;
      uVar2 = FUN_8024754c(uVar4);
      if (uVar2 == 0) {
        puVar3 = &DAT_80241344;
        iVar6 = 1;
        do {
          *puVar3 = 0x60000000;
          puVar3 = puVar3 + 1;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      else {
        FUN_80247568();
        FUN_80003494(0x80241344,0x802412b8,4);
      }
      uVar2 = *piVar5 + 0x80000000;
      FUN_80003494(uVar2,0x802412ec,0x98);
      FUN_80242148(uVar2,0x98);
      sync(0);
      FUN_802421d8(uVar2,0x98);
    }
    else {
      FUN_80247568();
    }
    piVar5 = piVar5 + 1;
  }
  DAT_803dea6c = &DAT_80003000;
  for (uVar4 = 0; (uVar4 & 0xff) < 0xf; uVar4 = uVar4 + 1) {
    FUN_802412bc(uVar4,&LAB_80241388);
  }
  DAT_80241354 = uVar1;
  FUN_80247568();
  return;
}

