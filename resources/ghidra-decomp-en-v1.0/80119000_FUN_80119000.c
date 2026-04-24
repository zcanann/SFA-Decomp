// Function: FUN_80119000
// Entry: 80119000
// Size: 748 bytes

/* WARNING: Removing unreachable block (ram,0x801191cc) */

void FUN_80119000(void)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined *puVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_802860cc();
  if (DAT_803dd660 == 0) {
    uVar1 = 0;
  }
  else if (DAT_803a5df8 == 0) {
    FUN_800033a8(&DAT_803a5de0,0,8);
    FUN_800033a8(&DAT_803a5de8,0,0xc);
    iVar2 = FUN_80248b9c((int)((ulonglong)uVar6 >> 0x20),&DAT_803a5d60);
    if (iVar2 == 0) {
      uVar1 = 0;
    }
    else {
      iVar2 = FUN_80015850(&DAT_803a5d60,&DAT_803a5d20,0x40,0);
      if (iVar2 < 0) {
        FUN_80248c64(&DAT_803a5d60);
        uVar1 = 0;
      }
      else {
        FUN_80003494(&DAT_803a5d9c,&DAT_803a5d20,0x30);
        iVar3 = FUN_80291654(&DAT_803a5d9c,&DAT_803db9e8);
        iVar2 = DAT_803a5dbc;
        if (iVar3 == 0) {
          if (DAT_803a5da0 == 0x10000) {
            iVar3 = FUN_80015850(&DAT_803a5d60,&DAT_803a5d20,0x20,DAT_803a5dbc);
            if (iVar3 < 0) {
              FUN_80248c64(&DAT_803a5d60);
              uVar1 = 0;
            }
            else {
              FUN_80003494(&DAT_803a5dcc,&DAT_803a5d20,0x14);
              iVar2 = iVar2 + 0x14;
              puVar5 = &DAT_803a5d60;
              DAT_803a5dff = 0;
              for (uVar4 = 0; uVar4 < DAT_803a5dcc; uVar4 = uVar4 + 1) {
                if (puVar5[0x70] == '\x01') {
                  iVar3 = FUN_80015850(&DAT_803a5d60,&DAT_803a5d20,0x20,iVar2);
                  if (iVar3 < 0) {
                    FUN_80248c64(&DAT_803a5d60);
                    uVar1 = 0;
                    goto LAB_801192d4;
                  }
                  FUN_80003494(&DAT_803a5de8,&DAT_803a5d20,0xc);
                  DAT_803a5dff = 1;
                  iVar2 = iVar2 + 0xc;
                }
                else {
                  if (puVar5[0x70] != '\0') {
                    uVar1 = 0;
                    goto LAB_801192d4;
                  }
                  iVar3 = FUN_80015850(&DAT_803a5d60,&DAT_803a5d20,0x20,iVar2);
                  if (iVar3 < 0) {
                    FUN_80248c64(&DAT_803a5d60);
                    uVar1 = 0;
                    goto LAB_801192d4;
                  }
                  FUN_80003494(&DAT_803a5de0,&DAT_803a5d20,8);
                  iVar2 = iVar2 + 8;
                }
                puVar5 = puVar5 + 1;
              }
              DAT_803a5dfd = 0;
              DAT_803a5dfc = 0;
              DAT_803a5dfe = 0;
              DAT_803a5df8 = 1;
              DAT_803a5e34 = FLOAT_803e1d54;
              DAT_803a5e38 = FLOAT_803e1d54;
              DAT_803a5e40 = 0;
              uVar1 = 1;
              DAT_803a5e08 = (int)uVar6;
            }
          }
          else {
            FUN_80248c64();
            uVar1 = 0;
          }
        }
        else {
          FUN_80248c64(&DAT_803a5d60);
          uVar1 = 0;
        }
      }
    }
  }
  else {
    uVar1 = 0;
  }
LAB_801192d4:
  FUN_80286118(uVar1);
  return;
}

