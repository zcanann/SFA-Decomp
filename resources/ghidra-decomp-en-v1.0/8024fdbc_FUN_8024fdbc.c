// Function: FUN_8024fdbc
// Entry: 8024fdbc
// Size: 484 bytes

void FUN_8024fdbc(void)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  longlong lVar9;
  undefined8 uVar10;
  
  lVar9 = 0;
  bVar1 = false;
  uVar7 = 0;
  uVar8 = 0;
LAB_8024ff50:
  do {
    while( true ) {
      if (bVar1) {
        lVar9 = lVar9 + CONCAT44(uVar8,uVar7);
        do {
          uVar10 = FUN_80246c50();
        } while (((uint)((ulonglong)uVar10 >> 0x20) ^ 0x80000000) <
                 (uint)((uint)uVar10 < (uint)lVar9) +
                 ((uint)((ulonglong)lVar9 >> 0x20) ^ 0x80000000));
        return;
      }
      uVar2 = read_volatile_4(DAT_cc006c00);
      write_volatile_4(DAT_cc006c00,uVar2 & 0xffffffdf | 0x20);
      uVar2 = read_volatile_4(DAT_cc006c00);
      write_volatile_4(DAT_cc006c00,uVar2 & 0xfffffffd);
      uVar2 = read_volatile_4(DAT_cc006c00);
      write_volatile_4(DAT_cc006c00,uVar2 & 0xfffffffe | 1);
      iVar3 = read_volatile_4(DAT_cc006c08);
      do {
        iVar4 = read_volatile_4(DAT_cc006c08);
      } while (iVar3 == iVar4);
      uVar10 = FUN_80246c50();
      uVar2 = read_volatile_4(DAT_cc006c00);
      write_volatile_4(DAT_cc006c00,uVar2 & 0xfffffffd | 2);
      uVar2 = read_volatile_4(DAT_cc006c00);
      write_volatile_4(DAT_cc006c00,uVar2 & 0xfffffffe | 1);
      iVar3 = read_volatile_4(DAT_cc006c08);
      do {
        iVar4 = read_volatile_4(DAT_cc006c08);
      } while (iVar3 == iVar4);
      lVar9 = FUN_80246c50();
      uVar6 = (uint)lVar9 - (uint)uVar10;
      uVar2 = read_volatile_4(DAT_cc006c00);
      uVar5 = (int)((ulonglong)lVar9 >> 0x20) -
              ((uint)((uint)lVar9 < (uint)uVar10) + (int)((ulonglong)uVar10 >> 0x20)) ^ 0x80000000;
      write_volatile_4(DAT_cc006c00,uVar2 & 0xfffffffd);
      uVar2 = read_volatile_4(DAT_cc006c00);
      write_volatile_4(DAT_cc006c00,uVar2 & 0xfffffffe);
      if ((uint)(uVar6 < DAT_803ddff4 - DAT_803de014) +
          (DAT_803ddff0 - ((uint)(DAT_803ddff4 < DAT_803de014) + DAT_803de010) ^ 0x80000000) <=
          uVar5) break;
      bVar1 = true;
      uVar7 = DAT_803de004;
      uVar8 = DAT_803de000;
    }
    if ((uint)(uVar6 < DAT_803ddff4 + DAT_803de014) +
        (DAT_803ddff0 + DAT_803de010 + (uint)CARRY4(DAT_803ddff4,DAT_803de014) ^ 0x80000000) <=
        uVar5) {
      if (uVar5 < (uint)(uVar6 < DAT_803ddffc - DAT_803de014) +
                  (DAT_803ddff8 - ((uint)(DAT_803ddffc < DAT_803de014) + DAT_803de010) ^ 0x80000000)
         ) {
        bVar1 = true;
        uVar7 = DAT_803de00c;
        uVar8 = DAT_803de008;
        goto LAB_8024ff50;
      }
    }
    bVar1 = false;
  } while( true );
}

