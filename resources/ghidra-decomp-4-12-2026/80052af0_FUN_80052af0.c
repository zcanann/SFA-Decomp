// Function: FUN_80052af0
// Entry: 80052af0
// Size: 576 bytes

/* WARNING: Removing unreachable block (ram,0x80052d08) */
/* WARNING: Removing unreachable block (ram,0x80052d00) */
/* WARNING: Removing unreachable block (ram,0x80052cf8) */
/* WARNING: Removing unreachable block (ram,0x80052cf0) */
/* WARNING: Removing unreachable block (ram,0x80052ce8) */
/* WARNING: Removing unreachable block (ram,0x80052ce0) */
/* WARNING: Removing unreachable block (ram,0x80052cd8) */
/* WARNING: Removing unreachable block (ram,0x80052cd0) */
/* WARNING: Removing unreachable block (ram,0x80052cc8) */
/* WARNING: Removing unreachable block (ram,0x80052b40) */
/* WARNING: Removing unreachable block (ram,0x80052b38) */
/* WARNING: Removing unreachable block (ram,0x80052b30) */
/* WARNING: Removing unreachable block (ram,0x80052b28) */
/* WARNING: Removing unreachable block (ram,0x80052b20) */
/* WARNING: Removing unreachable block (ram,0x80052b18) */
/* WARNING: Removing unreachable block (ram,0x80052b10) */
/* WARNING: Removing unreachable block (ram,0x80052b08) */
/* WARNING: Removing unreachable block (ram,0x80052b00) */

void FUN_80052af0(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 uVar14;
  
  if (DAT_803dda18 == '\0') {
    FUN_8025898c(1,0);
    FUN_802420b0(0x80378620,0x6640);
    FUN_8025d4a0(-0x7fc879e0,0x6640);
    uVar3 = 0;
    dVar9 = (double)FLOAT_803df7d8;
    dVar10 = (double)FLOAT_803df7dc;
    dVar11 = (double)FLOAT_803df7d4;
    dVar13 = (double)FLOAT_803df7e4;
    dVar12 = DOUBLE_803df7e8;
    do {
      uVar1 = 0x22;
      uVar14 = FUN_80259000(0x98,4,0x22);
      uVar2 = 0;
      dVar8 = (double)(float)((double)(float)((double)(float)(dVar11 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uVar3) - dVar12)) / dVar9) -
                             dVar10);
      dVar5 = (double)(float)((double)(float)((double)(float)(dVar11 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uVar3 + 1) - dVar12)) / dVar9)
                             - dVar10);
      do {
        dVar7 = (double)(float)((double)(float)((double)(float)(dVar11 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uVar2) - dVar12)) / dVar9) -
                               dVar10);
        dVar6 = (double)(float)(dVar7 * dVar7);
        dVar4 = (double)(float)(dVar8 * dVar8 + dVar6);
        if (dVar10 <= dVar4) {
          dVar4 = (double)FLOAT_803df7e0;
        }
        else {
          dVar4 = FUN_80293900((double)(float)(dVar10 - dVar4));
        }
        DAT_cc008000 = (float)dVar8;
        DAT_cc008000 = (float)dVar7;
        DAT_cc008000 = (float)dVar13;
        DAT_cc008000 = (float)dVar8;
        DAT_cc008000 = (float)dVar7;
        DAT_cc008000 = (float)dVar4;
        dVar4 = (double)(float)(dVar5 * dVar5 + dVar6);
        if (dVar10 <= dVar4) {
          dVar4 = (double)FLOAT_803df7e0;
        }
        else {
          dVar4 = FUN_80293900((double)(float)(dVar10 - dVar4));
        }
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = (float)dVar7;
        DAT_cc008000 = (float)dVar13;
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = (float)dVar7;
        DAT_cc008000 = (float)dVar4;
        uVar2 = uVar2 + 1;
      } while (uVar2 < 0x11);
      uVar3 = uVar3 + 1;
    } while (uVar3 < 0x10);
    DAT_803dda1c = FUN_8025d568((int)((ulonglong)uVar14 >> 0x20),(int)uVar14,uVar1);
    DAT_803dda18 = '\x01';
    FUN_8025898c(1,8);
  }
  FUN_8025d63c(&DAT_80378620,DAT_803dda1c);
  return;
}

