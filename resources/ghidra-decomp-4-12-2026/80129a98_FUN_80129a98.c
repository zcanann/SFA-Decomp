// Function: FUN_80129a98
// Entry: 80129a98
// Size: 632 bytes

/* WARNING: Removing unreachable block (ram,0x80129cf0) */
/* WARNING: Removing unreachable block (ram,0x80129ce8) */
/* WARNING: Removing unreachable block (ram,0x80129ce0) */
/* WARNING: Removing unreachable block (ram,0x80129cd8) */
/* WARNING: Removing unreachable block (ram,0x80129cd0) */
/* WARNING: Removing unreachable block (ram,0x80129ac8) */
/* WARNING: Removing unreachable block (ram,0x80129ac0) */
/* WARNING: Removing unreachable block (ram,0x80129ab8) */
/* WARNING: Removing unreachable block (ram,0x80129ab0) */
/* WARNING: Removing unreachable block (ram,0x80129aa8) */

void FUN_80129a98(void)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  char cVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  
  FUN_80286834();
  if (DAT_803de3f0 != 0) {
    bVar1 = (byte)DAT_803de3f0;
    FUN_80077318((double)FLOAT_803e2dcc,(double)FLOAT_803e2dd0,DAT_803a9720,0xff,0x100);
    iVar4 = 0xaa;
    dVar7 = DOUBLE_803e2de8;
    dVar8 = DOUBLE_803e2af8;
    dVar9 = DOUBLE_803e2de0;
    dVar10 = DOUBLE_803e2dd8;
    for (cVar5 = '\x02'; -1 < cVar5; cVar5 = cVar5 + -1) {
      uVar3 = (uint)(char)(bVar1 & 0x1f);
      dVar6 = dVar9 * ((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - dVar8);
      uVar2 = 0x5f - ((int)uVar3 >> 2);
      uVar3 = uVar3 * 2 + 0xbb;
      FUN_80077318((double)(float)(dVar10 + dVar6),
                   (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - dVar8),
                   DAT_803a9724,0xffU - iVar4 & 0xff,uVar3);
      FUN_80076998((double)(float)(dVar7 - dVar6),
                   (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - dVar8),
                   DAT_803a9724,0xffU - iVar4 & 0xff,uVar3,0x18,0x34,1);
      bVar1 = (bVar1 & 0x1f) + 3;
      iVar4 = iVar4 + -0x55;
    }
    bVar1 = (byte)DAT_803de3f0 & 0x1f ^ 0x10;
    iVar4 = 0xaa;
    dVar7 = DOUBLE_803e2dd8;
    dVar8 = DOUBLE_803e2de0;
    dVar9 = DOUBLE_803e2af8;
    dVar10 = DOUBLE_803e2de8;
    for (cVar5 = '\x02'; -1 < cVar5; cVar5 = cVar5 + -1) {
      uVar2 = (uint)(char)bVar1;
      dVar6 = dVar8 * ((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - dVar9);
      uVar3 = 0x5f - ((int)uVar2 >> 2);
      uVar2 = uVar2 * 2 + 0xbb;
      FUN_80077318((double)(float)(dVar7 + dVar6),
                   (double)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - dVar9),
                   DAT_803a9724,0xffU - iVar4 & 0xff,uVar2);
      FUN_80076998((double)(float)(dVar10 - dVar6),
                   (double)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - dVar9),
                   DAT_803a9724,0xffU - iVar4 & 0xff,uVar2,0x18,0x34,1);
      bVar1 = bVar1 + 3 & 0x1f;
      iVar4 = iVar4 + -0x55;
    }
  }
  FUN_80286880();
  return;
}

