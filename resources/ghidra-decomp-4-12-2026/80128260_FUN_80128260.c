// Function: FUN_80128260
// Entry: 80128260
// Size: 508 bytes

/* WARNING: Removing unreachable block (ram,0x8012843c) */
/* WARNING: Removing unreachable block (ram,0x80128434) */
/* WARNING: Removing unreachable block (ram,0x8012842c) */
/* WARNING: Removing unreachable block (ram,0x80128424) */
/* WARNING: Removing unreachable block (ram,0x8012841c) */
/* WARNING: Removing unreachable block (ram,0x80128414) */
/* WARNING: Removing unreachable block (ram,0x8012840c) */
/* WARNING: Removing unreachable block (ram,0x801282a0) */
/* WARNING: Removing unreachable block (ram,0x80128298) */
/* WARNING: Removing unreachable block (ram,0x80128290) */
/* WARNING: Removing unreachable block (ram,0x80128288) */
/* WARNING: Removing unreachable block (ram,0x80128280) */
/* WARNING: Removing unreachable block (ram,0x80128278) */
/* WARNING: Removing unreachable block (ram,0x80128270) */

void FUN_80128260(void)

{
  undefined uVar1;
  char cVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  longlong lVar9;
  double dVar10;
  undefined4 uStack_9c;
  undefined4 uStack_94;
  
  uVar1 = FUN_80286840();
  dVar4 = (double)FUN_802945e0();
  dVar4 = (double)(float)((double)FLOAT_803e2b98 * dVar4);
  for (cVar2 = '\n'; -1 < cVar2; cVar2 = cVar2 + -2) {
    iVar3 = (int)(short)((0xf5 - cVar2) - DAT_803de3dc);
    FUN_8011f088((double)FLOAT_803e2d48,(double)FLOAT_803e2b64,DAT_803a972c,iVar3,uVar1,0x200,0);
    FUN_8011f088((double)FLOAT_803e2d4c,(double)FLOAT_803e2b64,DAT_803a972c,iVar3,uVar1,0x200,0);
  }
  dVar6 = (double)FLOAT_803e2d10;
  dVar8 = (double)FLOAT_803e2d54;
  lVar9 = (longlong)(int)-(float)(dVar4 * (double)FLOAT_803e2aec - (double)FLOAT_803e2d50);
  dVar10 = (double)FLOAT_803e2d5c;
  dVar7 = DOUBLE_803e2af8;
  for (cVar2 = '\n'; -1 < cVar2; cVar2 = cVar2 + -10) {
    dVar5 = (double)(float)((double)(float)(dVar4 * (double)(float)(dVar6 - (double)(float)((double)
                                                  CONCAT44(0x43300000,(int)cVar2 ^ 0x80000000) -
                                                  dVar7))) / dVar6);
    iVar3 = (int)(short)((0xff - cVar2) - DAT_803de3dc);
    uStack_9c = (uint)lVar9;
    FUN_8011f088((double)(float)(dVar8 + dVar5),(double)FLOAT_803e2d58,DAT_803a9728,iVar3,uVar1,
                 uStack_9c,0);
    uStack_94 = (uint)lVar9;
    FUN_8011f088((double)(float)(dVar10 - dVar5),(double)FLOAT_803e2d58,DAT_803a9728,iVar3,uVar1,
                 uStack_94,0);
  }
  FUN_8028688c();
  return;
}

