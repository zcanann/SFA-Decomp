// Function: FUN_80127f24
// Entry: 80127f24
// Size: 508 bytes

/* WARNING: Removing unreachable block (ram,0x801280f8) */
/* WARNING: Removing unreachable block (ram,0x801280e8) */
/* WARNING: Removing unreachable block (ram,0x801280d8) */
/* WARNING: Removing unreachable block (ram,0x801280d0) */
/* WARNING: Removing unreachable block (ram,0x801280e0) */
/* WARNING: Removing unreachable block (ram,0x801280f0) */
/* WARNING: Removing unreachable block (ram,0x80128100) */

void FUN_80127f24(void)

{
  undefined uVar1;
  char cVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f25;
  double dVar6;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar7;
  undefined8 in_f28;
  double dVar8;
  undefined8 in_f29;
  double dVar9;
  undefined8 in_f30;
  longlong lVar10;
  undefined8 in_f31;
  double dVar11;
  undefined4 uStack156;
  undefined4 uStack148;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  uVar1 = FUN_802860dc();
  dVar5 = (double)FUN_80293e80((double)((FLOAT_803e1ec8 * FLOAT_803dd748 * FLOAT_803e201c) /
                                       FLOAT_803e1e94));
  dVar5 = (double)(float)((double)FLOAT_803e1f18 * dVar5);
  for (cVar2 = '\n'; -1 < cVar2; cVar2 = cVar2 + -2) {
    iVar3 = (int)(short)((0xf5 - cVar2) - DAT_803dd75c);
    FUN_8011eda4((double)FLOAT_803e20bc,(double)FLOAT_803e1ee4,DAT_803a8acc,iVar3,uVar1,0x200,0);
    FUN_8011eda4((double)FLOAT_803e20c0,(double)FLOAT_803e1ee4,DAT_803a8acc,iVar3,uVar1,0x200,0);
  }
  dVar7 = (double)FLOAT_803e2090;
  dVar9 = (double)FLOAT_803e20c8;
  lVar10 = (longlong)(int)-(float)(dVar5 * (double)FLOAT_803e1e6c - (double)FLOAT_803e20c4);
  dVar11 = (double)FLOAT_803e20d0;
  dVar8 = DOUBLE_803e1e78;
  for (cVar2 = '\n'; -1 < cVar2; cVar2 = cVar2 + -10) {
    dVar6 = (double)(float)((double)(float)(dVar5 * (double)(float)(dVar7 - (double)(float)((double)
                                                  CONCAT44(0x43300000,(int)cVar2 ^ 0x80000000) -
                                                  dVar8))) / dVar7);
    iVar3 = (int)(short)((0xff - cVar2) - DAT_803dd75c);
    uStack156 = (undefined4)lVar10;
    FUN_8011eda4((double)(float)(dVar9 + dVar6),(double)FLOAT_803e20cc,DAT_803a8ac8,iVar3,uVar1,
                 uStack156,0);
    uStack148 = (undefined4)lVar10;
    FUN_8011eda4((double)(float)(dVar11 - dVar6),(double)FLOAT_803e20cc,DAT_803a8ac8,iVar3,uVar1,
                 uStack148,0);
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  __psq_l0(auStack56,uVar4);
  __psq_l1(auStack56,uVar4);
  __psq_l0(auStack72,uVar4);
  __psq_l1(auStack72,uVar4);
  __psq_l0(auStack88,uVar4);
  __psq_l1(auStack88,uVar4);
  __psq_l0(auStack104,uVar4);
  __psq_l1(auStack104,uVar4);
  FUN_80286128();
  return;
}

