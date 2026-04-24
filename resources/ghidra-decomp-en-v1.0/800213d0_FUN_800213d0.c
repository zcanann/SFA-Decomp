// Function: FUN_800213d0
// Entry: 800213d0
// Size: 416 bytes

/* WARNING: Removing unreachable block (ram,0x80021548) */
/* WARNING: Removing unreachable block (ram,0x80021538) */
/* WARNING: Removing unreachable block (ram,0x80021528) */
/* WARNING: Removing unreachable block (ram,0x80021520) */
/* WARNING: Removing unreachable block (ram,0x80021530) */
/* WARNING: Removing unreachable block (ram,0x80021540) */
/* WARNING: Removing unreachable block (ram,0x80021550) */

void FUN_800213d0(undefined4 param_1,undefined4 param_2,undefined2 *param_3,undefined2 *param_4,
                 undefined2 *param_5)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f25;
  double dVar6;
  undefined8 in_f26;
  double dVar7;
  undefined8 in_f27;
  double dVar8;
  undefined8 in_f28;
  double dVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  undefined8 uVar12;
  float local_b8;
  float local_b4;
  float local_b0;
  longlong local_a8;
  longlong local_a0;
  longlong local_98;
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
  uVar12 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar12 >> 0x20);
  pfVar3 = (float *)uVar12;
  FUN_8024784c(pfVar3,iVar2,&local_b8);
  dVar11 = (double)local_b8;
  dVar10 = (double)local_b4;
  dVar9 = (double)local_b0;
  dVar8 = (double)*pfVar3;
  dVar7 = (double)pfVar3[1];
  dVar6 = (double)*(float *)(iVar2 + 8);
  dVar5 = (double)FUN_80291f44(-(double)pfVar3[2]);
  if ((double)FLOAT_803de7c8 <= dVar5) {
    dVar7 = (double)FUN_802923c4(dVar10,dVar11);
    dVar6 = (double)FLOAT_803de7c0;
    dVar9 = (double)(float)(dVar7 - dVar6);
  }
  else if (dVar5 <= (double)FLOAT_803de7cc) {
    dVar7 = (double)FUN_802923c4(dVar10,dVar11);
    dVar6 = (double)FLOAT_803de7c0;
    dVar9 = (double)(float)(dVar6 - dVar7);
  }
  else {
    dVar9 = (double)FUN_802923c4(dVar9,dVar6);
    dVar6 = (double)FUN_802923c4(dVar8,dVar7);
  }
  fVar1 = FLOAT_803de7d4;
  dVar7 = (double)FLOAT_803de7d0;
  iVar2 = (int)((float)(dVar7 * dVar6) / FLOAT_803de7d4);
  local_a8 = (longlong)iVar2;
  *param_3 = (short)iVar2;
  iVar2 = (int)((float)(dVar7 * dVar5) / fVar1);
  local_a0 = (longlong)iVar2;
  *param_4 = (short)iVar2;
  iVar2 = (int)((float)(dVar7 * dVar9) / fVar1);
  local_98 = (longlong)iVar2;
  *param_5 = (short)iVar2;
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

