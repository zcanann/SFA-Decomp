// Function: FUN_80133818
// Entry: 80133818
// Size: 284 bytes

/* WARNING: Removing unreachable block (ram,0x80133910) */
/* WARNING: Removing unreachable block (ram,0x80133900) */
/* WARNING: Removing unreachable block (ram,0x801338f8) */
/* WARNING: Removing unreachable block (ram,0x80133908) */
/* WARNING: Removing unreachable block (ram,0x80133918) */

void FUN_80133818(void)

{
  int iVar1;
  undefined4 uVar2;
  byte bVar3;
  undefined4 uVar4;
  undefined8 in_f27;
  double dVar5;
  undefined8 in_f28;
  double dVar6;
  undefined8 in_f29;
  double dVar7;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
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
  dVar5 = (double)FLOAT_803e2284;
  dVar6 = (double)FLOAT_803e2288;
  dVar7 = (double)FLOAT_803e2208;
  dVar8 = (double)FLOAT_803e228c;
  dVar9 = (double)FLOAT_803e2290;
  for (bVar3 = 0; bVar3 < 2; bVar3 = bVar3 + 1) {
    uVar2 = FUN_8002bdf4(0x20,bVar3 + 0x7da);
    uVar2 = FUN_8002df90(uVar2,4,0xffffffff,0xffffffff,0);
    iVar1 = (uint)bVar3 * 4;
    *(undefined4 *)(&DAT_803dbbc8 + iVar1) = uVar2;
    *(float *)(*(int *)(&DAT_803dbbc8 + iVar1) + 0xc) = (float)dVar5;
    *(float *)(*(int *)(&DAT_803dbbc8 + iVar1) + 0x10) = (float)dVar6;
    *(float *)(*(int *)(&DAT_803dbbc8 + iVar1) + 0xc) = (float)dVar7;
    *(float *)(*(int *)(&DAT_803dbbc8 + iVar1) + 0x10) = (float)dVar7;
    *(float *)(*(int *)(&DAT_803dbbc8 + iVar1) + 0x14) = (float)dVar8;
    **(undefined2 **)(&DAT_803dbbc8 + iVar1) = 2000;
    *(undefined2 *)(*(int *)(&DAT_803dbbc8 + iVar1) + 2) = 0;
    *(float *)(*(int *)(&DAT_803dbbc8 + iVar1) + 8) = (float)dVar9;
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
  return;
}

