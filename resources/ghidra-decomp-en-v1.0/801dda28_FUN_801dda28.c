// Function: FUN_801dda28
// Entry: 801dda28
// Size: 504 bytes

/* WARNING: Removing unreachable block (ram,0x801ddbf8) */
/* WARNING: Removing unreachable block (ram,0x801ddbe8) */
/* WARNING: Removing unreachable block (ram,0x801ddbf0) */
/* WARNING: Removing unreachable block (ram,0x801ddc00) */

void FUN_801dda28(void)

{
  short *psVar1;
  char cVar3;
  int iVar2;
  char cVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  double extraout_f1;
  double dVar8;
  undefined8 in_f28;
  double dVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  psVar1 = (short *)FUN_802860cc();
  dVar9 = extraout_f1;
  cVar3 = FUN_8002e04c();
  if (cVar3 != '\0') {
    cVar3 = '\x01';
    iVar6 = 0;
    dVar10 = (double)FLOAT_803e5640;
    dVar12 = (double)FLOAT_803e5644;
    dVar11 = DOUBLE_803e5648;
    for (cVar4 = '\0'; cVar4 < '\b'; cVar4 = cVar4 + '\x01') {
      iVar5 = *(int *)(psVar1 + 0x26);
      iVar2 = FUN_8002bdf4(0x38,0x27b);
      dVar8 = (double)FUN_80293e80((double)(float)((double)(float)(dVar10 * (double)(float)((double)
                                                  CONCAT44(0x43300000,*psVar1 + iVar6 ^ 0x80000000)
                                                  - dVar11)) / dVar12));
      *(float *)(iVar2 + 8) = (float)(dVar9 * dVar8 + (double)*(float *)(psVar1 + 6));
      *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(psVar1 + 8);
      dVar8 = (double)FUN_80294204((double)(float)((double)(float)(dVar10 * (double)(float)((double)
                                                  CONCAT44(0x43300000,*psVar1 + iVar6 ^ 0x80000000)
                                                  - dVar11)) / dVar12));
      *(float *)(iVar2 + 0x10) = (float)(dVar9 * dVar8 + (double)*(float *)(psVar1 + 10));
      *(undefined *)(iVar2 + 4) = *(undefined *)(iVar5 + 4);
      *(byte *)(iVar2 + 5) = *(byte *)(iVar5 + 5) & 0xfe | 4;
      *(undefined *)(iVar2 + 6) = *(undefined *)(iVar5 + 6);
      *(undefined *)(iVar2 + 7) = 0x1e;
      *(undefined2 *)(iVar2 + 0x18) = 0xffff;
      *(undefined2 *)(iVar2 + 0x1a) = 0x64c;
      *(undefined2 *)(iVar2 + 0x1c) = (&DAT_80327a70)[cVar3];
      *(undefined2 *)(iVar2 + 0x30) = *(undefined2 *)(&DAT_80327a60 + cVar3 * 2);
      *(char *)(iVar2 + 0x2a) = (char)((uint)(*psVar1 + iVar6 + 0x8000) >> 8);
      *(undefined *)(iVar2 + 0x32) = 1;
      FUN_8002df90(iVar2,5,0xffffffff,0xffffffff,0);
      cVar3 = cVar3 + '\x01';
      if ('\a' < cVar3) {
        cVar3 = '\0';
      }
      iVar6 = iVar6 + 0x2000;
    }
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  __psq_l0(auStack56,uVar7);
  __psq_l1(auStack56,uVar7);
  FUN_80286118();
  return;
}

