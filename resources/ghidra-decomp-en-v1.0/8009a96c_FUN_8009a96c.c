// Function: FUN_8009a96c
// Entry: 8009a96c
// Size: 516 bytes

/* WARNING: Removing unreachable block (ram,0x8009ab48) */
/* WARNING: Removing unreachable block (ram,0x8009ab38) */
/* WARNING: Removing unreachable block (ram,0x8009ab40) */
/* WARNING: Removing unreachable block (ram,0x8009ab50) */

void FUN_8009a96c(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,uint param_7,uint param_8,uint param_9,uint param_10,
                 uint param_11,ushort param_12)

{
  int iVar1;
  char cVar4;
  int iVar2;
  int iVar3;
  undefined extraout_r4;
  undefined4 uVar5;
  double extraout_f1;
  double dVar6;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  iVar1 = FUN_802860cc();
  dVar6 = extraout_f1;
  cVar4 = FUN_8002e04c();
  if (cVar4 != '\0') {
    iVar2 = FUN_8002bdf4(0x24,0x253);
    *(undefined *)(iVar2 + 4) = 2;
    *(undefined *)(iVar2 + 5) = 1;
    *(float *)(iVar2 + 8) = (float)dVar6;
    *(float *)(iVar2 + 0xc) = (float)param_2;
    *(float *)(iVar2 + 0x10) = (float)param_3;
    *(undefined *)(iVar2 + 0x19) = extraout_r4;
    *(short *)(iVar2 + 0x1a) = (short)(int)((double)FLOAT_803df3ac * param_4);
    *(ushort *)(iVar2 + 0x1c) = param_12 & 0xff;
    if ((param_7 & 0xff) != 0) {
      *(ushort *)(iVar2 + 0x1c) = *(ushort *)(iVar2 + 0x1c) | 4;
    }
    if ((param_8 & 0xff) != 0) {
      *(ushort *)(iVar2 + 0x1c) = *(ushort *)(iVar2 + 0x1c) | 8;
    }
    if ((param_9 & 0xff) != 0) {
      *(ushort *)(iVar2 + 0x1c) = *(ushort *)(iVar2 + 0x1c) | 0x10;
    }
    if ((param_11 & 0xff) != 0) {
      *(ushort *)(iVar2 + 0x1c) = *(ushort *)(iVar2 + 0x1c) | 0x20;
    }
    if ((((param_10 & 0xff) != 0) && (iVar3 = FUN_8002b9ec(), iVar3 != 0)) &&
       ((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0)) {
      dVar6 = (double)FUN_8000f480((double)*(float *)(iVar1 + 0x18),(double)*(float *)(iVar1 + 0x1c)
                                   ,(double)*(float *)(iVar1 + 0x20));
      if (dVar6 <= (double)FLOAT_803df3b0) {
        dVar6 = (double)(FLOAT_803df354 - (float)(dVar6 / (double)FLOAT_803df3b0));
        FUN_8000e650((double)(float)((double)FLOAT_803df3a0 * dVar6),
                     (double)(float)((double)FLOAT_803df384 * dVar6),(double)FLOAT_803df3a4);
        FUN_80014aa0((double)(float)((double)FLOAT_803df3a8 * dVar6));
      }
    }
    FUN_8002df90(iVar2,5,(int)*(char *)(iVar1 + 0xac),0xffffffff,0);
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  __psq_l0(auStack56,uVar5);
  __psq_l1(auStack56,uVar5);
  FUN_80286118();
  return;
}

