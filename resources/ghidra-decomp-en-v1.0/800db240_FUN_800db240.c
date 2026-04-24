// Function: FUN_800db240
// Entry: 800db240
// Size: 420 bytes

/* WARNING: Removing unreachable block (ram,0x800db3c4) */

void FUN_800db240(undefined4 param_1,undefined4 param_2,uint param_3)

{
  double dVar1;
  int iVar2;
  float *pfVar3;
  uint uVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f31;
  undefined8 uVar8;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar8 = FUN_802860dc();
  dVar1 = DOUBLE_803e05e0;
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  pfVar3 = (float *)uVar8;
  uVar4 = 0;
  while (((uVar4 & 0xff) < 0x100 &&
         ((param_3 & 0xffff) != (uint)(ushort)(&DAT_8039cb0c)[(uVar4 & 0xff) * 0x18]))) {
    uVar4 = uVar4 + 1;
  }
  uVar4 = uVar4 & 0xff;
  *pfVar3 = (float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039cb0e)[uVar4 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e05e0);
  pfVar3[1] = *(float *)(iVar2 + 4);
  pfVar3[2] = (float)((double)CONCAT44(0x43300000,
                                       (int)(short)(&DAT_8039cb10)[uVar4 * 0x18] ^ 0x80000000) -
                     dVar1);
  dVar6 = (double)FUN_800216d0(iVar2,pfVar3);
  dVar1 = DOUBLE_803e05e0;
  *pfVar3 = (float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039cb12)[uVar4 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e05e0);
  pfVar3[2] = (float)((double)CONCAT44(0x43300000,
                                       (int)(short)(&DAT_8039cb14)[uVar4 * 0x18] ^ 0x80000000) -
                     dVar1);
  dVar7 = (double)FUN_800216d0(iVar2,pfVar3);
  dVar1 = DOUBLE_803e05e0;
  if (dVar6 <= dVar7) {
    *pfVar3 = (float)((double)CONCAT44(0x43300000,
                                       (int)(short)(&DAT_8039cb0e)[uVar4 * 0x18] ^ 0x80000000) -
                     DOUBLE_803e05e0);
    pfVar3[2] = (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039cb10)[uVar4 * 0x18] ^ 0x80000000) -
                       dVar1);
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  FUN_80286128(1);
  return;
}

