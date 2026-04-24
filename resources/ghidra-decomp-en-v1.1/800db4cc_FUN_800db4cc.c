// Function: FUN_800db4cc
// Entry: 800db4cc
// Size: 420 bytes

/* WARNING: Removing unreachable block (ram,0x800db650) */
/* WARNING: Removing unreachable block (ram,0x800db4dc) */

void FUN_800db4cc(undefined4 param_1,undefined4 param_2,uint param_3)

{
  double dVar1;
  float *pfVar2;
  float *pfVar3;
  uint uVar4;
  double dVar5;
  double dVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_80286840();
  dVar1 = DOUBLE_803e1260;
  pfVar2 = (float *)((ulonglong)uVar7 >> 0x20);
  pfVar3 = (float *)uVar7;
  uVar4 = 0;
  while (((uVar4 & 0xff) < 0x100 &&
         ((param_3 & 0xffff) != (uint)(ushort)(&DAT_8039d76c)[(uVar4 & 0xff) * 0x18]))) {
    uVar4 = uVar4 + 1;
  }
  uVar4 = uVar4 & 0xff;
  *pfVar3 = (float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039d76e)[uVar4 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e1260);
  pfVar3[1] = pfVar2[1];
  pfVar3[2] = (float)((double)CONCAT44(0x43300000,
                                       (int)(short)(&DAT_8039d770)[uVar4 * 0x18] ^ 0x80000000) -
                     dVar1);
  dVar5 = FUN_80021794(pfVar2,pfVar3);
  dVar1 = DOUBLE_803e1260;
  *pfVar3 = (float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039d772)[uVar4 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e1260);
  pfVar3[2] = (float)((double)CONCAT44(0x43300000,
                                       (int)(short)(&DAT_8039d774)[uVar4 * 0x18] ^ 0x80000000) -
                     dVar1);
  dVar6 = FUN_80021794(pfVar2,pfVar3);
  dVar1 = DOUBLE_803e1260;
  if (dVar5 <= dVar6) {
    *pfVar3 = (float)((double)CONCAT44(0x43300000,
                                       (int)(short)(&DAT_8039d76e)[uVar4 * 0x18] ^ 0x80000000) -
                     DOUBLE_803e1260);
    pfVar3[2] = (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039d770)[uVar4 * 0x18] ^ 0x80000000) -
                       dVar1);
  }
  FUN_8028688c();
  return;
}

