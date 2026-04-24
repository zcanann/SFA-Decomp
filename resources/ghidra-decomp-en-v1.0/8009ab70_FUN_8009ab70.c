// Function: FUN_8009ab70
// Entry: 8009ab70
// Size: 468 bytes

/* WARNING: Removing unreachable block (ram,0x8009ad24) */

void FUN_8009ab70(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5,
                 uint param_6,uint param_7,ushort param_8)

{
  int iVar1;
  char cVar4;
  int iVar2;
  int iVar3;
  undefined extraout_r4;
  undefined4 uVar5;
  double extraout_f1;
  double dVar6;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = FUN_802860cc();
  dVar6 = extraout_f1;
  cVar4 = FUN_8002e04c();
  if (cVar4 != '\0') {
    iVar2 = FUN_8002bdf4(0x24,0x253);
    *(undefined *)(iVar2 + 4) = 2;
    *(undefined *)(iVar2 + 5) = 1;
    *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(iVar1 + 0x18);
    *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar1 + 0x1c);
    *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar1 + 0x20);
    *(undefined *)(iVar2 + 0x19) = extraout_r4;
    *(short *)(iVar2 + 0x1a) = (short)(int)((double)FLOAT_803df3ac * dVar6);
    *(ushort *)(iVar2 + 0x1c) = param_8 & 0xff;
    if ((param_3 & 0xff) != 0) {
      *(ushort *)(iVar2 + 0x1c) = *(ushort *)(iVar2 + 0x1c) | 4;
    }
    if ((param_4 & 0xff) != 0) {
      *(ushort *)(iVar2 + 0x1c) = *(ushort *)(iVar2 + 0x1c) | 8;
    }
    if ((param_5 & 0xff) != 0) {
      *(ushort *)(iVar2 + 0x1c) = *(ushort *)(iVar2 + 0x1c) | 0x10;
    }
    if ((param_7 & 0xff) != 0) {
      *(ushort *)(iVar2 + 0x1c) = *(ushort *)(iVar2 + 0x1c) | 0x20;
    }
    if ((((param_6 & 0xff) != 0) && (iVar3 = FUN_8002b9ec(), iVar3 != 0)) &&
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
  FUN_80286118();
  return;
}

