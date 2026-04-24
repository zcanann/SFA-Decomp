// Function: FUN_80088e54
// Entry: 80088e54
// Size: 476 bytes

/* WARNING: Removing unreachable block (ram,0x8008900c) */

void FUN_80088e54(double param_1,uint param_2)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = FUN_800e84f8();
  if (*(byte *)(DAT_803dd12c + 0x24c) != param_2) {
    *(byte *)(DAT_803dd12c + 0x24d) = *(byte *)(DAT_803dd12c + 0x24c);
    *(char *)(DAT_803dd12c + 0x24c) = (char)param_2;
    fVar3 = FLOAT_803df05c;
    fVar2 = FLOAT_803df058;
    if (param_1 == (double)FLOAT_803df058) {
      *(float *)(DAT_803dd12c + 0x248) = FLOAT_803df05c;
      *(float *)(DAT_803dd12c + 0x244) = fVar3;
    }
    else {
      *(float *)(DAT_803dd12c + 0x248) = FLOAT_803df05c / (float)((double)FLOAT_803df060 * param_1);
      *(float *)(DAT_803dd12c + 0x244) = fVar2;
    }
    bVar1 = *(byte *)(DAT_803dd12c + param_2 * 0xa4 + 0xc1) >> 3;
    if ((bVar1 & 3) != 0) {
      FUN_8005cef0((bVar1 & 3) - 1);
    }
    iVar6 = param_2 * 0xa4 + 0xc1;
    *(byte *)(DAT_803dd12c + 0x209) =
         *(byte *)(DAT_803dd12c + iVar6) & 0x80 | *(byte *)(DAT_803dd12c + 0x209) & 0x7f;
    *(byte *)(DAT_803dd12c + 0x209) =
         (byte)((*(byte *)(DAT_803dd12c + iVar6) >> 5 & 1) << 5) |
         *(byte *)(DAT_803dd12c + 0x209) & 0xdf;
    iVar6 = FUN_800e84f8();
    iVar5 = FUN_800e87c4();
    if (iVar5 == 0) {
      if (*(char *)(DAT_803dd12c + 0xc1) < '\0') {
        *(byte *)(iVar6 + 0x40) = *(byte *)(iVar6 + 0x40) | 2;
      }
      else {
        *(byte *)(iVar6 + 0x40) = *(byte *)(iVar6 + 0x40) & 0xfd;
      }
      if (*(char *)(DAT_803dd12c + 0x165) < '\0') {
        *(byte *)(iVar6 + 0x40) = *(byte *)(iVar6 + 0x40) | 4;
      }
      else {
        *(byte *)(iVar6 + 0x40) = *(byte *)(iVar6 + 0x40) & 0xfb;
      }
    }
    if (param_2 == 0) {
      *(byte *)(iVar4 + 0x40) = *(byte *)(iVar4 + 0x40) & 0xef;
    }
    else {
      *(byte *)(iVar4 + 0x40) = *(byte *)(iVar4 + 0x40) | 0x10;
    }
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return;
}

