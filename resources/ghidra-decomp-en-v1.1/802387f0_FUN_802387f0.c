// Function: FUN_802387f0
// Entry: 802387f0
// Size: 684 bytes

void FUN_802387f0(void)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  byte bVar6;
  float *pfVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_8028683c();
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  pfVar7 = *(float **)(iVar2 + 0xb8);
  *(byte *)((int)pfVar7 + 0x26) = *(byte *)((int)pfVar7 + 0x26) & 0x7f;
  uVar3 = (uint)*(short *)((int)uVar8 + 0x20);
  if (uVar3 != 0xffffffff) {
    uVar3 = FUN_80020078(uVar3);
    *(byte *)((int)pfVar7 + 0x26) =
         (byte)((uVar3 & 0xff) << 7) | *(byte *)((int)pfVar7 + 0x26) & 0x7f;
  }
  sVar1 = *(short *)(iVar2 + 0x46);
  if (sVar1 == 0x835) {
    for (bVar6 = 0; bVar6 < 2; bVar6 = bVar6 + 1) {
      uVar3 = (uint)bVar6;
      pfVar7[uVar3 + 5] = *(float *)(&DAT_803dd060 + uVar3 * 4);
      pfVar7[uVar3 + 2] = *(float *)(&DAT_803dd068 + uVar3 * 4);
      uVar4 = FUN_80022264(0xffff8001,0x7fff);
      *(short *)((int)pfVar7 + uVar3 * 2 + 0x20) = (short)uVar4;
    }
  }
  else if (sVar1 == 0x838) {
    for (bVar6 = 0; bVar6 < 2; bVar6 = bVar6 + 1) {
      uVar3 = (uint)bVar6;
      pfVar7[uVar3 + 5] = *(float *)(&DAT_803dd060 + uVar3 * 4);
      pfVar7[uVar3 + 2] = *(float *)(&DAT_803dd070 + uVar3 * 4);
      uVar4 = FUN_80022264(0xffff8001,0x7fff);
      *(short *)((int)pfVar7 + uVar3 * 2 + 0x20) = (short)uVar4;
    }
  }
  else if (sVar1 == 0x83d) {
    for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
      uVar3 = (uint)bVar6;
      pfVar7[uVar3 + 5] = (float)(&DAT_8032ca78)[uVar3];
      pfVar7[uVar3 + 2] = (float)(&DAT_8032ca84)[uVar3];
      uVar4 = FUN_80022264(0xffff8001,0x7fff);
      *(short *)((int)pfVar7 + uVar3 * 2 + 0x20) = (short)uVar4;
    }
  }
  else {
    for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
      uVar3 = (uint)bVar6;
      pfVar7[uVar3 + 5] = (float)(&DAT_8032ca90)[uVar3];
      pfVar7[uVar3 + 2] = (float)(&DAT_8032ca9c)[uVar3];
      uVar4 = FUN_80022264(0xffff8001,0x7fff);
      *(short *)((int)pfVar7 + uVar3 * 2 + 0x20) = (short)uVar4;
    }
    if ((*(char *)((int)pfVar7 + 0x26) < '\0') &&
       (uVar3 = (uint)*(short *)((int)uVar8 + 0x1e), uVar3 != 0xffffffff)) {
      uVar3 = FUN_80020078(uVar3);
      uVar3 = countLeadingZeros(uVar3);
      *(byte *)((int)pfVar7 + 0x26) =
           (byte)((uVar3 >> 5 & 0xff) << 7) | *(byte *)((int)pfVar7 + 0x26) & 0x7f;
    }
  }
  *(ushort *)(iVar2 + 0xb0) = *(ushort *)(iVar2 + 0xb0) | 0x2000;
  iVar5 = FUN_8002b660(iVar2);
  FUN_800285f0(iVar5,FUN_80028590);
  if (*(char *)((int)pfVar7 + 0x26) < '\0') {
    *pfVar7 = FLOAT_803e8078;
  }
  else {
    *pfVar7 = FLOAT_803e8068;
  }
  uVar3 = FUN_80022264(0,0x14);
  pfVar7[1] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e8088);
  *(float *)(iVar2 + 0x40) = *(float *)(iVar2 + 0x40) * FLOAT_803e809c;
  FUN_80286888();
  return;
}

