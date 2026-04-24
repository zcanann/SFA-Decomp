// Function: FUN_8023812c
// Entry: 8023812c
// Size: 684 bytes

void FUN_8023812c(void)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  undefined2 uVar5;
  undefined4 uVar4;
  byte bVar6;
  float *pfVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_802860d8();
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  pfVar7 = *(float **)(iVar2 + 0xb8);
  *(byte *)((int)pfVar7 + 0x26) = *(byte *)((int)pfVar7 + 0x26) & 0x7f;
  if (*(short *)((int)uVar8 + 0x20) != -1) {
    uVar3 = FUN_8001ffb4();
    *(byte *)((int)pfVar7 + 0x26) =
         (byte)((uVar3 & 0xff) << 7) | *(byte *)((int)pfVar7 + 0x26) & 0x7f;
  }
  sVar1 = *(short *)(iVar2 + 0x46);
  if (sVar1 == 0x835) {
    for (bVar6 = 0; bVar6 < 2; bVar6 = bVar6 + 1) {
      uVar3 = (uint)bVar6;
      pfVar7[uVar3 + 5] = *(float *)(&DAT_803dc3f8 + uVar3 * 4);
      pfVar7[uVar3 + 2] = *(float *)(&DAT_803dc400 + uVar3 * 4);
      uVar5 = FUN_800221a0(0xffff8001,0x7fff);
      *(undefined2 *)((int)pfVar7 + uVar3 * 2 + 0x20) = uVar5;
    }
  }
  else if (sVar1 == 0x838) {
    for (bVar6 = 0; bVar6 < 2; bVar6 = bVar6 + 1) {
      uVar3 = (uint)bVar6;
      pfVar7[uVar3 + 5] = *(float *)(&DAT_803dc3f8 + uVar3 * 4);
      pfVar7[uVar3 + 2] = *(float *)(&DAT_803dc408 + uVar3 * 4);
      uVar5 = FUN_800221a0(0xffff8001,0x7fff);
      *(undefined2 *)((int)pfVar7 + uVar3 * 2 + 0x20) = uVar5;
    }
  }
  else if (sVar1 == 0x83d) {
    for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
      uVar3 = (uint)bVar6;
      pfVar7[uVar3 + 5] = (float)(&DAT_8032be20)[uVar3];
      pfVar7[uVar3 + 2] = (float)(&DAT_8032be2c)[uVar3];
      uVar5 = FUN_800221a0(0xffff8001,0x7fff);
      *(undefined2 *)((int)pfVar7 + uVar3 * 2 + 0x20) = uVar5;
    }
  }
  else {
    for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
      uVar3 = (uint)bVar6;
      pfVar7[uVar3 + 5] = (float)(&DAT_8032be38)[uVar3];
      pfVar7[uVar3 + 2] = (float)(&DAT_8032be44)[uVar3];
      uVar5 = FUN_800221a0(0xffff8001,0x7fff);
      *(undefined2 *)((int)pfVar7 + uVar3 * 2 + 0x20) = uVar5;
    }
    if ((*(char *)((int)pfVar7 + 0x26) < '\0') && (*(short *)((int)uVar8 + 0x1e) != -1)) {
      uVar4 = FUN_8001ffb4();
      uVar3 = countLeadingZeros(uVar4);
      *(byte *)((int)pfVar7 + 0x26) =
           (byte)((uVar3 >> 5 & 0xff) << 7) | *(byte *)((int)pfVar7 + 0x26) & 0x7f;
    }
  }
  *(ushort *)(iVar2 + 0xb0) = *(ushort *)(iVar2 + 0xb0) | 0x2000;
  uVar4 = FUN_8002b588(iVar2);
  FUN_8002852c(uVar4,FUN_800284cc);
  if (*(char *)((int)pfVar7 + 0x26) < '\0') {
    *pfVar7 = FLOAT_803e73e0;
  }
  else {
    *pfVar7 = FLOAT_803e73d0;
  }
  uVar3 = FUN_800221a0(0,0x14);
  pfVar7[1] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e73f0);
  *(float *)(iVar2 + 0x40) = *(float *)(iVar2 + 0x40) * FLOAT_803e7404;
  FUN_80286124();
  return;
}

