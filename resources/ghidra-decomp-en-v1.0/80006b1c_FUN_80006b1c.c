// Function: FUN_80006b1c
// Entry: 80006b1c
// Size: 336 bytes

void FUN_80006b1c(undefined4 param_1,undefined4 param_2,int param_3,int param_4,uint param_5)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  uint uVar7;
  byte *pbVar8;
  int iVar9;
  int iVar10;
  undefined8 uVar11;
  
  uVar11 = FUN_802860dc();
  piVar4 = (int *)((ulonglong)uVar11 >> 0x20);
  piVar6 = (int *)uVar11;
  iVar5 = FUN_80013a54(piVar6);
  param_5 = param_5 & 0xff;
  if (0 < param_3) {
    do {
      uVar7 = piVar4[4];
      pbVar8 = (byte *)(*piVar4 + ((int)uVar7 >> 3));
      bVar1 = *pbVar8;
      bVar2 = pbVar8[1];
      bVar3 = pbVar8[2];
      piVar4[4] = uVar7 + param_5;
      iVar9 = piVar6[4] >> 3;
      iVar10 = (~(-1 << param_5) &
               ((uint)bVar1 << 0x10 | (uint)bVar2 << 8 | (uint)bVar3) >> (uVar7 & 7)) <<
               (0x18 - param_5) - (piVar6[4] & 7U);
      *(byte *)(*piVar6 + iVar9) = *(byte *)(*piVar6 + iVar9) | (byte)((uint)iVar10 >> 0x10);
      *(byte *)(*piVar6 + iVar9 + 1) = *(byte *)(*piVar6 + iVar9 + 1) | (byte)((uint)iVar10 >> 8);
      *(byte *)(*piVar6 + iVar9 + 2) = *(byte *)(*piVar6 + iVar9 + 2) | (byte)iVar10;
      piVar6[4] = piVar6[4] + param_5;
      piVar6[4] = piVar6[4] + param_4;
      param_3 = param_3 + -1;
    } while (param_3 != 0);
  }
  FUN_80013a5c(piVar6,iVar5 + param_5);
  FUN_80286128(*(undefined *)(*piVar4 + (piVar4[4] >> 3) + 1));
  return;
}

