// Function: FUN_80006b1c
// Entry: 80006b1c
// Size: 336 bytes

void FUN_80006b1c(undefined4 param_1,undefined4 param_2,int param_3,int param_4,uint param_5)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  int *piVar7;
  uint uVar8;
  byte *pbVar9;
  int iVar10;
  int iVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_80286840();
  piVar5 = (int *)((ulonglong)uVar12 >> 0x20);
  piVar7 = (int *)uVar12;
  iVar6 = FUN_80013a74((int)piVar7);
  uVar4 = param_5 & 0xff;
  if (0 < param_3) {
    do {
      uVar8 = piVar5[4];
      pbVar9 = (byte *)(*piVar5 + ((int)uVar8 >> 3));
      bVar1 = *pbVar9;
      bVar2 = pbVar9[1];
      bVar3 = pbVar9[2];
      piVar5[4] = uVar8 + uVar4;
      iVar10 = piVar7[4] >> 3;
      iVar11 = (~(-1 << uVar4) &
               ((uint)bVar1 << 0x10 | (uint)bVar2 << 8 | (uint)bVar3) >> (uVar8 & 7)) <<
               (0x18 - uVar4) - (piVar7[4] & 7U);
      *(byte *)(*piVar7 + iVar10) = *(byte *)(*piVar7 + iVar10) | (byte)((uint)iVar11 >> 0x10);
      *(byte *)(*piVar7 + iVar10 + 1) = *(byte *)(*piVar7 + iVar10 + 1) | (byte)((uint)iVar11 >> 8);
      *(byte *)(*piVar7 + iVar10 + 2) = *(byte *)(*piVar7 + iVar10 + 2) | (byte)iVar11;
      piVar7[4] = piVar7[4] + uVar4;
      piVar7[4] = piVar7[4] + param_4;
      param_3 = param_3 + -1;
    } while (param_3 != 0);
  }
  FUN_80013a7c((int)piVar7,iVar6 + uVar4);
  FUN_8028688c();
  return;
}

