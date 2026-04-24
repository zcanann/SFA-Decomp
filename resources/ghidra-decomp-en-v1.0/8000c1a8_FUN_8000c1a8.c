// Function: FUN_8000c1a8
// Entry: 8000c1a8
// Size: 600 bytes

void FUN_8000c1a8(undefined4 param_1,undefined4 param_2,char *param_3,float *param_4,float *param_5,
                 float *param_6,uint *param_7,uint *param_8,uint *param_9)

{
  byte bVar1;
  char cVar2;
  double dVar3;
  uint uVar4;
  short *psVar5;
  undefined4 uVar6;
  int iVar7;
  char cVar9;
  char cVar10;
  int iVar8;
  uint uVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_802860c8();
  psVar5 = (short *)((ulonglong)uVar12 >> 0x20);
  if ((psVar5 == (short *)0x0) || (*(byte *)((int)psVar5 + 0x1f) >> 4 == 0)) {
    uVar6 = 0;
  }
  else {
    iVar7 = FUN_800221a0(1,psVar5[0xe]);
    if (*psVar5 == 0xab) {
      bVar1 = *(byte *)((int)psVar5 + 0x1f);
      if ((bVar1 & 0xf) == 0) {
        *(byte *)((int)psVar5 + 0x1f) = bVar1 & 0xf0 | 1;
      }
      else {
        *(byte *)((int)psVar5 + 0x1f) = bVar1 & 0xf0;
      }
      uVar11 = *(byte *)((int)psVar5 + 0x1f) & 0xf;
    }
    else {
      uVar11 = 0;
      for (; uVar4 = (uint)*(byte *)((int)psVar5 + uVar11 + 0x16), (int)uVar4 < iVar7;
          iVar7 = iVar7 - uVar4) {
        uVar11 = uVar11 + 1;
      }
      if (((*(byte *)((int)psVar5 + 0x1f) & 0xf) == uVar11) &&
         (uVar11 = uVar11 + 1, (int)(uint)(*(byte *)((int)psVar5 + 0x1f) >> 4) <= (int)uVar11)) {
        uVar11 = 0;
      }
    }
    *(byte *)((int)psVar5 + 0x1f) = (byte)uVar11 & 0xf | *(byte *)((int)psVar5 + 0x1f) & 0xf0;
    *(short *)uVar12 = psVar5[uVar11 + 5];
    if (*(short *)uVar12 == 0) {
      uVar6 = 0;
    }
    else {
      cVar10 = *(char *)((int)psVar5 + 3);
      if (cVar10 == '\0') {
        *param_3 = *(char *)(psVar5 + 1);
      }
      else {
        cVar9 = FUN_800221a0(0,cVar10);
        cVar2 = *(char *)(psVar5 + 1);
        cVar10 = FUN_800221a0(0,cVar10);
        *param_3 = (cVar2 + cVar9) - cVar10;
      }
      cVar10 = *(char *)((int)psVar5 + 5);
      if (cVar10 == '\0') {
        *param_4 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(psVar5 + 2)) -
                          DOUBLE_803de588);
      }
      else {
        iVar7 = FUN_800221a0(0,cVar10);
        bVar1 = *(byte *)(psVar5 + 2);
        iVar8 = FUN_800221a0(0,cVar10);
        *param_4 = (float)((double)CONCAT44(0x43300000,((uint)bVar1 + iVar7) - iVar8 ^ 0x80000000) -
                          DOUBLE_803de580);
      }
      dVar3 = DOUBLE_803de588;
      *param_5 = (float)((double)CONCAT44(0x43300000,(uint)(ushort)psVar5[3]) - DOUBLE_803de588);
      *param_6 = (float)((double)CONCAT44(0x43300000,(uint)(ushort)psVar5[4]) - dVar3);
      *param_7 = (uint)(byte)(&DAT_803db248)[*(byte *)(psVar5 + 0xf) >> 4];
      *param_8 = *(byte *)(psVar5 + 0xf) & 1;
      *param_9 = *(byte *)(psVar5 + 0xf) >> 3 & 1;
      uVar6 = 1;
    }
  }
  FUN_80286114(uVar6);
  return;
}

