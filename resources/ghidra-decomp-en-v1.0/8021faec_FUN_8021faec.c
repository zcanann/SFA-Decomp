// Function: FUN_8021faec
// Entry: 8021faec
// Size: 1604 bytes

void FUN_8021faec(void)

{
  short sVar1;
  undefined2 *puVar2;
  uint uVar3;
  undefined4 uVar4;
  short sVar6;
  undefined2 *puVar5;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  
  puVar2 = (undefined2 *)FUN_802860dc();
  iVar10 = *(int *)(puVar2 + 0x5c);
  iVar9 = *(int *)(puVar2 + 0x26);
  FUN_8002b9ec();
  if (*(int *)(puVar2 + 0x62) == 0) {
    iVar7 = FUN_8003687c(puVar2,0,0,0);
    sVar6 = puVar2[0x23];
    if (sVar6 == 0x70a) {
      if ((iVar7 == 0xf) || (iVar7 == 0xe)) {
        *(byte *)(iVar10 + 0x41) = *(byte *)(iVar10 + 0x41) & 0xbf;
        FUN_8008016c(iVar10 + 0x24);
        FUN_80080178(iVar10 + 0x24,300);
      }
    }
    else if (((0x709 < sVar6) || (sVar6 != 0x6f9)) && (iVar7 == 0x10)) {
      iVar7 = *(int *)(puVar2 + 0x26);
      FUN_8002b050(puVar2,300);
      FUN_800200e8((int)*(short *)(iVar7 + 0x1e),1);
      *(byte *)(iVar10 + 0x41) = *(byte *)(iVar10 + 0x41) & 0xef | 0x10;
    }
  }
  else {
    FUN_80035f00(puVar2);
    if ((*(byte *)(iVar10 + 0x41) >> 2 & 1) == 0) goto LAB_80220118;
    *(byte *)(iVar10 + 0x41) = *(byte *)(iVar10 + 0x41) & 0xf7 | 8;
  }
  if (((*(byte *)(iVar10 + 0x41) >> 4 & 1) == 0) && (*(short *)(iVar9 + 0x1e) != -1)) {
    uVar3 = FUN_8001ffb4();
    if (*(byte *)(iVar10 + 0x41) >> 7 != uVar3) {
      uVar4 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x1e));
      uVar3 = countLeadingZeros(uVar4);
      uVar3 = uVar3 >> 5 & 1;
      *(byte *)(iVar10 + 0x41) = (byte)(uVar3 << 6) | *(byte *)(iVar10 + 0x41) & 0xbf;
      if (uVar3 == 0) {
        FUN_8008016c(iVar10 + 0x24);
      }
      else {
        iVar7 = *(int *)(puVar2 + 0x26);
        iVar8 = *(int *)(puVar2 + 0x5c);
        FUN_8008016c(iVar8 + 0x24);
        sVar6 = *(short *)(iVar7 + 0x1a);
        if (sVar6 != 0) {
          sVar1 = *(short *)(iVar7 + 0x20);
          if (sVar1 == 0) {
            FUN_80080178(iVar8 + 0x24,(int)(short)(sVar6 * 0x3c));
          }
          else if (sVar1 < 0) {
            sVar6 = FUN_800221a0(1,sVar6 * 0x3c);
            FUN_80080178(iVar8 + 0x24,(int)sVar6);
          }
          else {
            FUN_80080178(iVar8 + 0x24,(int)(short)(sVar1 * 0x3c));
            if (*(short *)(iVar7 + 0x1a) <= *(short *)(iVar7 + 0x20)) {
              *(byte *)(iVar8 + 0x41) = *(byte *)(iVar8 + 0x41) & 0xbf;
            }
          }
        }
      }
    }
    uVar3 = FUN_8001ffb4((int)*(short *)(iVar9 + 0x1e));
    *(byte *)(iVar10 + 0x41) = (byte)((uVar3 & 0xff) << 7) | *(byte *)(iVar10 + 0x41) & 0x7f;
  }
  if (((*(byte *)(iVar10 + 0x41) >> 6 & 1) != 0) &&
     (((puVar2[0x58] & 0x800) != 0 || (*(int *)(puVar2 + 0x62) != 0)))) {
    FUN_80098b18((double)(FLOAT_803e6b70 *
                         (float)((double)CONCAT44(0x43300000,
                                                  (int)*(short *)(iVar9 + 0x1c) ^ 0x80000000) -
                                DOUBLE_803e6ba0)),puVar2,*(uint *)(iVar10 + 0x34) & 0xff,0,0,0);
  }
  iVar7 = FUN_8002b044(puVar2);
  if (iVar7 == 0) {
    if ((*(byte *)(iVar10 + 0x41) >> 4 & 1) != 0) {
      *(byte *)(iVar10 + 0x41) = *(byte *)(iVar10 + 0x41) & 0xbf | 0x40;
      *(byte *)(iVar10 + 0x41) = *(byte *)(iVar10 + 0x41) & 0xef;
      FUN_800200e8((int)*(short *)(iVar9 + 0x1e),*(byte *)(iVar10 + 0x41) >> 7);
    }
    iVar7 = FUN_80080150(iVar10 + 0x24);
    if ((iVar7 != 0) && ((*(byte *)(iVar10 + 0x41) >> 6 & 1) == 0)) {
      if ((float)((double)CONCAT44(0x43300000,(int)DAT_803dc348 ^ 0x80000000) - DOUBLE_803e6ba0) <=
          *(float *)(iVar10 + 0x24)) {
        if (*(int *)(iVar10 + 0x2c) != 0) {
          FUN_8001db6c((double)FLOAT_803e6b98,*(int *)(iVar10 + 0x2c),0);
          iVar7 = FUN_8001db64(*(undefined4 *)(iVar10 + 0x2c));
          if (iVar7 == 0) {
            FUN_8001cb3c(iVar10 + 0x2c);
          }
        }
      }
      else if ((*(int *)(iVar10 + 0x2c) == 0) && ((*(byte *)(iVar10 + 0x41) & 1) != 0)) {
        uVar4 = FUN_8001cc9c(puVar2,0xff,0x80,0,0);
        *(undefined4 *)(iVar10 + 0x2c) = uVar4;
        if (*(int *)(iVar10 + 0x2c) != 0) {
          FUN_8001db6c((double)FLOAT_803e6b74,*(int *)(iVar10 + 0x2c),0);
          FUN_8001db6c((double)FLOAT_803e6b78,*(undefined4 *)(iVar10 + 0x2c),1);
          if (puVar2[0x23] == 0x6f9) {
            FUN_8001d730((double)(FLOAT_803dc34c * *(float *)(puVar2 + 4)),
                         *(undefined4 *)(iVar10 + 0x2c),0,0,0xb4,0xff,100);
          }
          else {
            FUN_8001d730((double)(FLOAT_803dc34c * *(float *)(puVar2 + 4)),
                         *(undefined4 *)(iVar10 + 0x2c),0,0xff,0x80,0,100);
          }
          FUN_8001dd88((double)FLOAT_803e6b74,(double)FLOAT_803e6b74,(double)FLOAT_803e6b7c,
                       *(undefined4 *)(iVar10 + 0x2c));
          dVar13 = (double)(FLOAT_803e6b80 * *(float *)(puVar2 + 4));
          dVar12 = (double)FLOAT_803e6b84;
          if ((dVar12 <= dVar13) && (dVar12 = dVar13, (double)FLOAT_803e6b88 < dVar13)) {
            dVar12 = (double)FLOAT_803e6b88;
          }
          dVar11 = (double)(float)((double)FLOAT_803e6b8c + dVar13);
          dVar13 = (double)FLOAT_803e6b90;
          if ((dVar13 <= dVar11) && (dVar13 = dVar11, (double)FLOAT_803e6b94 < dVar11)) {
            dVar13 = (double)FLOAT_803e6b94;
          }
          FUN_8001dc38(dVar12,dVar13,*(undefined4 *)(iVar10 + 0x2c));
        }
      }
    }
    iVar7 = FUN_800801a8(iVar10 + 0x24);
    if (iVar7 != 0) {
      if (*(short *)(iVar9 + 0x1a) != 0) {
        FUN_80080178(iVar10 + 0x24,(int)(short)(*(short *)(iVar9 + 0x1a) * 0x3c));
      }
      uVar3 = countLeadingZeros(*(byte *)(iVar10 + 0x41) >> 6 & 1);
      *(byte *)(iVar10 + 0x41) =
           (byte)((uVar3 >> 5 & 0xff) << 6) & 0x40 | *(byte *)(iVar10 + 0x41) & 0xbf;
    }
  }
  else {
    *(byte *)(iVar10 + 0x41) = *(byte *)(iVar10 + 0x41) & 0xbf;
    *(byte *)(iVar10 + 0x41) = *(byte *)(iVar10 + 0x41) & 0xef | 0x10;
  }
  if (((*(byte *)(iVar10 + 0x41) >> 6 & 1) != 0) &&
     (iVar9 = FUN_800801a8(iVar10 + 0x28), iVar9 != 0)) {
    iVar8 = *(int *)(puVar2 + 0x26);
    iVar7 = *(int *)(puVar2 + 0x5c);
    iVar9 = FUN_8002bdf4(0x24,0x1b5);
    *(undefined *)(iVar9 + 4) = 2;
    *(undefined *)(iVar9 + 0x19) = *(undefined *)(iVar7 + 0x40);
    *(undefined2 *)(iVar9 + 0x1a) = *(undefined2 *)(iVar8 + 0x1c);
    *(undefined4 *)(iVar9 + 8) = *(undefined4 *)(puVar2 + 6);
    *(undefined4 *)(iVar9 + 0xc) = *(undefined4 *)(puVar2 + 8);
    *(undefined4 *)(iVar9 + 0x10) = *(undefined4 *)(puVar2 + 10);
    if (iVar9 == 0) {
      puVar5 = (undefined2 *)0x0;
    }
    else {
      puVar5 = (undefined2 *)FUN_8021f8cc(iVar10,puVar2);
    }
    if (puVar5 != (undefined2 *)0x0) {
      *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(puVar2 + 6);
      *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(puVar2 + 8);
      *(undefined4 *)(puVar5 + 10) = *(undefined4 *)(puVar2 + 10);
      *puVar5 = *puVar2;
      puVar5[1] = puVar2[1];
      *(float *)(puVar5 + 0x14) = FLOAT_803dc344;
    }
    FUN_8008016c(iVar10 + 0x28);
    FUN_80080178(iVar10 + 0x28,(int)(short)DAT_803dc350);
  }
  if ((*(byte *)(iVar10 + 0x41) >> 6 & 1) != 0) {
    if ((*(byte *)(iVar10 + 0x41) >> 5 & 1) == 0) {
      FUN_8000b4d0(puVar2,0x32c,3);
    }
    FUN_8000d8e4(puVar2,0x32d,2);
  }
  *(byte *)(iVar10 + 0x41) =
       (byte)((*(byte *)(iVar10 + 0x41) >> 6 & 1) << 5) | *(byte *)(iVar10 + 0x41) & 0xdf;
  if (*(int *)(iVar10 + 0x2c) != 0) {
    FUN_8001d6b0();
  }
LAB_80220118:
  FUN_80286128();
  return;
}

