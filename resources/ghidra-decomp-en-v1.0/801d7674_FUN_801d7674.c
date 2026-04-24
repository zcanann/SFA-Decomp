// Function: FUN_801d7674
// Entry: 801d7674
// Size: 1164 bytes

void FUN_801d7674(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  short *psVar5;
  short sVar6;
  int *piVar7;
  
  piVar7 = *(int **)(param_1 + 0xb8);
  if (*piVar7 != 0) {
    FUN_80037cb0();
    FUN_8002cbc4(*piVar7);
    *piVar7 = 0;
  }
  iVar2 = FUN_801d6c04((double)FLOAT_803e54a4,param_1);
  if (*(short *)(param_1 + 0xa0) == 0) {
    iVar3 = FUN_80080100(100);
    if (iVar3 != 0) {
      FUN_800393f8(param_1,piVar7 + 5,0xab,0xffffff00,0xffffffff,0);
    }
    iVar3 = FUN_80080100(500);
    if (iVar3 != 0) {
      FUN_800393f8(param_1,piVar7 + 5,0x417,0xfffffb00,0xffffffff,0);
    }
  }
  iVar3 = FUN_8001ffb4(0xc7d);
  if (iVar3 != 0) {
    iVar3 = FUN_80080100(DAT_803dc038);
    if (iVar3 != 0) {
      uVar1 = countLeadingZeros(*(byte *)((int)piVar7 + 0xd5) >> 6 & 1);
      *(byte *)((int)piVar7 + 0xd5) =
           (byte)((uVar1 >> 5 & 1) << 6) | *(byte *)((int)piVar7 + 0xd5) & 0xbf;
    }
    if ((*(byte *)((int)piVar7 + 0xd5) >> 6 & 1) == 0) {
      uVar1 = FUN_8001ffb4(0xa45);
      *(byte *)((int)piVar7 + 0xd5) =
           (byte)((uVar1 & 0xff) << 6) & 0x40 | *(byte *)((int)piVar7 + 0xd5) & 0xbf;
    }
  }
  if ((*(byte *)((int)piVar7 + 0xd5) >> 6 & 1) == 0) {
    uVar4 = FUN_80036e58(8,param_1,0);
  }
  else {
    uVar4 = FUN_8002b9ec();
  }
  *(float *)(param_1 + 0x10) =
       *(float *)(param_1 + 0x10) +
       (float)((double)CONCAT44(0x43300000,DAT_803dc040 ^ 0x80000000) - DOUBLE_803e5490);
  FUN_8003adc4(param_1,uVar4,piVar7 + 0x1d,0x23,1,DAT_803dc03c);
  psVar5 = (short *)FUN_800395d8(param_1,0);
  *(float *)(param_1 + 0x10) =
       *(float *)(param_1 + 0x10) -
       (float)((double)CONCAT44(0x43300000,DAT_803dc040 ^ 0x80000000) - DOUBLE_803e5490);
  if (psVar5 != (short *)0x0) {
    psVar5[1] = psVar5[1] + DAT_803ddbf2;
    *psVar5 = 0;
    *psVar5 = *psVar5 + DAT_803dc044;
  }
  if (iVar2 != 0) {
    *(byte *)((int)piVar7 + 0xd5) = *(byte *)((int)piVar7 + 0xd5) & 0xef;
    sVar6 = FUN_800385e8(param_1,uVar4,0);
    iVar3 = (int)(short)(sVar6 - DAT_803ddbf0);
    iVar2 = iVar3 + -0x8000;
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (iVar2 < 0x18e4) {
      if (*(short *)(param_1 + 0xa0) == 0) {
        iVar2 = FUN_80080100(DAT_803dc048);
        if (iVar2 == 0) {
          iVar2 = FUN_80080100(DAT_803dc04c);
          if (iVar2 != 0) {
            FUN_8000bb18(param_1,0x2f1);
            FUN_80030334((double)FLOAT_803e5460,param_1,0x1a,0);
          }
        }
        else {
          FUN_8000bb18(param_1,0x416);
          FUN_80030334((double)FLOAT_803e5460,param_1,0x1b,0);
        }
      }
      else {
        FUN_80030334((double)FLOAT_803e5460,param_1,0,0);
        FUN_8000b824(param_1,0x2f1);
      }
    }
    else {
      if (iVar3 < 1) {
        if (iVar3 < -0xe38) {
          iVar2 = 0x19;
        }
        else {
          iVar2 = 0x18;
        }
      }
      else if (iVar3 < 0xe39) {
        iVar2 = 0x16;
      }
      else {
        iVar2 = 0x17;
      }
      if (*(short *)(param_1 + 0xa0) != iVar2) {
        FUN_80030334((double)FLOAT_803e5460,param_1,iVar2,0);
      }
    }
  }
  FUN_80038f38(param_1,piVar7 + 5);
  FUN_8003b310(param_1,piVar7 + 0x11);
  iVar2 = FUN_8001ffb4(0x887);
  if (iVar2 == 0) {
    *(undefined *)(piVar7 + 3) = 0;
  }
  if ((*(byte *)((int)piVar7 + 0xd5) >> 4 & 1) != 0) {
    return;
  }
  sVar6 = *(short *)(param_1 + 0xa0);
  if (sVar6 != 0x19) {
    if (0x18 < sVar6) {
      if (sVar6 == 0x1b) {
        if (*(float *)(param_1 + 0x98) <= FLOAT_803e54ac) {
          return;
        }
        FUN_8000bb18(param_1,0x2f4);
        *(byte *)((int)piVar7 + 0xd5) = *(byte *)((int)piVar7 + 0xd5) & 0xef | 0x10;
        return;
      }
      if (0x1a < sVar6) {
        return;
      }
      if (*(float *)(param_1 + 0x98) <= FLOAT_803e54a8) {
        return;
      }
      FUN_8000bb18(param_1,0x417);
      *(byte *)((int)piVar7 + 0xd5) = *(byte *)((int)piVar7 + 0xd5) & 0xef | 0x10;
      return;
    }
    if (sVar6 != 0x17) {
      if ((sVar6 < 0x17) && (sVar6 < 0x16)) {
        return;
      }
      if (*(float *)(param_1 + 0x98) <= FLOAT_803e546c) {
        return;
      }
      FUN_8000bb18(param_1,700);
      *(byte *)((int)piVar7 + 0xd5) = *(byte *)((int)piVar7 + 0xd5) & 0xef | 0x10;
      return;
    }
  }
  if (FLOAT_803e546c < *(float *)(param_1 + 0x98)) {
    FUN_8000bb18(param_1,0x2f1);
    *(byte *)((int)piVar7 + 0xd5) = *(byte *)((int)piVar7 + 0xd5) & 0xef | 0x10;
  }
  return;
}

