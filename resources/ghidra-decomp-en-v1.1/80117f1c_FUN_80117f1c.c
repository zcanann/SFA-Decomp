// Function: FUN_80117f1c
// Entry: 80117f1c
// Size: 932 bytes

void FUN_80117f1c(undefined2 *param_1,short *param_2,uint param_3)

{
  ushort uVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  short *psVar5;
  uint uVar6;
  
  if (param_2 == (short *)0x0) {
    if (((DAT_803a6a58 == 0) || (DAT_803a6a5d != '\x02')) || (DAT_803a6a5f == '\0')) {
      FUN_800033a8((int)param_1,0,param_3 << 2);
    }
    else {
      do {
        do {
          if (DAT_803a6ab0 == 0) {
            DAT_803a6ab0 = FUN_801175b4(0);
            if (DAT_803a6ab0 == 0) {
              FUN_800033a8((int)param_1,0,param_3 << 2);
              return;
            }
            DAT_803a6aa8 = *(undefined4 *)(DAT_803a6ab0 + 0xc);
          }
          uVar3 = *(uint *)(DAT_803a6ab0 + 8);
        } while (uVar3 == 0);
        if (param_3 <= uVar3) {
          uVar3 = param_3;
        }
        psVar5 = *(short **)(DAT_803a6ab0 + 4);
        for (uVar6 = uVar3; uVar6 != 0; uVar6 = uVar6 - 1) {
          fVar2 = DAT_803a6a98;
          if (DAT_803a6aa0 != 0) {
            DAT_803a6aa0 = DAT_803a6aa0 + -1;
            fVar2 = DAT_803a6a94 + DAT_803a6a9c;
          }
          DAT_803a6a94 = fVar2;
          uVar1 = *(ushort *)(&DAT_8031b000 + (int)DAT_803a6a94 * 2);
          iVar4 = (int)((uint)uVar1 * (int)*psVar5) >> 0xf;
          if (iVar4 < -0x8000) {
            iVar4 = -0x8000;
          }
          if (0x7fff < iVar4) {
            iVar4 = 0x7fff;
          }
          *param_1 = (short)iVar4;
          iVar4 = (int)((uint)uVar1 * (int)psVar5[1]) >> 0xf;
          if (iVar4 < -0x8000) {
            iVar4 = -0x8000;
          }
          if (0x7fff < iVar4) {
            iVar4 = 0x7fff;
          }
          param_1[1] = (short)iVar4;
          param_1 = param_1 + 2;
          psVar5 = psVar5 + 2;
        }
        param_3 = param_3 - uVar3;
        *(uint *)(DAT_803a6ab0 + 8) = *(int *)(DAT_803a6ab0 + 8) - uVar3;
        *(short **)(DAT_803a6ab0 + 4) = psVar5;
        if (*(int *)(DAT_803a6ab0 + 8) == 0) {
          FUN_801175f8(DAT_803a6ab0);
          DAT_803a6ab0 = 0;
        }
      } while (param_3 != 0);
    }
  }
  else if (((DAT_803a6a58 == 0) || (DAT_803a6a5d != '\x02')) || (DAT_803a6a5f == '\0')) {
    FUN_80003494((uint)param_1,(uint)param_2,param_3 << 2);
  }
  else {
    do {
      do {
        if (DAT_803a6ab0 == 0) {
          DAT_803a6ab0 = FUN_801175b4(0);
          if (DAT_803a6ab0 == 0) {
            FUN_80003494((uint)param_1,(uint)param_2,param_3 << 2);
            return;
          }
          DAT_803a6aa8 = *(undefined4 *)(DAT_803a6ab0 + 0xc);
        }
        uVar3 = *(uint *)(DAT_803a6ab0 + 8);
      } while (uVar3 == 0);
      if (param_3 <= uVar3) {
        uVar3 = param_3;
      }
      psVar5 = *(short **)(DAT_803a6ab0 + 4);
      for (uVar6 = uVar3; uVar6 != 0; uVar6 = uVar6 - 1) {
        fVar2 = DAT_803a6a98;
        if (DAT_803a6aa0 != 0) {
          DAT_803a6aa0 = DAT_803a6aa0 + -1;
          fVar2 = DAT_803a6a94 + DAT_803a6a9c;
        }
        DAT_803a6a94 = fVar2;
        uVar1 = *(ushort *)(&DAT_8031b000 + (int)DAT_803a6a94 * 2);
        iVar4 = (int)*param_2 + ((int)((uint)uVar1 * (int)*psVar5) >> 0xf);
        if (iVar4 < -0x8000) {
          iVar4 = -0x8000;
        }
        if (0x7fff < iVar4) {
          iVar4 = 0x7fff;
        }
        *param_1 = (short)iVar4;
        iVar4 = (int)param_2[1] + ((int)((uint)uVar1 * (int)psVar5[1]) >> 0xf);
        if (iVar4 < -0x8000) {
          iVar4 = -0x8000;
        }
        if (0x7fff < iVar4) {
          iVar4 = 0x7fff;
        }
        param_1[1] = (short)iVar4;
        param_1 = param_1 + 2;
        param_2 = param_2 + 2;
        psVar5 = psVar5 + 2;
      }
      param_3 = param_3 - uVar3;
      *(uint *)(DAT_803a6ab0 + 8) = *(int *)(DAT_803a6ab0 + 8) - uVar3;
      *(short **)(DAT_803a6ab0 + 4) = psVar5;
      if (*(int *)(DAT_803a6ab0 + 8) == 0) {
        FUN_801175f8(DAT_803a6ab0);
        DAT_803a6ab0 = 0;
      }
    } while (param_3 != 0);
  }
  return;
}

