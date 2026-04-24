// Function: FUN_80117c74
// Entry: 80117c74
// Size: 932 bytes

void FUN_80117c74(undefined2 *param_1,short *param_2,uint param_3)

{
  ushort uVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  short *psVar5;
  uint uVar6;
  
  if (param_2 == (short *)0x0) {
    if (((DAT_803a5df8 == 0) || (DAT_803a5dfd != '\x02')) || (DAT_803a5dff == '\0')) {
      FUN_800033a8(param_1,0,param_3 << 2);
    }
    else {
      do {
        do {
          if (DAT_803a5e50 == 0) {
            DAT_803a5e50 = FUN_8011730c(0);
            if (DAT_803a5e50 == 0) {
              FUN_800033a8(param_1,0,param_3 << 2);
              return;
            }
            DAT_803a5e48 = *(undefined4 *)(DAT_803a5e50 + 0xc);
          }
          uVar3 = *(uint *)(DAT_803a5e50 + 8);
        } while (uVar3 == 0);
        if (param_3 <= uVar3) {
          uVar3 = param_3;
        }
        psVar5 = *(short **)(DAT_803a5e50 + 4);
        for (uVar6 = uVar3; uVar6 != 0; uVar6 = uVar6 - 1) {
          fVar2 = DAT_803a5e38;
          if (DAT_803a5e40 != 0) {
            DAT_803a5e40 = DAT_803a5e40 + -1;
            fVar2 = DAT_803a5e34 + DAT_803a5e3c;
          }
          DAT_803a5e34 = fVar2;
          uVar1 = *(ushort *)(&DAT_8031a3b0 + (int)DAT_803a5e34 * 2);
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
        *(uint *)(DAT_803a5e50 + 8) = *(int *)(DAT_803a5e50 + 8) - uVar3;
        *(short **)(DAT_803a5e50 + 4) = psVar5;
        if (*(int *)(DAT_803a5e50 + 8) == 0) {
          FUN_80117350();
          DAT_803a5e50 = 0;
        }
      } while (param_3 != 0);
    }
  }
  else if (((DAT_803a5df8 == 0) || (DAT_803a5dfd != '\x02')) || (DAT_803a5dff == '\0')) {
    FUN_80003494(param_1,param_2,param_3 << 2);
  }
  else {
    do {
      do {
        if (DAT_803a5e50 == 0) {
          DAT_803a5e50 = FUN_8011730c(0);
          if (DAT_803a5e50 == 0) {
            FUN_80003494(param_1,param_2,param_3 << 2);
            return;
          }
          DAT_803a5e48 = *(undefined4 *)(DAT_803a5e50 + 0xc);
        }
        uVar3 = *(uint *)(DAT_803a5e50 + 8);
      } while (uVar3 == 0);
      if (param_3 <= uVar3) {
        uVar3 = param_3;
      }
      psVar5 = *(short **)(DAT_803a5e50 + 4);
      for (uVar6 = uVar3; uVar6 != 0; uVar6 = uVar6 - 1) {
        fVar2 = DAT_803a5e38;
        if (DAT_803a5e40 != 0) {
          DAT_803a5e40 = DAT_803a5e40 + -1;
          fVar2 = DAT_803a5e34 + DAT_803a5e3c;
        }
        DAT_803a5e34 = fVar2;
        uVar1 = *(ushort *)(&DAT_8031a3b0 + (int)DAT_803a5e34 * 2);
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
      *(uint *)(DAT_803a5e50 + 8) = *(int *)(DAT_803a5e50 + 8) - uVar3;
      *(short **)(DAT_803a5e50 + 4) = psVar5;
      if (*(int *)(DAT_803a5e50 + 8) == 0) {
        FUN_80117350();
        DAT_803a5e50 = 0;
      }
    } while (param_3 != 0);
  }
  return;
}

