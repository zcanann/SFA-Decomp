// Function: FUN_8022f5c4
// Entry: 8022f5c4
// Size: 1044 bytes

void FUN_8022f5c4(short *param_1)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  bool bVar6;
  int local_38 [2];
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  iVar3 = FUN_8022d768();
  fVar2 = FLOAT_803e707c;
  pfVar5 = *(float **)(param_1 + 0x5c);
  if ((*pfVar5 <= FLOAT_803e707c) || (*pfVar5 = *pfVar5 - FLOAT_803db414, fVar2 < *pfVar5)) {
    if ((iVar3 == 0) || (iVar4 = FUN_8022d710(iVar3), iVar4 == 0)) {
      if (-1 < *(char *)(pfVar5 + 1)) {
        iVar4 = FUN_8022d768();
        if (iVar4 == 0) {
          bVar6 = false;
        }
        else {
          bVar6 = *(float *)(param_1 + 10) - *(float *)(iVar4 + 0x14) < FLOAT_803e7080;
        }
        if (bVar6) {
          uStack44 = (uint)*(byte *)(param_1 + 0x1b);
          local_30 = 0x43300000;
          iVar4 = (int)(FLOAT_803e7084 * FLOAT_803db414 +
                       (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e7090));
          local_28 = (longlong)iVar4;
          if (0xff < iVar4) {
            iVar4 = 0xff;
          }
          *(char *)(param_1 + 0x1b) = (char)iVar4;
          param_1[3] = param_1[3] & 0xbfff;
          uStack28 = (int)*param_1 ^ 0x80000000;
          local_20 = 0x43300000;
          iVar4 = (int)(FLOAT_803e7088 * FLOAT_803db414 +
                       (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e7070));
          local_18 = (longlong)iVar4;
          *param_1 = (short)iVar4;
          FUN_80035df4(param_1,0x13,0,0);
          if ((*(byte *)(pfVar5 + 1) >> 6 & 1) == 0) {
            iVar4 = FUN_8003687c(param_1,local_38,0,0);
            if (((iVar4 != 0) && (local_38[0] != 0)) &&
               ((*(short *)(local_38[0] + 0x46) == 0x604 ||
                (*(short *)(local_38[0] + 0x46) == 0x605)))) {
              FUN_8022d520(iVar3,0xf);
              *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) & 0xbf | 0x40;
              FUN_8002b884(param_1,1);
              FUN_8009ab70((double)FLOAT_803e708c,param_1,1,0,0,0,0,0,2);
            }
            if ((*(int *)(*(int *)(param_1 + 0x2a) + 0x50) != 0) &&
               (iVar4 = FUN_8022d768(), *(int *)(*(int *)(param_1 + 0x2a) + 0x50) == iVar4)) {
              param_1[3] = param_1[3] | 0x4000;
              FUN_80035f00(param_1);
              FUN_8009ab70((double)FLOAT_803e708c,param_1,1,0,0,0,0,0,2);
            }
          }
          else if ((*(int *)(*(int *)(param_1 + 0x2a) + 0x50) != 0) &&
                  (iVar4 = FUN_8022d768(), *(int *)(*(int *)(param_1 + 0x2a) + 0x50) == iVar4)) {
            FUN_8022d520(iVar3,0x19);
            *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) & 0x7f | 0x80;
            param_1[3] = param_1[3] | 0x4000;
            FUN_80035f00(param_1);
          }
          if (iVar3 == 0) {
            return;
          }
          if (-1 < *(char *)(pfVar5 + 1)) {
            return;
          }
          sVar1 = param_1[0x23];
          if (sVar1 == 0x6d8) {
            FUN_8000bb18(param_1,0x2a8);
            FUN_8022d5dc(iVar3);
            return;
          }
          if (0x6d7 < sVar1) {
            if (sVar1 == 0x6db) {
              FUN_8000bb18(param_1,0x2a8);
              FUN_8022d5b4(iVar3);
              return;
            }
            if (0x6da < sVar1) {
              return;
            }
            if (sVar1 < 0x6da) {
              FUN_8000bb18(param_1,0x2a8);
              FUN_8022d5c8(iVar3);
              return;
            }
            FUN_8000bb18(param_1,0x2a8);
            FUN_8022d5a0(iVar3);
            return;
          }
          if (sVar1 == 0x609) {
            FUN_8000bb18(param_1,0x2a6);
            FUN_8022d6f0(iVar3);
            return;
          }
          if (0x608 < sVar1) {
            return;
          }
          if (sVar1 < 0x608) {
            return;
          }
          FUN_8000bb18(param_1,0x2a7);
          FUN_8022d6d0(iVar3);
          return;
        }
      }
      param_1[3] = param_1[3] | 0x4000;
      *(undefined *)(param_1 + 0x1b) = 0;
    }
    else {
      *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) & 0x7f;
      param_1[3] = param_1[3] & 0xbfff;
      FUN_80035f20(param_1);
    }
  }
  else {
    FUN_8002cbc4(param_1);
  }
  return;
}

