// Function: FUN_8018d8dc
// Entry: 8018d8dc
// Size: 1992 bytes

void FUN_8018d8dc(short *param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int *piVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  double local_28;
  double local_20;
  
  FUN_8002b9ec();
  iVar8 = *(int *)(param_1 + 0x5c);
  iVar4 = FUN_8000faac();
  iVar7 = *(int *)(param_1 + 0x26);
  sVar6 = param_1[0x23];
  if (sVar6 == 0x6b4) {
    FUN_8002fa48((double)FLOAT_803e3df8,(double)FLOAT_803db414,param_1,0);
  }
  else if (sVar6 < 0x6b4) {
    if (sVar6 == 0x409) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    }
    else if (sVar6 < 0x409) {
      if (sVar6 == 0x10d) {
        *(ushort *)(iVar8 + 0x3c) = *(short *)(iVar8 + 0x3c) - (ushort)DAT_803db410;
        if (*(short *)(iVar8 + 0x3c) < 0) {
          iVar4 = FUN_800221a0(0,*(byte *)(iVar8 + 0x40) - 1);
          FUN_8000bb18(param_1,*(undefined2 *)(*(int *)(iVar8 + 0x44) + iVar4 * 2));
          *(undefined2 *)(iVar8 + 0x3c) = *(undefined2 *)(iVar8 + 0x48);
          sVar6 = FUN_800221a0(0,*(undefined2 *)(iVar8 + 0x48));
          *(short *)(iVar8 + 0x3c) = *(short *)(iVar8 + 0x3c) + sVar6;
        }
      }
      else if (sVar6 < 0x10d) {
        if (sVar6 == 0x8e) {
          *(float *)(iVar8 + 0x14) =
               FLOAT_803e3e04 * *(float *)(iVar8 + 0x1c) + *(float *)(iVar8 + 0x14);
          if ((FLOAT_803e3e08 < *(float *)(iVar8 + 0x14)) ||
             (*(float *)(iVar8 + 0x14) < FLOAT_803e3e0c)) {
            *(float *)(iVar8 + 0x1c) = -*(float *)(iVar8 + 0x1c);
          }
          if ((FLOAT_803e3e10 < *(float *)(iVar8 + 0x18)) ||
             (*(float *)(iVar8 + 0x18) < FLOAT_803e3e14)) {
            *(float *)(iVar8 + 0x24) = -*(float *)(iVar8 + 0x24);
          }
          *(float *)(iVar8 + 0x18) =
               FLOAT_803e3e04 * *(float *)(iVar8 + 0x24) + *(float *)(iVar8 + 0x18);
        }
      }
      else if (sVar6 == 0x125) {
        local_20 = (double)CONCAT44(0x43300000,-(int)*(short *)(iVar4 + 4) ^ 0x80000000);
        param_1[2] = (short)(int)(DOUBLE_803e3e18 * (local_20 - DOUBLE_803e3e28));
        iVar4 = FUN_8002b9ec();
        fVar1 = *(float *)(iVar4 + 0x18) - *(float *)(param_1 + 0xc);
        fVar2 = *(float *)(iVar4 + 0x20) - *(float *)(param_1 + 0x10);
        fVar3 = *(float *)(iVar4 + 0x1c) - *(float *)(param_1 + 0xe);
        dVar9 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
        if (((double)FLOAT_803e3e20 <= dVar9) || (*(char *)(iVar8 + 0x3f) != '\x01')) {
          if (((double)FLOAT_803e3e20 < dVar9) && (*(char *)(iVar8 + 0x3f) == '\0')) {
            *(undefined *)(iVar8 + 0x3f) = 1;
            FUN_800066e0(param_1,param_1,0x5d,0,0,0);
          }
        }
        else {
          *(undefined *)(iVar8 + 0x3f) = 0;
          FUN_800066e0(param_1,param_1,0x5c,0,0,0);
        }
      }
    }
    else if (sVar6 == 0x622) {
      piVar5 = (int *)FUN_800394ac(param_1,0,0);
      if (((piVar5 != (int *)0x0) &&
          (iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x38)), iVar4 != 0)) && (*piVar5 == 0)) {
        FUN_8000bb18(param_1,0x3c4);
        *piVar5 = 0x100;
      }
    }
    else if (sVar6 < 0x622) {
      if (((sVar6 == 0x4bf) && (*(float *)(param_1 + 8) < FLOAT_803e3dfc + *(float *)(iVar7 + 0xc)))
         && (iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x38)), iVar4 != 0)) {
        *(float *)(param_1 + 8) = *(float *)(param_1 + 8) + FLOAT_803db414;
      }
    }
    else if (sVar6 == 0x65d) {
      FUN_8002fa48((double)FLOAT_803e3df8,(double)FLOAT_803db414,param_1,0);
    }
  }
  else if (sVar6 == 0x71b) {
    *(ushort *)(iVar8 + 0x36) = *(short *)(iVar8 + 0x36) - (ushort)DAT_803db410;
    FUN_80035df4(param_1,0x13,1,0);
    if (*(short *)(iVar8 + 0x36) < 1) {
      FUN_8002cbc4(param_1);
    }
    else {
      *(float *)(param_1 + 8) =
           (float)-(DOUBLE_803e3de0 * (double)FLOAT_803db414 - (double)*(float *)(param_1 + 8));
    }
  }
  else if (sVar6 < 0x71b) {
    if (sVar6 == 0x6fd) {
      iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x38));
      if (iVar4 == 0) {
        *param_1 = *param_1 + (short)(int)(FLOAT_803e3df0 * FLOAT_803db414);
        param_1[2] = param_1[2] + (short)(int)(FLOAT_803e3df4 * FLOAT_803db414);
      }
      else {
        *param_1 = *param_1 + (short)(int)(FLOAT_803e3df0 * FLOAT_803db414);
        param_1[2] = param_1[2] + (short)(int)(FLOAT_803e3df4 * FLOAT_803db414);
      }
    }
    else if (sVar6 < 0x6fd) {
      if (sVar6 == 0x6be) {
        iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x3a));
        if ((iVar4 != 0) && (*(char *)(iVar8 + 0x3e) == '\0')) {
          *(undefined *)(iVar8 + 0x3e) = 1;
          (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
        }
      }
      else if ((((0x6bd < sVar6) && (0x6fb < sVar6)) &&
               (iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x38)), fVar1 = FLOAT_803e3de8,
               iVar4 != 0)) &&
              ((*(float *)(param_1 + 8) <= FLOAT_803e3de8 + *(float *)(iVar7 + 0xc) &&
               (*(float *)(param_1 + 8) = FLOAT_803e3dec * FLOAT_803db414 + *(float *)(param_1 + 8),
               fVar1 + *(float *)(iVar7 + 0xc) <= *(float *)(param_1 + 8))))) {
        FUN_800200e8((int)*(short *)(iVar8 + 0x38),0);
      }
    }
    else if (sVar6 == 0x708) {
      iVar4 = FUN_8003687c(param_1,0,0,0);
      if (iVar4 != 0) {
        FUN_800200e8((int)*(short *)(iVar8 + 0x38),1);
      }
      iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x38));
      if (iVar4 == 0) {
        *param_1 = *param_1 + (short)*(char *)(iVar7 + 0x18) * (ushort)DAT_803db410;
      }
    }
    else if ((sVar6 < 0x708) && (sVar6 < 0x6ff)) {
      iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x38));
      if (iVar4 == 0) {
        param_1[1] = param_1[1] + (short)(int)(FLOAT_803e3df0 * FLOAT_803db414);
        param_1[2] = param_1[2] + (short)(int)(FLOAT_803e3df4 * FLOAT_803db414);
      }
      else {
        param_1[1] = param_1[1] + (short)(int)(FLOAT_803e3df0 * FLOAT_803db414);
        param_1[2] = param_1[2] + (short)(int)(FLOAT_803e3df4 * FLOAT_803db414);
      }
    }
  }
  else if (sVar6 == 0x7de) {
    iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x38));
    if (iVar4 == 0) {
      local_20 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
      param_1[2] = (short)(int)(FLOAT_803db414 * *(float *)(iVar8 + 0x24) +
                               (float)(local_20 - DOUBLE_803e3e28));
    }
    else {
      local_28 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
      param_1[2] = (short)(int)-(FLOAT_803db414 * *(float *)(iVar8 + 0x24) -
                                (float)(local_28 - DOUBLE_803e3e28));
    }
  }
  else if (sVar6 < 0x7de) {
    if ((sVar6 == 0x729) && (iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x38)), iVar4 == 0)) {
      param_1[1] = param_1[1] + (ushort)DAT_803db410 * 100;
    }
  }
  else if (((sVar6 == 0x828) && (iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x3a)), iVar4 != 0))
          && (*(char *)(iVar8 + 0x3e) == '\0')) {
    iVar4 = (int)param_1[2] + (int)(FLOAT_803e3e00 * FLOAT_803db414);
    if (iVar4 < 0x8000) {
      param_1[2] = (short)iVar4;
    }
    else {
      *(undefined *)(iVar8 + 0x3e) = 1;
      param_1[2] = 0x7fff;
    }
  }
  return;
}

