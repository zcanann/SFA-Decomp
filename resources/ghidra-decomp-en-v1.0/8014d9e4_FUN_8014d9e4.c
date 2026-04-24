// Function: FUN_8014d9e4
// Entry: 8014d9e4
// Size: 1932 bytes

void FUN_8014d9e4(undefined2 *param_1,int param_2,int param_3)

{
  short sVar1;
  float fVar2;
  double dVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  char cVar7;
  int *piVar8;
  
  piVar8 = *(int **)(param_1 + 0x5c);
  *(undefined4 *)(param_1 + 0x7a) = 0;
  if (param_3 == 0) {
    if (*(short *)(param_2 + 0x1a) != -1) {
      if (*(short *)(param_2 + 0x18) == -1) {
        uVar6 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1a));
        uVar4 = countLeadingZeros(uVar6);
        *(uint *)(param_1 + 0x7a) = uVar4 >> 5;
      }
      else {
        iVar5 = FUN_8001ffb4();
        if (iVar5 == 0) {
          uVar6 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1a));
          uVar4 = countLeadingZeros(uVar6);
          *(uint *)(param_1 + 0x7a) = uVar4 >> 5;
        }
      }
    }
    if ((*(int *)(param_2 + 0x14) != -1) && (*(int *)(param_1 + 0x7a) == 0)) {
      if (*(short *)(param_2 + 0x18) != -1) {
        uVar6 = FUN_8001ffb4();
        *(undefined4 *)(param_1 + 0x7a) = uVar6;
      }
      if (((*(int *)(param_1 + 0x7a) == 0) && (*(short *)(param_2 + 0x2c) != 0)) &&
         (iVar5 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(param_2 + 0x14)), iVar5 == 0))
      {
        *(undefined4 *)(param_1 + 0x7a) = 1;
      }
    }
  }
  if (*(int *)(param_1 + 0x7a) == 0) {
    param_1[3] = param_1[3] & 0xbfff;
    *(undefined *)(param_1 + 0x1b) = 0xff;
  }
  else {
    param_1[3] = param_1[3] | 0x4000;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  dVar3 = DOUBLE_803e25e0;
  piVar8[0xbf] = (int)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2f)) -
                              DOUBLE_803e25e0) / FLOAT_803e257c);
  piVar8[0xaa] = (int)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x29) << 3) -
                             dVar3);
  piVar8[0xb7] = 0;
  piVar8[0xb8] = piVar8[0xb7];
  *param_1 = (short)((int)*(char *)(param_2 + 0x2a) << 8);
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_2 + 0x10);
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
  if (param_3 != 0) goto LAB_8014e120;
  piVar8[0xb9] = 0;
  piVar8[0xba] = 0;
  *(undefined *)((int)piVar8 + 0x2f1) = 0;
  *(undefined *)((int)piVar8 + 0x2f2) = 0;
  *(undefined2 *)(piVar8 + 0xbb) = 0;
  *(undefined *)((int)piVar8 + 0x2f5) = 0;
  fVar2 = FLOAT_803e2574;
  piVar8[0xc0] = (int)FLOAT_803e2574;
  piVar8[0xc1] = (int)fVar2;
  piVar8[0xc2] = (int)fVar2;
  piVar8[0xc3] = (int)fVar2;
  *(undefined *)((int)piVar8 + 0x323) = 0;
  piVar8[0xc4] = (int)fVar2;
  *(undefined2 *)(piVar8 + 0xbe) = 0;
  *(undefined *)((int)piVar8 + 0x33a) = 0;
  *(undefined *)((int)piVar8 + 0x33b) = 0;
  *(undefined2 *)(piVar8 + 0xce) = 0;
  *(undefined *)(piVar8 + 0xcf) = 0;
  *(undefined *)((int)piVar8 + 0x33d) = 0;
  piVar8[0xc9] = (int)fVar2;
  piVar8[0xca] = (int)fVar2;
  piVar8[0xcb] = (int)fVar2;
  piVar8[0xcc] = (int)fVar2;
  piVar8[0xcd] = (int)fVar2;
  *(undefined2 *)(piVar8 + 0xad) = 0xffff;
  *(undefined2 *)((int)piVar8 + 0x2b6) = *(undefined2 *)(piVar8 + 0xad);
  param_1[0x58] = param_1[0x58] | (short)*(char *)(param_2 + 0x28) & 7U;
  *(ushort *)(piVar8 + 0xac) = (ushort)*(byte *)(param_2 + 0x32);
  *(code **)(param_1 + 0x5e) = FUN_8014be1c;
  sVar1 = param_1[0x23];
  if (sVar1 == 0x4d7) {
    FUN_801568a8(param_1,piVar8);
  }
  else if (sVar1 < 0x4d7) {
    if (sVar1 == 0x281) {
LAB_8014ddb4:
      FUN_801522e0(param_1,piVar8);
    }
    else if (sVar1 < 0x281) {
      if (sVar1 != 0x13a) {
        if (0x139 < sVar1) {
          if (sVar1 == 0x25d) {
            FUN_80155aac(param_1,piVar8);
          }
          else {
            if ((0x25c < sVar1) || (sVar1 != 0x251)) goto LAB_8014dec4;
            FUN_80154c24(param_1,piVar8);
          }
          goto LAB_8014ded0;
        }
        if (sVar1 == 0xd8) goto LAB_8014ddb4;
        if ((0xd7 < sVar1) || (sVar1 != 0x11)) goto LAB_8014dec4;
      }
LAB_8014dda4:
      FUN_80151954(param_1,piVar8);
    }
    else if (sVar1 == 0x427) {
      FUN_8014ff58(param_1,piVar8);
    }
    else if (sVar1 < 0x427) {
      if (sVar1 == 0x3fe) {
LAB_8014dde4:
        FUN_801534d8(param_1,piVar8);
      }
      else {
        if ((0x3fd < sVar1) || (sVar1 != 0x369)) goto LAB_8014dec4;
        FUN_801542ac(param_1,piVar8);
      }
    }
    else if (sVar1 == 0x458) {
      FUN_80156cdc(param_1,piVar8);
    }
    else if (sVar1 < 0x458) {
      if (sVar1 < 0x457) goto LAB_8014dec4;
      FUN_80156188(param_1,piVar8);
    }
    else {
      if (sVar1 != 0x4ac) goto LAB_8014dec4;
      FUN_80157898(param_1,piVar8);
    }
  }
  else {
    if (sVar1 == 0x7a6) goto LAB_8014dda4;
    if (sVar1 < 0x7a6) {
      if (sVar1 == 0x613) {
        FUN_80152a94(param_1,piVar8);
      }
      else if (sVar1 < 0x613) {
        if (sVar1 < 0x5ba) {
          if (sVar1 == 0x58b) {
            FUN_80153c90(param_1,piVar8);
            goto LAB_8014ded0;
          }
          if ((0x58a < sVar1) && (0x5b6 < sVar1)) goto LAB_8014dda4;
        }
        else if (sVar1 == 0x5e1) goto LAB_8014dda4;
LAB_8014dec4:
        FUN_8014ff58(param_1,piVar8);
      }
      else if (sVar1 < 0x6a2) {
        if (sVar1 != 0x642) goto LAB_8014dec4;
        FUN_80152ec0(param_1,piVar8);
      }
      else {
        if (0x6a5 < sVar1) goto LAB_8014dec4;
        FUN_80159654(param_1,piVar8);
      }
    }
    else {
      if (sVar1 != 0x842) {
        if (sVar1 < 0x842) {
          if (sVar1 != 0x7c7) {
            if (sVar1 < 0x7c7) {
              if (0x7c5 < sVar1) goto LAB_8014dde4;
            }
            else if (sVar1 < 0x7c9) {
              FUN_8015a424(param_1,piVar8);
              goto LAB_8014ded0;
            }
          }
        }
        else {
          if (sVar1 == 0x851) {
            FUN_8015ae68(param_1,piVar8);
            goto LAB_8014ded0;
          }
          if ((sVar1 < 0x851) && (sVar1 == 0x84b)) goto LAB_8014de74;
        }
        goto LAB_8014dec4;
      }
LAB_8014de74:
      FUN_8015acc0(param_1,piVar8);
    }
  }
LAB_8014ded0:
  *(undefined2 *)((int)piVar8 + 0x2b2) = *(undefined2 *)(piVar8 + 0xac);
  if (*(short *)(param_2 + 0x34) != 0) {
    piVar8[0xb9] = piVar8[0xb9] & 0xffffffd9;
  }
  FUN_80037200(param_1,3);
  *(undefined *)(piVar8 + 0xbc) = 7;
  *(undefined *)((int)piVar8 + 0x2ef) = 2;
  if (*piVar8 == 0) {
    iVar5 = FUN_80023cc8(0x108,0x1a,0);
    *piVar8 = iVar5;
  }
  if (*piVar8 != 0) {
    FUN_800033a8(*piVar8,0,0x108);
  }
  cVar7 = (**(code **)(*DAT_803dca9c + 0x8c))
                    ((double)(float)piVar8[0xab],*piVar8,param_1,&DAT_803dbc58,0xffffffff);
  if (cVar7 == '\0') {
    piVar8[0xb7] = piVar8[0xb7] | 0x2000;
  }
  (**(code **)(*DAT_803dcaa8 + 4))(piVar8 + 1,0,0x1a6,1);
  if ((piVar8[0xb9] & 8U) != 0) {
    (**(code **)(*DAT_803dcaa8 + 8))(piVar8 + 1,1,&DAT_8031dbe4,&DAT_803dbc64,4);
  }
  if ((piVar8[0xb9] & 4U) != 0) {
    (**(code **)(*DAT_803dcaa8 + 0xc))(piVar8 + 1,1,&DAT_8031dbd8,&DAT_803dbc60,&DAT_803dbc68);
  }
  (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,piVar8 + 1);
  if ((piVar8[0xb9] & 0xcU) != 0) {
    *(undefined *)((int)piVar8 + 0x25f) = 1;
  }
  if (((((piVar8[0xb9] & 0x8000022U) == 0) && (*(short *)(param_2 + 0x34) == 0)) &&
      (param_1[0x23] != 0x3fe)) && (param_1[0x23] != 0x7c6)) {
    piVar8[1] = piVar8[1] & 0xfffbffff;
  }
  else {
    piVar8[1] = piVar8[1] | 0x40000;
  }
  if (((piVar8[0xb9] & 4U) == 0) && ((piVar8[0xb9] & 8U) != 0)) {
    piVar8[1] = piVar8[1] & 0xffffc7ff;
  }
  if (*(int *)(param_1 + 0x7a) == 0) {
    if ((piVar8[0xb9] & 1U) != 0) {
      FUN_80035f20(param_1);
    }
  }
  else {
    piVar8[0xb7] = piVar8[0xb7] | 0x1000;
    piVar8[0xb8] = piVar8[0xb8] & 0xffffefff;
    FUN_80035f00(param_1);
  }
LAB_8014e120:
  piVar8[0xb6] = (int)FLOAT_803e2574;
  if (FLOAT_803e25b0 < (float)piVar8[0xaa]) {
    piVar8[0xaa] = (int)FLOAT_803e25b0;
  }
  if (FLOAT_803e25b0 < (float)piVar8[0xab]) {
    piVar8[0xab] = (int)FLOAT_803e25b0;
  }
  return;
}

