// Function: FUN_8014de78
// Entry: 8014de78
// Size: 1932 bytes

void FUN_8014de78(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,int param_11)

{
  short sVar1;
  float fVar2;
  double dVar3;
  uint uVar4;
  int iVar5;
  char cVar6;
  int *piVar7;
  double dVar8;
  
  piVar7 = *(int **)(param_9 + 0x5c);
  *(undefined4 *)(param_9 + 0x7a) = 0;
  if (param_11 == 0) {
    if ((int)*(short *)(param_10 + 0x1a) != 0xffffffff) {
      if ((int)*(short *)(param_10 + 0x18) == 0xffffffff) {
        uVar4 = FUN_80020078((int)*(short *)(param_10 + 0x1a));
        uVar4 = countLeadingZeros(uVar4);
        *(uint *)(param_9 + 0x7a) = uVar4 >> 5;
      }
      else {
        uVar4 = FUN_80020078((int)*(short *)(param_10 + 0x18));
        if (uVar4 == 0) {
          uVar4 = FUN_80020078((int)*(short *)(param_10 + 0x1a));
          uVar4 = countLeadingZeros(uVar4);
          *(uint *)(param_9 + 0x7a) = uVar4 >> 5;
        }
      }
    }
    if ((*(int *)(param_10 + 0x14) != -1) && (*(int *)(param_9 + 0x7a) == 0)) {
      if ((int)*(short *)(param_10 + 0x18) != 0xffffffff) {
        uVar4 = FUN_80020078((int)*(short *)(param_10 + 0x18));
        *(uint *)(param_9 + 0x7a) = uVar4;
      }
      if (((*(int *)(param_9 + 0x7a) == 0) && (*(short *)(param_10 + 0x2c) != 0)) &&
         (iVar5 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(param_10 + 0x14)), iVar5 == 0)
         ) {
        *(undefined4 *)(param_9 + 0x7a) = 1;
      }
    }
  }
  if (*(int *)(param_9 + 0x7a) == 0) {
    param_9[3] = param_9[3] & 0xbfff;
    *(undefined *)(param_9 + 0x1b) = 0xff;
  }
  else {
    param_9[3] = param_9[3] | 0x4000;
    *(undefined *)(param_9 + 0x1b) = 0;
  }
  dVar3 = DOUBLE_803e3278;
  dVar8 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_10 + 0x2f)) -
                         DOUBLE_803e3278);
  piVar7[0xbf] = (int)(float)(dVar8 / (double)FLOAT_803e3210);
  piVar7[0xaa] = (int)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_10 + 0x29) << 3) -
                             dVar3);
  piVar7[0xb7] = 0;
  piVar7[0xb8] = piVar7[0xb7];
  *param_9 = (short)((int)*(char *)(param_10 + 0x2a) << 8);
  *(undefined4 *)(param_9 + 6) = *(undefined4 *)(param_10 + 8);
  *(undefined4 *)(param_9 + 8) = *(undefined4 *)(param_10 + 0xc);
  *(undefined4 *)(param_9 + 10) = *(undefined4 *)(param_10 + 0x10);
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
  if (param_11 != 0) goto LAB_8014e5b4;
  piVar7[0xb9] = 0;
  piVar7[0xba] = 0;
  *(undefined *)((int)piVar7 + 0x2f1) = 0;
  *(undefined *)((int)piVar7 + 0x2f2) = 0;
  *(undefined2 *)(piVar7 + 0xbb) = 0;
  *(undefined *)((int)piVar7 + 0x2f5) = 0;
  fVar2 = FLOAT_803e31fc;
  piVar7[0xc0] = (int)FLOAT_803e31fc;
  piVar7[0xc1] = (int)fVar2;
  piVar7[0xc2] = (int)fVar2;
  piVar7[0xc3] = (int)fVar2;
  *(undefined *)((int)piVar7 + 0x323) = 0;
  piVar7[0xc4] = (int)fVar2;
  *(undefined2 *)(piVar7 + 0xbe) = 0;
  *(undefined *)((int)piVar7 + 0x33a) = 0;
  *(undefined *)((int)piVar7 + 0x33b) = 0;
  *(undefined2 *)(piVar7 + 0xce) = 0;
  *(undefined *)(piVar7 + 0xcf) = 0;
  *(undefined *)((int)piVar7 + 0x33d) = 0;
  piVar7[0xc9] = (int)fVar2;
  piVar7[0xca] = (int)fVar2;
  piVar7[0xcb] = (int)fVar2;
  piVar7[0xcc] = (int)fVar2;
  piVar7[0xcd] = (int)fVar2;
  *(undefined2 *)(piVar7 + 0xad) = 0xffff;
  *(undefined2 *)((int)piVar7 + 0x2b6) = *(undefined2 *)(piVar7 + 0xad);
  param_9[0x58] = param_9[0x58] | (short)*(char *)(param_10 + 0x28) & 7U;
  *(ushort *)(piVar7 + 0xac) = (ushort)*(byte *)(param_10 + 0x32);
  *(code **)(param_9 + 0x5e) = FUN_8014c294;
  sVar1 = param_9[0x23];
  if (sVar1 == 0x4d7) {
    FUN_80156d54(param_9,(int)piVar7);
  }
  else if (sVar1 < 0x4d7) {
    if (sVar1 == 0x281) {
LAB_8014e248:
      FUN_8015278c((int)param_9,(int)piVar7);
    }
    else if (sVar1 < 0x281) {
      if (sVar1 != 0x13a) {
        if (0x139 < sVar1) {
          if (sVar1 == 0x25d) {
            FUN_80155f58(param_9,(int)piVar7);
          }
          else {
            if ((0x25c < sVar1) || (sVar1 != 0x251)) goto LAB_8014e358;
            FUN_801550d0((int)param_9,(int)piVar7);
          }
          goto LAB_8014e364;
        }
        if (sVar1 == 0xd8) goto LAB_8014e248;
        if ((0xd7 < sVar1) || (sVar1 != 0x11)) goto LAB_8014e358;
      }
LAB_8014e238:
      FUN_80151de8((int)param_9,(int)piVar7);
    }
    else if (sVar1 == 0x427) {
      FUN_801503ec(param_9,(int)piVar7);
    }
    else if (sVar1 < 0x427) {
      if (sVar1 == 0x3fe) {
LAB_8014e278:
        FUN_80153984((int)param_9,(int)piVar7);
      }
      else {
        if ((0x3fd < sVar1) || (sVar1 != 0x369)) goto LAB_8014e358;
        FUN_80154758(param_9,(int)piVar7);
      }
    }
    else if (sVar1 == 0x458) {
      FUN_80157188(param_9,(int)piVar7);
    }
    else if (sVar1 < 0x458) {
      if (sVar1 < 0x457) goto LAB_8014e358;
      FUN_80156634(param_9,(int)piVar7);
    }
    else {
      if (sVar1 != 0x4ac) goto LAB_8014e358;
      FUN_80157d44((int)param_9,(int)piVar7);
    }
  }
  else {
    if (sVar1 == 0x7a6) goto LAB_8014e238;
    if (sVar1 < 0x7a6) {
      if (sVar1 == 0x613) {
        FUN_80152f40((uint)param_9,(int)piVar7);
      }
      else if (sVar1 < 0x613) {
        if (sVar1 < 0x5ba) {
          if (sVar1 == 0x58b) {
            FUN_8015413c(param_9,(int)piVar7);
            goto LAB_8014e364;
          }
          if ((0x58a < sVar1) && (0x5b6 < sVar1)) goto LAB_8014e238;
        }
        else if (sVar1 == 0x5e1) goto LAB_8014e238;
LAB_8014e358:
        FUN_801503ec(param_9,(int)piVar7);
      }
      else if (sVar1 < 0x6a2) {
        if (sVar1 != 0x642) goto LAB_8014e358;
        FUN_8015336c((int)param_9,(int)piVar7);
      }
      else {
        if (0x6a5 < sVar1) goto LAB_8014e358;
        FUN_80159b00((int)param_9,(int)piVar7);
      }
    }
    else {
      if (sVar1 != 0x842) {
        if (sVar1 < 0x842) {
          if (sVar1 != 0x7c7) {
            if (sVar1 < 0x7c7) {
              if (0x7c5 < sVar1) goto LAB_8014e278;
            }
            else if (sVar1 < 0x7c9) {
              FUN_8015a8d0(dVar8,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                           (int)piVar7);
              goto LAB_8014e364;
            }
          }
        }
        else {
          if (sVar1 == 0x851) {
            FUN_8015b314((int)param_9,(int)piVar7);
            goto LAB_8014e364;
          }
          if ((sVar1 < 0x851) && (sVar1 == 0x84b)) goto LAB_8014e308;
        }
        goto LAB_8014e358;
      }
LAB_8014e308:
      FUN_8015b16c((int)param_9,(int)piVar7);
    }
  }
LAB_8014e364:
  *(undefined2 *)((int)piVar7 + 0x2b2) = *(undefined2 *)(piVar7 + 0xac);
  if (*(short *)(param_10 + 0x34) != 0) {
    piVar7[0xb9] = piVar7[0xb9] & 0xffffffd9;
  }
  FUN_800372f8((int)param_9,3);
  *(undefined *)(piVar7 + 0xbc) = 7;
  *(undefined *)((int)piVar7 + 0x2ef) = 2;
  if (*piVar7 == 0) {
    iVar5 = FUN_80023d8c(0x108,0x1a);
    *piVar7 = iVar5;
  }
  if (*piVar7 != 0) {
    FUN_800033a8(*piVar7,0,0x108);
  }
  cVar6 = (**(code **)(*DAT_803dd71c + 0x8c))
                    ((double)(float)piVar7[0xab],*piVar7,param_9,&DAT_803dc8c0,0xffffffff);
  if (cVar6 == '\0') {
    piVar7[0xb7] = piVar7[0xb7] | 0x2000;
  }
  (**(code **)(*DAT_803dd728 + 4))(piVar7 + 1,0,0x1a6,1);
  if ((piVar7[0xb9] & 8U) != 0) {
    (**(code **)(*DAT_803dd728 + 8))(piVar7 + 1,1,&DAT_8031e834,&DAT_803dc8cc,4);
  }
  if ((piVar7[0xb9] & 4U) != 0) {
    (**(code **)(*DAT_803dd728 + 0xc))(piVar7 + 1,1,&DAT_8031e828,&DAT_803dc8c8,&DAT_803dc8d0);
  }
  (**(code **)(*DAT_803dd728 + 0x20))(param_9,piVar7 + 1);
  if ((piVar7[0xb9] & 0xcU) != 0) {
    *(undefined *)((int)piVar7 + 0x25f) = 1;
  }
  if (((((piVar7[0xb9] & 0x8000022U) == 0) && (*(short *)(param_10 + 0x34) == 0)) &&
      (param_9[0x23] != 0x3fe)) && (param_9[0x23] != 0x7c6)) {
    piVar7[1] = piVar7[1] & 0xfffbffff;
  }
  else {
    piVar7[1] = piVar7[1] | 0x40000;
  }
  if (((piVar7[0xb9] & 4U) == 0) && ((piVar7[0xb9] & 8U) != 0)) {
    piVar7[1] = piVar7[1] & 0xffffc7ff;
  }
  if (*(int *)(param_9 + 0x7a) == 0) {
    if ((piVar7[0xb9] & 1U) != 0) {
      FUN_80036018((int)param_9);
    }
  }
  else {
    piVar7[0xb7] = piVar7[0xb7] | 0x1000;
    piVar7[0xb8] = piVar7[0xb8] & 0xffffefff;
    FUN_80035ff8((int)param_9);
  }
LAB_8014e5b4:
  piVar7[0xb6] = (int)FLOAT_803e31fc;
  if (FLOAT_803e3244 < (float)piVar7[0xaa]) {
    piVar7[0xaa] = (int)FLOAT_803e3244;
  }
  if (FLOAT_803e3244 < (float)piVar7[0xab]) {
    piVar7[0xab] = (int)FLOAT_803e3244;
  }
  return;
}

