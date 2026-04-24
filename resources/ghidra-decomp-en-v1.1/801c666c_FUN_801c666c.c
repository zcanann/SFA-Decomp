// Function: FUN_801c666c
// Entry: 801c666c
// Size: 3104 bytes

void FUN_801c666c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  short sVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar12;
  undefined8 uVar13;
  uint uStack_38;
  uint auStack_34 [3];
  undefined4 local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  iVar12 = *(int *)(param_9 + 0x5c);
  iVar9 = FUN_8002bac4();
  auStack_34[2] = DAT_803e90f0;
  local_28 = DAT_803e90f4;
  if (*(char *)(iVar12 + 0x32) == '\0') {
    uVar10 = FUN_80020078(0x58b);
    *(char *)(iVar12 + 0x32) = (char)uVar10;
    if (*(char *)(iVar12 + 0x32) != '\0') {
      in_r7 = *DAT_803dd6e8;
      (**(code **)(in_r7 + 0x38))(0x285,0x14,0x8c,1);
    }
  }
  if ((*(int *)(param_9 + 0x7a) != 0) &&
     (*(int *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) + -1, *(int *)(param_9 + 0x7a) == 0)) {
    uVar13 = FUN_80088f20(7,'\x01');
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                          iVar9,0x221,0,in_r7,in_r8,in_r9,in_r10);
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                          iVar9,0x220,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar9,0x222,
                 0,in_r7,in_r8,in_r9,in_r10);
  }
  FUN_801c5f44(param_9);
  if ((iVar9 != 0) && (uVar10 = FUN_80296328(iVar9), uVar10 == 0)) {
    FUN_80296454(iVar9,0);
  }
  auStack_34[1] = 0;
  do {
    iVar11 = FUN_800375e4((int)param_9,auStack_34,&uStack_38,auStack_34 + 1);
  } while (iVar11 != 0);
  FUN_801d84c4(iVar12 + 0x34,2,-1,-1,0xb9d,(int *)0xd);
  FUN_801d8650(iVar12 + 0x34,1,-1,-1,0xcbb,(int *)0x8);
  FUN_801d84c4(iVar12 + 0x34,0x10,-1,-1,0xcbb,(int *)0xc4);
  fVar2 = FLOAT_803e5c64;
  if (*(float *)(iVar12 + 8) <= FLOAT_803e5c64) {
    switch(*(undefined *)(iVar12 + 0x2f)) {
    case 0:
      param_9[3] = param_9[3] & 0xbfff;
      fVar1 = *(float *)(iVar12 + 0x10) - FLOAT_803dc074;
      *(float *)(iVar12 + 0x10) = fVar1;
      if (fVar1 <= fVar2) {
        FUN_8000bb38((uint)param_9,0x343);
        uStack_1c = FUN_80022264(500,1000);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        *(float *)(iVar12 + 0x10) =
             (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5c58);
      }
      if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
        *(undefined *)(iVar12 + 0x2f) = 1;
        FUN_800201ac(0x129,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
        FUN_8000a538((int *)0xd8,1);
        DAT_80326e48 = FLOAT_803e5c64;
        DAT_80326e4c = FLOAT_803e5c64;
        DAT_80326e50 = FLOAT_803e5c64;
        DAT_80326e54 = FLOAT_803e5c64;
        DAT_80326e58 = FLOAT_803e5c64;
        DAT_80326e5c = FLOAT_803e5c64;
        DAT_80326e60 = FLOAT_803e5c64;
        DAT_80326e64 = FLOAT_803e5c64;
        DAT_80326e68 = FLOAT_803e5c64;
        DAT_80326e6c = FLOAT_803e5c64;
        DAT_80326e70 = FLOAT_803e5c64;
        DAT_80326e74 = FLOAT_803e5c64;
        DAT_80326e78 = DAT_80326e84;
        DAT_80326e7a = DAT_80326e86;
        DAT_80326e7c = DAT_80326e88;
        DAT_80326e7e = DAT_80326e8a;
        DAT_80326e80 = DAT_80326e8c;
        DAT_80326e82 = DAT_80326e8e;
        DAT_80326e84 = DAT_80326e90;
      }
      break;
    case 1:
      if (*(char *)(iVar12 + 0x30) == '\x01') {
        *(undefined *)(iVar12 + 0x2f) = 2;
        *(float *)(iVar12 + 8) = FLOAT_803e5c68;
        *(undefined2 *)(iVar12 + 0x24) = 6;
        FUN_8000bb38((uint)param_9,0x16f);
        *(float *)(iVar12 + 4) = FLOAT_803e5c64;
        FUN_800201ac(0xb9d,1);
        (**(code **)(*DAT_803dd6cc + 0xc))(0x78,1);
      }
      param_9[3] = param_9[3] | 0x4000;
      break;
    case 2:
      *(undefined *)(iVar12 + 0x2f) = 3;
      *(float *)(iVar12 + 8) = FLOAT_803e5c6c;
      *(undefined2 *)(iVar12 + 0x24) = 8;
      *(float *)(iVar12 + 4) = FLOAT_803e5c70;
      *(undefined2 *)(iVar12 + 0x22) = 5;
      uVar10 = FUN_80022264(0,5);
      *(char *)(iVar12 + 0x2e) = (char)uVar10;
      (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_9,0xffffffff);
      break;
    case 3:
    case 4:
    case 5:
      if (*(float *)(iVar12 + 4) <= FLOAT_803e5c64) {
        switch(*(undefined2 *)(iVar12 + 0x24)) {
        case 0:
          *(undefined2 *)(iVar12 + 0x24) = 1;
          *(float *)(iVar12 + 4) = FLOAT_803e5c7c;
          break;
        case 1:
          *(undefined2 *)(iVar12 + 0x24) = 4;
          *(float *)(iVar12 + 4) = fVar2;
          break;
        case 2:
          *(short *)(iVar12 + 0x22) = *(short *)(iVar12 + 0x22) + -1;
          if (*(short *)(iVar12 + 0x22) < 1) {
            FUN_8000bb38(0,0x3a8);
            *(undefined2 *)(iVar12 + 0x24) = 5;
            if (*(char *)(iVar12 + 0x2f) == '\x03') {
              *(float *)(iVar12 + 0xc) = FLOAT_803e5c40;
            }
            else if (*(char *)(iVar12 + 0x2f) == '\x04') {
              *(float *)(iVar12 + 0xc) = FLOAT_803e5c40;
            }
            else {
              *(float *)(iVar12 + 0xc) = FLOAT_803e5c40;
            }
          }
          else {
            *(undefined *)(iVar12 + 0x31) = 0;
            uStack_1c = FUN_80022264(0x28,0x3c);
            uStack_1c = uStack_1c ^ 0x80000000;
            local_20 = 0x43300000;
            *(float *)(iVar12 + 0x14) =
                 (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5c58);
            FUN_8000bb38((uint)param_9,0x344);
            *(undefined2 *)(iVar12 + 0x24) = 0;
            *(float *)(iVar12 + 4) = FLOAT_803e5c78;
            if (*(char *)(iVar12 + 0x2f) == '\x03') {
              uVar10 = FUN_80022264(0,1);
            }
            else if (*(char *)(iVar12 + 0x2f) == '\x04') {
              uVar10 = FUN_80022264(0,5);
            }
            else {
              uVar10 = FUN_80022264(0,7);
            }
            sVar8 = DAT_80326e82;
            sVar7 = DAT_80326e80;
            sVar6 = DAT_80326e7a;
            sVar5 = DAT_80326e78;
            fVar4 = DAT_80326e74;
            fVar3 = DAT_80326e70;
            fVar1 = DAT_80326e54;
            fVar2 = DAT_80326e50;
            if (uVar10 == 0) {
              DAT_80326e78 = DAT_80326e78 + 1;
              if (5 < DAT_80326e78) {
                DAT_80326e78 = 0;
              }
              DAT_80326e7a = DAT_80326e7a + 1;
              if (5 < DAT_80326e7a) {
                DAT_80326e7a = 0;
              }
              DAT_80326e7c = DAT_80326e7c + 1;
              if (5 < DAT_80326e7c) {
                DAT_80326e7c = 0;
              }
              DAT_80326e7e = DAT_80326e7e + 1;
              if (5 < DAT_80326e7e) {
                DAT_80326e7e = 0;
              }
              DAT_80326e80 = DAT_80326e80 + 1;
              if (5 < DAT_80326e80) {
                DAT_80326e80 = 0;
              }
              DAT_80326e82 = DAT_80326e82 + 1;
              if (5 < DAT_80326e82) {
                DAT_80326e82 = 0;
              }
            }
            else if (uVar10 == 1) {
              DAT_80326e78 = DAT_80326e78 + -1;
              if (DAT_80326e78 < 0) {
                DAT_80326e78 = 5;
              }
              DAT_80326e7a = DAT_80326e7a + -1;
              if (DAT_80326e7a < 0) {
                DAT_80326e7a = 5;
              }
              DAT_80326e7c = DAT_80326e7c + -1;
              if (DAT_80326e7c < 0) {
                DAT_80326e7c = 5;
              }
              DAT_80326e7e = DAT_80326e7e + -1;
              if (DAT_80326e7e < 0) {
                DAT_80326e7e = 5;
              }
              DAT_80326e80 = DAT_80326e80 + -1;
              if (DAT_80326e80 < 0) {
                DAT_80326e80 = 5;
              }
              DAT_80326e82 = DAT_80326e82 + -1;
              if (DAT_80326e82 < 0) {
                DAT_80326e82 = 5;
              }
            }
            else if (uVar10 == 2) {
              DAT_80326e78 = DAT_80326e7c;
              DAT_80326e7c = DAT_80326e80;
              DAT_80326e80 = sVar5;
            }
            else if (uVar10 == 3) {
              DAT_80326e80 = DAT_80326e78;
              DAT_80326e78 = DAT_80326e7c;
              DAT_80326e7c = sVar7;
            }
            else if (uVar10 == 4) {
              DAT_80326e7a = DAT_80326e7e;
              DAT_80326e7e = DAT_80326e82;
              DAT_80326e82 = sVar6;
            }
            else if (uVar10 == 5) {
              DAT_80326e82 = DAT_80326e7a;
              DAT_80326e7a = DAT_80326e7e;
              DAT_80326e7e = sVar8;
            }
            else if (uVar10 == 6) {
              DAT_80326e50 = DAT_80326e58;
              DAT_80326e54 = DAT_80326e5c;
              DAT_80326e58 = DAT_80326e68;
              DAT_80326e5c = DAT_80326e6c;
              DAT_80326e68 = DAT_80326e70;
              DAT_80326e6c = DAT_80326e74;
              DAT_80326e70 = fVar2;
              DAT_80326e74 = fVar1;
            }
            else if (uVar10 == 7) {
              DAT_80326e70 = DAT_80326e68;
              DAT_80326e74 = DAT_80326e6c;
              DAT_80326e68 = DAT_80326e58;
              DAT_80326e6c = DAT_80326e5c;
              DAT_80326e58 = DAT_80326e50;
              DAT_80326e5c = DAT_80326e54;
              DAT_80326e50 = fVar3;
              DAT_80326e54 = fVar4;
            }
          }
          break;
        case 4:
          *(undefined2 *)(iVar12 + 0x24) = 2;
          *(float *)(iVar12 + 4) = fVar2;
          break;
        case 5:
          FUN_8000da78(0,0x3a8);
          if (*(short *)(iVar12 + 0x26) == 0) {
            (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
            *(float *)(iVar12 + 8) = FLOAT_803e5c80;
            *(undefined2 *)(iVar12 + 0x24) = 7;
            FUN_8000bb38((uint)param_9,0x16f);
            *(undefined *)(iVar12 + 0x2f) = 10;
          }
          else if (*(short *)(iVar12 + 0x26) == 1) {
            if (*(char *)(iVar12 + 0x2f) == '\x03') {
              uVar10 = FUN_80022264(0,5);
              *(char *)(iVar12 + 0x2e) = (char)uVar10;
              *(undefined *)(iVar12 + 0x2f) = 4;
              *(undefined2 *)(iVar12 + 0x24) = 9;
              *(float *)(iVar12 + 8) = FLOAT_803e5c84;
              *(float *)(iVar12 + 4) = FLOAT_803e5c48;
              *(undefined2 *)(iVar12 + 0x22) = 7;
              *(undefined2 *)(iVar12 + 0x26) = 0xffff;
              FUN_8000bb38((uint)param_9,0x170);
              (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_9,0xffffffff);
            }
            else if (*(char *)(iVar12 + 0x2f) == '\x04') {
              uVar10 = FUN_80022264(0,5);
              *(char *)(iVar12 + 0x2e) = (char)uVar10;
              *(undefined *)(iVar12 + 0x2f) = 5;
              *(undefined2 *)(iVar12 + 0x24) = 9;
              *(float *)(iVar12 + 8) = FLOAT_803e5c84;
              *(float *)(iVar12 + 4) = FLOAT_803e5c48;
              *(undefined2 *)(iVar12 + 0x22) = 9;
              *(undefined2 *)(iVar12 + 0x26) = 0xffff;
              FUN_8000bb38((uint)param_9,0x170);
              (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_9,0xffffffff);
            }
            else {
              *(float *)(iVar12 + 8) = FLOAT_803e5c80;
              (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
              *(undefined *)(iVar12 + 0x2f) = 6;
              *(undefined2 *)(iVar12 + 0x24) = 3;
              *(undefined2 *)(iVar12 + 0x26) = 0;
              *(undefined2 *)(iVar12 + 0x24) = 7;
              FUN_8000bb38((uint)param_9,0x7e);
              FUN_8000bb38((uint)param_9,0x16f);
            }
          }
          else {
            *(float *)(iVar12 + 0xc) = *(float *)(iVar12 + 0xc) - FLOAT_803dc074;
            if (*(float *)(iVar12 + 0xc) <= FLOAT_803e5c64) {
              *(undefined *)(iVar12 + 0x2f) = 10;
              (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
              *(float *)(iVar12 + 8) = FLOAT_803e5c80;
              *(undefined2 *)(iVar12 + 0x24) = 7;
              FUN_8000bb38((uint)param_9,0x16f);
            }
          }
          break;
        case 7:
          *(undefined2 *)(iVar12 + 0x24) = 3;
          *(float *)(iVar12 + 4) = FLOAT_803e5c70;
          *(float *)(iVar12 + 8) = FLOAT_803e5c74;
          break;
        case 8:
          *(undefined2 *)(iVar12 + 0x24) = 2;
          *(float *)(iVar12 + 4) = FLOAT_803e5c70;
          *(float *)(iVar12 + 8) = FLOAT_803e5c74;
          break;
        case 9:
          *(undefined2 *)(iVar12 + 0x24) = 8;
          *(float *)(iVar12 + 4) = FLOAT_803e5c70;
          *(float *)(iVar12 + 8) = FLOAT_803e5c74;
        }
      }
      else {
        if (((*(short *)(iVar12 + 0x24) == 1) && (*(char *)(iVar12 + 0x31) == '\0')) &&
           (*(float *)(iVar12 + 4) < *(float *)(iVar12 + 0x14))) {
          uVar10 = FUN_80022264(0,10);
          if (7 < (int)uVar10) {
            FUN_8000bb38((uint)param_9,0x345);
          }
          *(undefined *)(iVar12 + 0x31) = 1;
        }
        *(float *)(iVar12 + 4) = *(float *)(iVar12 + 4) - FLOAT_803dc074;
        if (*(float *)(iVar12 + 4) < FLOAT_803e5c64) {
          *(float *)(iVar12 + 4) = FLOAT_803e5c64;
        }
      }
      break;
    case 6:
      FUN_800201ac(0xb9d,0);
      FUN_80009a94(3);
      uVar10 = FUN_80296cb4(iVar9,8);
      if (uVar10 == 0) {
        *(undefined *)(iVar12 + 0x2f) = 7;
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
      }
      else {
        FUN_800201ac(0x129,1);
        *(undefined *)(iVar12 + 0x2f) = 7;
      }
      break;
    case 7:
      FUN_800201ac(0x129,0);
      *(undefined *)(iVar12 + 0x2f) = 8;
      break;
    case 8:
      *(undefined *)(iVar12 + 0x2f) = 0;
      *(float *)(iVar12 + 4) = fVar2;
      *(undefined2 *)(iVar12 + 0x20) = 0;
      *(undefined2 *)(iVar12 + 0x22) = 0;
      *(undefined2 *)(iVar12 + 0x24) = 0;
      *(undefined2 *)(iVar12 + 0x26) = 0xffff;
      *(undefined *)(iVar12 + 0x2e) = 0;
      *(undefined *)(iVar12 + 0x30) = 0;
      *(float *)(iVar12 + 8) = FLOAT_803e5c88;
      FUN_800201ac(0x129,1);
      FUN_800201ac(0xb9d,0);
      FUN_800201ac(0xa6d,0);
      FUN_800201ac(0xa6f,0);
      FUN_800201ac(0xa70,0);
      FUN_800201ac(0x143,0);
      *(undefined *)(iVar12 + 0x30) = 0;
      *(undefined2 *)(iVar12 + 0x26) = 0xffff;
      break;
    case 10:
      FUN_800201ac(0xa6f,1);
      *(undefined *)(iVar12 + 0x2f) = 8;
    }
  }
  else {
    *(float *)(iVar12 + 8) = *(float *)(iVar12 + 8) - FLOAT_803dc074;
    if (*(float *)(iVar12 + 8) <= fVar2) {
      *(float *)(iVar12 + 8) = fVar2;
    }
  }
  return;
}

