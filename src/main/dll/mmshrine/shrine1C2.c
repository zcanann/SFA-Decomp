#include "ghidra_import.h"
#include "main/dll/mmshrine/shrine1C2.h"

extern undefined8 FUN_80008cbc();
extern undefined4 FUN_80009a94();
extern undefined4 FUN_8000a538();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000da78();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_80013ee8();
extern undefined4 FUN_800146a8();
extern undefined4 FUN_8001dc30();
extern undefined4 FUN_8001f448();
extern void* FUN_8001f58c();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_80021754();
extern uint FUN_80021884();
extern uint FUN_80022264();
extern undefined4 FUN_80023d8c();
extern int FUN_8002bac4();
extern int FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_8002fb40();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_800372f8();
extern int FUN_800375e4();
extern undefined4 FUN_80037a5c();
extern undefined4 FUN_8003b9ec();
extern undefined8 FUN_80088f20();
extern undefined4 FUN_8009a010();
extern undefined4 FUN_801c5f44();
extern undefined4 FUN_801c6298();
extern undefined4 FUN_801d84c4();
extern undefined4 FUN_801d8650();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_802945e0();
extern uint FUN_80296328();
extern undefined4 FUN_80296454();
extern undefined4 FUN_80296c78();
extern uint FUN_80296cb4();
extern uint countLeadingZeros();

extern undefined4 DAT_80326e48;
extern undefined4 DAT_80326e4c;
extern undefined4 DAT_80326e50;
extern undefined4 DAT_80326e54;
extern undefined4 DAT_80326e58;
extern undefined4 DAT_80326e5c;
extern undefined4 DAT_80326e60;
extern undefined4 DAT_80326e64;
extern undefined4 DAT_80326e68;
extern undefined4 DAT_80326e6c;
extern undefined4 DAT_80326e70;
extern undefined4 DAT_80326e74;
extern undefined4 DAT_80326e78;
extern undefined4 DAT_80326e7a;
extern undefined4 DAT_80326e7c;
extern undefined4 DAT_80326e7e;
extern undefined4 DAT_80326e80;
extern undefined4 DAT_80326e82;
extern undefined4 DAT_80326e84;
extern undefined4 DAT_80326e86;
extern undefined4 DAT_80326e88;
extern undefined4 DAT_80326e8a;
extern undefined4 DAT_80326e8c;
extern undefined4 DAT_80326e8e;
extern undefined4 DAT_80326e90;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de840;
extern undefined4 DAT_803de844;
extern undefined4 DAT_803e90f0;
extern undefined4 DAT_803e90f4;
extern f64 DOUBLE_803e5c58;
extern f64 DOUBLE_803e5cc8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5c40;
extern f32 FLOAT_803e5c48;
extern f32 FLOAT_803e5c64;
extern f32 FLOAT_803e5c68;
extern f32 FLOAT_803e5c6c;
extern f32 FLOAT_803e5c70;
extern f32 FLOAT_803e5c74;
extern f32 FLOAT_803e5c78;
extern f32 FLOAT_803e5c7c;
extern f32 FLOAT_803e5c80;
extern f32 FLOAT_803e5c84;
extern f32 FLOAT_803e5c88;
extern f32 FLOAT_803e5c98;
extern f32 FLOAT_803e5c9c;
extern f32 FLOAT_803e5ca0;
extern f32 FLOAT_803e5ca4;
extern f32 FLOAT_803e5cb0;
extern f32 FLOAT_803e5cb4;
extern f32 FLOAT_803e5cb8;
extern f32 FLOAT_803e5cbc;
extern f32 FLOAT_803e5cc0;
extern f32 FLOAT_803e5cd0;

/*
 * --INFO--
 *
 * Function: FUN_801c666c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C666C
 * EN v1.1 Size: 3104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: FUN_801c728c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C728C
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c728c(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c73d4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C73D4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c73d4(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c7408
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C7408
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c7408(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
  uint uVar1;
  int *piVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  short *psVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_9 + 0x26);
  psVar4 = *(short **)(param_9 + 0x5c);
  if ((*(int *)(param_9 + 0x7c) == 0) && (uVar1 = FUN_80020078((int)psVar4[2]), uVar1 != 0)) {
    piVar2 = (int *)FUN_80013ee8(0x82);
    (**(code **)(*piVar2 + 4))(param_9,0,0,1,0xffffffff,0);
    in_r8 = 0;
    in_r9 = *piVar2;
    (**(code **)(in_r9 + 4))(param_9,1,0,1,0xffffffff);
    param_1 = FUN_8000bb38((uint)param_9,0x16d);
    FUN_80013e4c((undefined *)piVar2);
    psVar4[1] = 1;
    *(undefined4 *)(param_9 + 0x7c) = 1;
  }
  if (psVar4[1] != 0) {
    *psVar4 = *psVar4 - psVar4[1] * (ushort)DAT_803dc070;
  }
  uVar1 = FUN_8002e144();
  if (((uVar1 & 0xff) != 0) && (*psVar4 < 1)) {
    puVar3 = (undefined2 *)FUN_80023d8c(0x38,0xe);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(iVar5 + 8);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(iVar5 + 0xc);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(iVar5 + 0x10);
    *puVar3 = 0x11;
    *(undefined4 *)(puVar3 + 10) = 0xffffffff;
    *(undefined *)(puVar3 + 2) = *(undefined *)(iVar5 + 4);
    *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar5 + 5);
    *(undefined *)(puVar3 + 3) = *(undefined *)(iVar5 + 6);
    *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar5 + 7);
    *(undefined *)((int)puVar3 + 0x27) = 3;
    *(undefined *)(puVar3 + 0x14) = 0;
    puVar3[0xc] = psVar4[2] + (short)*(char *)(iVar5 + 0x1f);
    puVar3[0x18] = 0xffff;
    *(char *)(puVar3 + 0x15) = (char)((ushort)*param_9 >> 8);
    *(undefined *)((int)puVar3 + 0x2b) = 2;
    puVar3[0x10] = 0;
    puVar3[0xf] = 0;
    puVar3[0x11] = 0xffff;
    *(undefined *)((int)puVar3 + 0x29) = 0xff;
    *(undefined *)(puVar3 + 0x17) = 0xff;
    puVar3[0x12] = 0;
    puVar3[0x16] = 0;
    puVar3[0x1a] = 0xffff;
    puVar3[0xd] = 0;
    *(char *)(puVar3 + 0x19) = (char)psVar4[4];
    iVar5 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                         *(undefined *)(param_9 + 0x56),0xffffffff,*(uint **)(param_9 + 0x18),in_r8,
                         in_r9,in_r10);
    if (iVar5 != 0) {
      *(undefined *)(*(int *)(iVar5 + 0xb8) + 0x404) = 0x20;
    }
    *psVar4 = 100;
    psVar4[1] = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c76a4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C76A4
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c76a4(ushort *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 local_30;
  
  iVar4 = *(int *)(param_1 + 0x26);
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar1 = FUN_8002bac4();
  if ((param_1[3] & 0x4000) == 0) {
    *(short *)(iVar3 + 0xc) =
         *(short *)(iVar3 + 0xc) + (short)(int)(FLOAT_803e5c98 * FLOAT_803dc074);
    *(short *)(iVar3 + 0xe) =
         *(short *)(iVar3 + 0xe) + (short)(int)(FLOAT_803e5c9c * FLOAT_803dc074);
    *(short *)(iVar3 + 0x10) =
         *(short *)(iVar3 + 0x10) + (short)(int)(FLOAT_803e5ca0 * FLOAT_803dc074);
    dVar5 = (double)FUN_802945e0();
    *(float *)(param_1 + 8) = FLOAT_803e5ca4 + (float)((double)*(float *)(iVar4 + 0xc) + dVar5);
    dVar5 = (double)FUN_802945e0();
    dVar6 = (double)FUN_802945e0();
    param_1[2] = (ushort)(int)(FLOAT_803e5cb0 * (float)(dVar6 + dVar5));
    dVar5 = (double)FUN_802945e0();
    dVar6 = (double)FUN_802945e0();
    param_1[1] = (ushort)(int)(FLOAT_803e5cb0 * (float)(dVar6 + dVar5));
    FUN_8002fb40((double)FLOAT_803e5cb4,(double)FLOAT_803dc074);
    if (iVar1 != 0) {
      uVar2 = FUN_80021884();
      uVar2 = (uVar2 & 0xffff) - (uint)*param_1;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *param_1 = *param_1 +
                 (short)(int)(((float)(local_30 - DOUBLE_803e5cc8) * FLOAT_803dc074) /
                             FLOAT_803e5cb8);
      dVar5 = (double)FUN_80021754((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      if ((double)FLOAT_803e5cbc < dVar5) {
        *(undefined *)(param_1 + 0x1b) = 0xff;
      }
      else {
        *(char *)(param_1 + 0x1b) =
             (char)(int)(FLOAT_803e5cc0 * (float)(dVar5 / (double)FLOAT_803e5cbc));
      }
    }
  }
  else {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0xc);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c79f8
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C79F8
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c79f8(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  
  iVar2 = FUN_8028683c();
  piVar5 = *(int **)(iVar2 + 0xb8);
  iVar3 = FUN_8002bac4();
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    bVar1 = *(byte *)(param_3 + iVar4 + 0x81);
    if (bVar1 != 0) {
      if (bVar1 == 7) {
        FUN_80296c78(iVar3,0x80,1);
        FUN_800201ac(299,1);
        FUN_800201ac(0xc85,1);
        (**(code **)(*DAT_803dd72c + 0x44))(0xb,5);
      }
      else if (bVar1 < 7) {
        if (bVar1 == 3) {
          *(byte *)((int)piVar5 + 0x15) = *(byte *)((int)piVar5 + 0x15) & 0x7f | 0x80;
        }
      }
      else if (bVar1 == 0xf) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) & 0xbfff;
        if (*piVar5 != 0) {
          FUN_8001dc30((double)FLOAT_803e5cd0,*piVar5,'\0');
        }
      }
      else if ((bVar1 < 0xf) && (0xd < bVar1)) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        if (*piVar5 != 0) {
          FUN_8001dc30((double)FLOAT_803e5cd0,*piVar5,'\0');
        }
      }
    }
    *(undefined *)(param_3 + iVar4 + 0x81) = 0;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c7b6c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C7B6C
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c7b6c(int param_1)
{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *puVar2 = 0;
  }
  FUN_800146a8();
  FUN_8003709c(param_1,0xb);
  FUN_8000a538((int *)0xd8,0);
  FUN_8000a538((int *)0xd9,0);
  FUN_8000a538((int *)0x8,0);
  FUN_8000a538((int *)0xb,0);
  FUN_800201ac(0xefa,0);
  uVar1 = FUN_80020078(0xc91);
  uVar1 = countLeadingZeros(uVar1);
  FUN_800201ac(0xcbb,uVar1 >> 5);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c7c1c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C7C1C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c7c1c(void)
{
  int iVar1;
  char in_r8;
  int *piVar2;
  
  iVar1 = FUN_8028683c();
  piVar2 = *(int **)(iVar1 + 0xb8);
  if (in_r8 == '\0') {
    if (*piVar2 != 0) {
      FUN_8001dc30((double)FLOAT_803e5cd0,*piVar2,'\0');
    }
  }
  else {
    if (*piVar2 != 0) {
      FUN_8001dc30((double)FLOAT_803e5cd0,*piVar2,'\x01');
    }
    FUN_8003b9ec(iVar1);
    FUN_8009a010((double)FLOAT_803e5cd0,(double)FLOAT_803e5cd0,iVar1,7,(int *)*piVar2);
  }
  FUN_80286888();
  return;
}
