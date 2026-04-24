// Function: FUN_801c60b8
// Entry: 801c60b8
// Size: 3104 bytes

void FUN_801c60b8(int param_1)

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
  undefined uVar11;
  int iVar10;
  int iVar12;
  undefined auStack56 [4];
  undefined auStack52 [4];
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_20;
  uint uStack28;
  
  iVar12 = *(int *)(param_1 + 0xb8);
  iVar9 = FUN_8002b9ec();
  local_2c = DAT_803e8470;
  local_28 = DAT_803e8474;
  if (*(char *)(iVar12 + 0x32) == '\0') {
    uVar11 = FUN_8001ffb4(0x58b);
    *(undefined *)(iVar12 + 0x32) = uVar11;
    if (*(char *)(iVar12 + 0x32) != '\0') {
      (**(code **)(*DAT_803dca68 + 0x38))(0x285,0x14,0x8c,1);
    }
  }
  if ((*(int *)(param_1 + 0xf4) != 0) &&
     (*(int *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) + -1, *(int *)(param_1 + 0xf4) == 0)) {
    FUN_80088c94(7,1);
    FUN_80008cbc(param_1,iVar9,0x221,0);
    FUN_80008cbc(param_1,iVar9,0x220,0);
    FUN_80008cbc(param_1,iVar9,0x222,0);
  }
  FUN_801c5990(param_1);
  if ((iVar9 != 0) && (iVar10 = FUN_80295bc8(iVar9), iVar10 == 0)) {
    FUN_80295cf4(iVar9,0);
  }
  local_30 = 0;
  do {
    iVar10 = FUN_800374ec(param_1,auStack52,auStack56,&local_30);
  } while (iVar10 != 0);
  FUN_801d7ed4(iVar12 + 0x34,2,0xffffffff,0xffffffff,0xb9d,0xd);
  FUN_801d8060(iVar12 + 0x34,1,0xffffffff,0xffffffff,0xcbb,8);
  FUN_801d7ed4(iVar12 + 0x34,0x10,0xffffffff,0xffffffff,0xcbb,0xc4);
  fVar2 = FLOAT_803e4fcc;
  if (*(float *)(iVar12 + 8) <= FLOAT_803e4fcc) {
    switch(*(undefined *)(iVar12 + 0x2f)) {
    case 0:
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
      fVar1 = *(float *)(iVar12 + 0x10) - FLOAT_803db414;
      *(float *)(iVar12 + 0x10) = fVar1;
      if (fVar1 <= fVar2) {
        FUN_8000bb18(param_1,0x343);
        uStack28 = FUN_800221a0(500,1000);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        *(float *)(iVar12 + 0x10) = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e4fc0)
        ;
      }
      if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
        *(undefined *)(iVar12 + 0x2f) = 1;
        FUN_800200e8(0x129,0);
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
        FUN_8000a518(0xd8,1);
        DAT_80326208 = FLOAT_803e4fcc;
        DAT_8032620c = FLOAT_803e4fcc;
        DAT_80326210 = FLOAT_803e4fcc;
        DAT_80326214 = FLOAT_803e4fcc;
        DAT_80326218 = FLOAT_803e4fcc;
        DAT_8032621c = FLOAT_803e4fcc;
        DAT_80326220 = FLOAT_803e4fcc;
        DAT_80326224 = FLOAT_803e4fcc;
        DAT_80326228 = FLOAT_803e4fcc;
        DAT_8032622c = FLOAT_803e4fcc;
        DAT_80326230 = FLOAT_803e4fcc;
        DAT_80326234 = FLOAT_803e4fcc;
        DAT_80326238 = DAT_80326244;
        DAT_8032623a = DAT_80326246;
        DAT_8032623c = DAT_80326248;
        DAT_8032623e = DAT_8032624a;
        DAT_80326240 = DAT_8032624c;
        DAT_80326242 = DAT_8032624e;
        DAT_80326244 = DAT_80326250;
      }
      break;
    case 1:
      if (*(char *)(iVar12 + 0x30) == '\x01') {
        *(undefined *)(iVar12 + 0x2f) = 2;
        *(float *)(iVar12 + 8) = FLOAT_803e4fd0;
        *(undefined2 *)(iVar12 + 0x24) = 6;
        FUN_8000bb18(param_1,0x16f);
        *(float *)(iVar12 + 4) = FLOAT_803e4fcc;
        FUN_800200e8(0xb9d,1);
        (**(code **)(*DAT_803dca4c + 0xc))(0x78,1);
      }
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      break;
    case 2:
      *(undefined *)(iVar12 + 0x2f) = 3;
      *(float *)(iVar12 + 8) = FLOAT_803e4fd4;
      *(undefined2 *)(iVar12 + 0x24) = 8;
      *(float *)(iVar12 + 4) = FLOAT_803e4fd8;
      *(undefined2 *)(iVar12 + 0x22) = 5;
      uVar11 = FUN_800221a0(0,5);
      *(undefined *)(iVar12 + 0x2e) = uVar11;
      (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
      break;
    case 3:
    case 4:
    case 5:
      if (*(float *)(iVar12 + 4) <= FLOAT_803e4fcc) {
        switch(*(undefined2 *)(iVar12 + 0x24)) {
        case 0:
          *(undefined2 *)(iVar12 + 0x24) = 1;
          *(float *)(iVar12 + 4) = FLOAT_803e4fe4;
          break;
        case 1:
          *(undefined2 *)(iVar12 + 0x24) = 4;
          *(float *)(iVar12 + 4) = fVar2;
          break;
        case 2:
          *(short *)(iVar12 + 0x22) = *(short *)(iVar12 + 0x22) + -1;
          if (*(short *)(iVar12 + 0x22) < 1) {
            FUN_8000bb18(0,0x3a8);
            *(undefined2 *)(iVar12 + 0x24) = 5;
            if (*(char *)(iVar12 + 0x2f) == '\x03') {
              *(float *)(iVar12 + 0xc) = FLOAT_803e4fa8;
            }
            else if (*(char *)(iVar12 + 0x2f) == '\x04') {
              *(float *)(iVar12 + 0xc) = FLOAT_803e4fa8;
            }
            else {
              *(float *)(iVar12 + 0xc) = FLOAT_803e4fa8;
            }
          }
          else {
            *(undefined *)(iVar12 + 0x31) = 0;
            uStack28 = FUN_800221a0(0x28,0x3c);
            uStack28 = uStack28 ^ 0x80000000;
            local_20 = 0x43300000;
            *(float *)(iVar12 + 0x14) =
                 (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e4fc0);
            FUN_8000bb18(param_1,0x344);
            *(undefined2 *)(iVar12 + 0x24) = 0;
            *(float *)(iVar12 + 4) = FLOAT_803e4fe0;
            if (*(char *)(iVar12 + 0x2f) == '\x03') {
              iVar9 = FUN_800221a0(0,1);
            }
            else if (*(char *)(iVar12 + 0x2f) == '\x04') {
              iVar9 = FUN_800221a0(0,5);
            }
            else {
              iVar9 = FUN_800221a0(0,7);
            }
            sVar8 = DAT_80326242;
            sVar7 = DAT_80326240;
            sVar6 = DAT_8032623a;
            sVar5 = DAT_80326238;
            fVar4 = DAT_80326234;
            fVar3 = DAT_80326230;
            fVar1 = DAT_80326214;
            fVar2 = DAT_80326210;
            if (iVar9 == 0) {
              DAT_80326238 = DAT_80326238 + 1;
              if (5 < DAT_80326238) {
                DAT_80326238 = 0;
              }
              DAT_8032623a = DAT_8032623a + 1;
              if (5 < DAT_8032623a) {
                DAT_8032623a = 0;
              }
              DAT_8032623c = DAT_8032623c + 1;
              if (5 < DAT_8032623c) {
                DAT_8032623c = 0;
              }
              DAT_8032623e = DAT_8032623e + 1;
              if (5 < DAT_8032623e) {
                DAT_8032623e = 0;
              }
              DAT_80326240 = DAT_80326240 + 1;
              if (5 < DAT_80326240) {
                DAT_80326240 = 0;
              }
              DAT_80326242 = DAT_80326242 + 1;
              if (5 < DAT_80326242) {
                DAT_80326242 = 0;
              }
            }
            else if (iVar9 == 1) {
              DAT_80326238 = DAT_80326238 + -1;
              if (DAT_80326238 < 0) {
                DAT_80326238 = 5;
              }
              DAT_8032623a = DAT_8032623a + -1;
              if (DAT_8032623a < 0) {
                DAT_8032623a = 5;
              }
              DAT_8032623c = DAT_8032623c + -1;
              if (DAT_8032623c < 0) {
                DAT_8032623c = 5;
              }
              DAT_8032623e = DAT_8032623e + -1;
              if (DAT_8032623e < 0) {
                DAT_8032623e = 5;
              }
              DAT_80326240 = DAT_80326240 + -1;
              if (DAT_80326240 < 0) {
                DAT_80326240 = 5;
              }
              DAT_80326242 = DAT_80326242 + -1;
              if (DAT_80326242 < 0) {
                DAT_80326242 = 5;
              }
            }
            else if (iVar9 == 2) {
              DAT_80326238 = DAT_8032623c;
              DAT_8032623c = DAT_80326240;
              DAT_80326240 = sVar5;
            }
            else if (iVar9 == 3) {
              DAT_80326240 = DAT_80326238;
              DAT_80326238 = DAT_8032623c;
              DAT_8032623c = sVar7;
            }
            else if (iVar9 == 4) {
              DAT_8032623a = DAT_8032623e;
              DAT_8032623e = DAT_80326242;
              DAT_80326242 = sVar6;
            }
            else if (iVar9 == 5) {
              DAT_80326242 = DAT_8032623a;
              DAT_8032623a = DAT_8032623e;
              DAT_8032623e = sVar8;
            }
            else if (iVar9 == 6) {
              DAT_80326210 = DAT_80326218;
              DAT_80326214 = DAT_8032621c;
              DAT_80326218 = DAT_80326228;
              DAT_8032621c = DAT_8032622c;
              DAT_80326228 = DAT_80326230;
              DAT_8032622c = DAT_80326234;
              DAT_80326230 = fVar2;
              DAT_80326234 = fVar1;
            }
            else if (iVar9 == 7) {
              DAT_80326230 = DAT_80326228;
              DAT_80326234 = DAT_8032622c;
              DAT_80326228 = DAT_80326218;
              DAT_8032622c = DAT_8032621c;
              DAT_80326218 = DAT_80326210;
              DAT_8032621c = DAT_80326214;
              DAT_80326210 = fVar3;
              DAT_80326214 = fVar4;
            }
          }
          break;
        case 4:
          *(undefined2 *)(iVar12 + 0x24) = 2;
          *(float *)(iVar12 + 4) = fVar2;
          break;
        case 5:
          FUN_8000da58(0,0x3a8);
          if (*(short *)(iVar12 + 0x26) == 0) {
            (**(code **)(*DAT_803dca4c + 8))(0x1e,1);
            *(float *)(iVar12 + 8) = FLOAT_803e4fe8;
            *(undefined2 *)(iVar12 + 0x24) = 7;
            FUN_8000bb18(param_1,0x16f);
            *(undefined *)(iVar12 + 0x2f) = 10;
          }
          else if (*(short *)(iVar12 + 0x26) == 1) {
            if (*(char *)(iVar12 + 0x2f) == '\x03') {
              uVar11 = FUN_800221a0(0,5);
              *(undefined *)(iVar12 + 0x2e) = uVar11;
              *(undefined *)(iVar12 + 0x2f) = 4;
              *(undefined2 *)(iVar12 + 0x24) = 9;
              *(float *)(iVar12 + 8) = FLOAT_803e4fec;
              *(float *)(iVar12 + 4) = FLOAT_803e4fb0;
              *(undefined2 *)(iVar12 + 0x22) = 7;
              *(undefined2 *)(iVar12 + 0x26) = 0xffff;
              FUN_8000bb18(param_1,0x170);
              (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
            }
            else if (*(char *)(iVar12 + 0x2f) == '\x04') {
              uVar11 = FUN_800221a0(0,5);
              *(undefined *)(iVar12 + 0x2e) = uVar11;
              *(undefined *)(iVar12 + 0x2f) = 5;
              *(undefined2 *)(iVar12 + 0x24) = 9;
              *(float *)(iVar12 + 8) = FLOAT_803e4fec;
              *(float *)(iVar12 + 4) = FLOAT_803e4fb0;
              *(undefined2 *)(iVar12 + 0x22) = 9;
              *(undefined2 *)(iVar12 + 0x26) = 0xffff;
              FUN_8000bb18(param_1,0x170);
              (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
            }
            else {
              *(float *)(iVar12 + 8) = FLOAT_803e4fe8;
              (**(code **)(*DAT_803dca4c + 8))(0x1e,1);
              *(undefined *)(iVar12 + 0x2f) = 6;
              *(undefined2 *)(iVar12 + 0x24) = 3;
              *(undefined2 *)(iVar12 + 0x26) = 0;
              *(undefined2 *)(iVar12 + 0x24) = 7;
              FUN_8000bb18(param_1,0x7e);
              FUN_8000bb18(param_1,0x16f);
            }
          }
          else {
            *(float *)(iVar12 + 0xc) = *(float *)(iVar12 + 0xc) - FLOAT_803db414;
            if (*(float *)(iVar12 + 0xc) <= FLOAT_803e4fcc) {
              *(undefined *)(iVar12 + 0x2f) = 10;
              (**(code **)(*DAT_803dca4c + 8))(0x1e,1);
              *(float *)(iVar12 + 8) = FLOAT_803e4fe8;
              *(undefined2 *)(iVar12 + 0x24) = 7;
              FUN_8000bb18(param_1,0x16f);
            }
          }
          break;
        case 7:
          *(undefined2 *)(iVar12 + 0x24) = 3;
          *(float *)(iVar12 + 4) = FLOAT_803e4fd8;
          *(float *)(iVar12 + 8) = FLOAT_803e4fdc;
          break;
        case 8:
          *(undefined2 *)(iVar12 + 0x24) = 2;
          *(float *)(iVar12 + 4) = FLOAT_803e4fd8;
          *(float *)(iVar12 + 8) = FLOAT_803e4fdc;
          break;
        case 9:
          *(undefined2 *)(iVar12 + 0x24) = 8;
          *(float *)(iVar12 + 4) = FLOAT_803e4fd8;
          *(float *)(iVar12 + 8) = FLOAT_803e4fdc;
        }
      }
      else {
        if (((*(short *)(iVar12 + 0x24) == 1) && (*(char *)(iVar12 + 0x31) == '\0')) &&
           (*(float *)(iVar12 + 4) < *(float *)(iVar12 + 0x14))) {
          iVar9 = FUN_800221a0(0,10);
          if (7 < iVar9) {
            FUN_8000bb18(param_1,0x345);
          }
          *(undefined *)(iVar12 + 0x31) = 1;
        }
        *(float *)(iVar12 + 4) = *(float *)(iVar12 + 4) - FLOAT_803db414;
        if (*(float *)(iVar12 + 4) < FLOAT_803e4fcc) {
          *(float *)(iVar12 + 4) = FLOAT_803e4fcc;
        }
      }
      break;
    case 6:
      FUN_800200e8(0xb9d,0);
      FUN_80009a94(3);
      iVar9 = FUN_80296554(iVar9,8);
      if (iVar9 == 0) {
        *(undefined *)(iVar12 + 0x2f) = 7;
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
      }
      else {
        FUN_800200e8(0x129,1);
        *(undefined *)(iVar12 + 0x2f) = 7;
      }
      break;
    case 7:
      FUN_800200e8(0x129,0);
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
      *(float *)(iVar12 + 8) = FLOAT_803e4ff0;
      FUN_800200e8(0x129,1);
      FUN_800200e8(0xb9d,0);
      FUN_800200e8(0xa6d,0);
      FUN_800200e8(0xa6f,0);
      FUN_800200e8(0xa70,0);
      FUN_800200e8(0x143,0);
      *(undefined *)(iVar12 + 0x30) = 0;
      *(undefined2 *)(iVar12 + 0x26) = 0xffff;
      break;
    case 10:
      FUN_800200e8(0xa6f,1);
      *(undefined *)(iVar12 + 0x2f) = 8;
    }
  }
  else {
    *(float *)(iVar12 + 8) = *(float *)(iVar12 + 8) - FLOAT_803db414;
    if (*(float *)(iVar12 + 8) <= fVar2) {
      *(float *)(iVar12 + 8) = fVar2;
    }
  }
  return;
}

