// Function: FUN_801c7724
// Entry: 801c7724
// Size: 2124 bytes

void FUN_801c7724(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  char cVar6;
  char cVar7;
  char cVar8;
  char cVar9;
  char cVar10;
  char cVar11;
  undefined4 uVar5;
  int iVar12;
  int local_38 [2];
  undefined4 local_30;
  uint uStack44;
  
  iVar3 = FUN_802860d0();
  iVar12 = *(int *)(iVar3 + 0xb8);
  iVar4 = FUN_8002b9ec();
  local_38[0] = 0;
  if (iVar4 != 0) {
    cVar6 = FUN_8001ffb4(0x149);
    cVar7 = FUN_8001ffb4(0x14c);
    cVar8 = FUN_8001ffb4(0x14d);
    cVar9 = FUN_8001ffb4(0x14e);
    cVar10 = FUN_8001ffb4(0x14a);
    cVar11 = FUN_8001ffb4(0x14b);
    if (((((cVar6 == '\0') || (cVar7 == '\0')) || (cVar8 == '\0')) ||
        ((cVar9 == '\0' || (cVar10 == '\0')))) || (cVar11 == '\0')) {
      if (((*(byte *)(iVar12 + 0x15) >> 6 & 1) == 0) && (cVar6 != '\0')) {
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xbf | 0x40;
        FUN_8000bb18(0,0x109);
      }
      else if (((*(byte *)(iVar12 + 0x15) >> 5 & 1) == 0) && (cVar7 != '\0')) {
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xdf | 0x20;
        FUN_8000bb18(0,0x109);
      }
      else if (((*(byte *)(iVar12 + 0x15) >> 4 & 1) == 0) && (cVar8 != '\0')) {
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xef | 0x10;
        FUN_8000bb18(0,0x109);
      }
      else if (((*(byte *)(iVar12 + 0x15) >> 3 & 1) == 0) && (cVar9 != '\0')) {
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xf7 | 8;
        FUN_8000bb18(0,0x109);
      }
      else if (((*(byte *)(iVar12 + 0x15) >> 2 & 1) == 0) && (cVar10 != '\0')) {
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xfb | 4;
        FUN_8000bb18(0,0x109);
      }
      else if (((*(byte *)(iVar12 + 0x15) >> 1 & 1) == 0) && (cVar11 != '\0')) {
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xfd | 2;
        FUN_8000bb18(0,0x109);
      }
    }
    if ((*(int *)(iVar3 + 0xf4) != 0) &&
       (*(int *)(iVar3 + 0xf4) = *(int *)(iVar3 + 0xf4) + -1, *(int *)(iVar3 + 0xf4) == 0)) {
      FUN_80088c94(7,1);
      FUN_80008cbc(iVar3,iVar4,0xcc,0);
      FUN_80008cbc(iVar3,iVar4,0xcd,0);
      FUN_80008cbc(iVar3,iVar4,0x222,0);
    }
    FUN_801c70f0(iVar3);
    uVar5 = FUN_800481b0(0x22);
    FUN_8004350c(uVar5,1,0);
    FUN_801d7ed4(iVar12 + 0x13,2,0xffffffff,0xffffffff,0xdd2,0xb);
    FUN_801d8060(iVar12 + 0x13,1,0xffffffff,0xffffffff,0xcbb,8);
    FUN_801d7ed4(iVar12 + 0x13,4,0xffffffff,0xffffffff,0xcbb,0xc4);
    fVar2 = FLOAT_803e503c;
    if (*(float *)(iVar12 + 4) <= FLOAT_803e503c) {
      switch(*(undefined *)(iVar12 + 0x14)) {
      case 0:
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xbfff;
        fVar1 = *(float *)(iVar12 + 8) - FLOAT_803db414;
        *(float *)(iVar12 + 8) = fVar1;
        if (fVar1 <= fVar2) {
          FUN_8000bb18(iVar3,0x343);
          uStack44 = FUN_800221a0(500,1000);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          *(float *)(iVar12 + 8) = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e5030);
        }
        if ((*(byte *)(iVar3 + 0xaf) & 1) != 0) {
          *(undefined *)(iVar12 + 0x14) = 5;
          FUN_800200e8(0x129,0);
          FUN_800200e8(0x5af,0);
          FUN_800200e8(0xdd2,1);
          (**(code **)(*DAT_803dca54 + 0x48))(0,iVar3,0xffffffff);
          FUN_8000a518(0xd8,1);
        }
        break;
      case 1:
        if (*(char *)(iVar12 + 0x15) < '\0') {
          FUN_800200e8(0x148,1);
          *(undefined *)(iVar12 + 0x14) = 2;
          FUN_800146bc(0x1d,0x4e);
          FUN_8001469c();
        }
        break;
      case 2:
        *(undefined *)(iVar12 + 0x12) = 0;
        iVar3 = FUN_8001ffb4(0x149);
        if (iVar3 != 0) {
          *(char *)(iVar12 + 0x12) = *(char *)(iVar12 + 0x12) + '\x01';
        }
        iVar3 = FUN_8001ffb4(0x14b);
        if (iVar3 != 0) {
          *(char *)(iVar12 + 0x12) = *(char *)(iVar12 + 0x12) + '\x01';
        }
        iVar3 = FUN_8001ffb4(0x14e);
        if (iVar3 != 0) {
          *(char *)(iVar12 + 0x12) = *(char *)(iVar12 + 0x12) + '\x01';
        }
        iVar3 = FUN_8001ffb4(0x14d);
        if (iVar3 != 0) {
          *(char *)(iVar12 + 0x12) = *(char *)(iVar12 + 0x12) + '\x01';
        }
        iVar3 = FUN_8001ffb4(0x14c);
        if (iVar3 != 0) {
          *(char *)(iVar12 + 0x12) = *(char *)(iVar12 + 0x12) + '\x01';
        }
        iVar3 = FUN_8001ffb4(0x14a);
        if (iVar3 != 0) {
          *(char *)(iVar12 + 0x12) = *(char *)(iVar12 + 0x12) + '\x01';
        }
        if (*(char *)(iVar12 + 0x12) == '\x06') {
          *(undefined *)(iVar12 + 0x14) = 6;
          FUN_8001467c();
          FUN_800200e8(0xdd2,0);
          *(float *)(iVar12 + 4) = FLOAT_803e5040;
          (**(code **)(*DAT_803dca4c + 8))(0x1e,1);
          FUN_8000bb18(0,0x7e);
        }
        else {
          iVar3 = FUN_80014670();
          if (iVar3 == 0) {
            *(undefined *)(iVar12 + 0x12) = 0;
          }
          else {
            *(undefined *)(iVar12 + 0x14) = 7;
            iVar3 = FUN_80036f50(0x10,local_38);
            for (; local_38[0] != 0; local_38[0] = local_38[0] + -1) {
              FUN_8002cbc4(*(undefined4 *)(iVar3 + local_38[0] * 4 + -4));
            }
            *(float *)(iVar12 + 4) = FLOAT_803e5040;
            (**(code **)(*DAT_803dca4c + 8))(0x1e,1);
          }
        }
        break;
      case 3:
        iVar4 = FUN_80296554(iVar4,0x80);
        if (iVar4 == 0) {
          FUN_80009a94(3);
          (**(code **)(*DAT_803dca54 + 0x48))(1,iVar3,0xffffffff);
          *(undefined *)(iVar12 + 0x14) = 4;
          FUN_800200e8(0x36a,0);
          (**(code **)(*DAT_803dcaac + 0x50))(0xd,0,1);
          (**(code **)(*DAT_803dcaac + 0x50))(0xd,1,1);
          (**(code **)(*DAT_803dcaac + 0x50))(0xd,5,1);
          (**(code **)(*DAT_803dcaac + 0x50))(0xd,10,1);
          (**(code **)(*DAT_803dcaac + 0x50))(0xd,0xb,1);
          FUN_800200e8(0xc91,1);
          FUN_800200e8(0xe05,0);
        }
        else {
          FUN_800200e8(0x129,1);
          *(undefined *)(iVar12 + 0x14) = 4;
        }
        break;
      case 4:
        *(undefined *)(iVar12 + 0x14) = 0;
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0x7f;
        FUN_800200e8(0xdd2,0);
        FUN_800200e8(0x129,1);
        FUN_800200e8(0x149,0);
        FUN_800200e8(0x14c,0);
        FUN_800200e8(0x14d,0);
        FUN_800200e8(0x14e,0);
        FUN_800200e8(0x14a,0);
        FUN_800200e8(0x14b,0);
        FUN_800200e8(0x14b,0);
        FUN_800200e8(0x5af,1);
        FUN_800200e8(0x148,0);
        FUN_800200e8(0xe37,0);
        FUN_800200e8(0xe3a,0);
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xbf;
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xdf;
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xef;
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xf7;
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xfb;
        *(byte *)(iVar12 + 0x15) = *(byte *)(iVar12 + 0x15) & 0xfd;
        break;
      case 5:
        *(float *)(iVar12 + 4) = FLOAT_803e5040;
        (**(code **)(*DAT_803dca4c + 0xc))(0x1e,1);
        *(undefined *)(iVar12 + 0x14) = 1;
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
        break;
      case 6:
        *(undefined *)(iVar12 + 0x14) = 3;
        break;
      case 7:
        *(undefined *)(iVar12 + 0x14) = 4;
        FUN_800200e8(0xdd2,0);
        FUN_800200e8(0xe37,1);
      }
    }
    else {
      *(float *)(iVar12 + 4) = *(float *)(iVar12 + 4) - FLOAT_803db414;
      if (*(float *)(iVar12 + 4) <= fVar2) {
        *(float *)(iVar12 + 4) = fVar2;
      }
    }
  }
  FUN_8028611c();
  return;
}

