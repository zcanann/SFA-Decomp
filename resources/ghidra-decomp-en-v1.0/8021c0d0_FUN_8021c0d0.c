// Function: FUN_8021c0d0
// Entry: 8021c0d0
// Size: 1476 bytes

void FUN_8021c0d0(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 *param_4)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  float *pfVar6;
  double dVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_802860dc();
  iVar5 = (int)((ulonglong)uVar8 >> 0x20);
  pfVar6 = *(float **)(iVar5 + 0xb8);
  iVar4 = FUN_8002b9ec();
  *param_4 = 0xffffffff;
  fVar1 = FLOAT_803e6a3c;
  switch((uint)uVar8 & 0xff) {
  case 1:
    iVar4 = FUN_8002b9ec();
    pfVar6[0x44] = FLOAT_803e6a78 * -pfVar6[0x44];
    *pfVar6 = FLOAT_803e6a3c;
    if (*(int *)(iVar4 + 0x30) == iVar5) {
      FUN_8000fad8();
      dVar7 = (double)pfVar6[0x44];
      if (dVar7 < (double)FLOAT_803e6a3c) {
        dVar7 = -dVar7;
      }
      FUN_8000e67c(dVar7);
    }
    break;
  case 3:
    if ((((*(byte *)(pfVar6 + 0x5e) >> 6 & 1) == 0) && (FLOAT_803e6a3c < pfVar6[0x44])) &&
       (-1 < (char)*(byte *)(pfVar6 + 0x5e))) {
      iVar4 = FUN_8002b9ec();
      pfVar6[0x44] = FLOAT_803e6a78 * -pfVar6[0x44];
      *pfVar6 = FLOAT_803e6a3c;
      if (*(int *)(iVar4 + 0x30) == iVar5) {
        FUN_8000fad8();
        dVar7 = (double)pfVar6[0x44];
        if (dVar7 < (double)FLOAT_803e6a3c) {
          dVar7 = -dVar7;
        }
        FUN_8000e67c(dVar7);
      }
      goto LAB_8021c67c;
    }
    break;
  case 4:
    if (FLOAT_803e6a3c < pfVar6[0x44]) {
      if ((*(byte *)(pfVar6 + 0x5e) >> 6 & 1) == 0) {
        iVar5 = FUN_8001ffb4(0x661);
        if (iVar5 == 0) {
          FUN_800200e8(0x788,1);
          *(byte *)(pfVar6 + 0x5e) = *(byte *)(pfVar6 + 0x5e) & 0xe1 | 2;
          *pfVar6 = FLOAT_803e6a3c;
        }
        else {
          fVar1 = FLOAT_803e6a38;
          if (*pfVar6 < FLOAT_803e6a3c) {
            fVar1 = FLOAT_803e6a74;
          }
          pfVar6[0x45] = pfVar6[0x45] + fVar1;
        }
      }
      else {
        FUN_800200e8(0x660,1);
      }
    }
    break;
  case 5:
    if ((*(byte *)(pfVar6 + 0x5e) >> 6 & 1) == 0) {
      *(byte *)(pfVar6 + 0x5e) = *(byte *)(pfVar6 + 0x5e) & 0xe1 | 4;
    }
    break;
  case 6:
    if ((*(byte *)(pfVar6 + 0x5e) >> 6 & 1) == 0) {
      fVar1 = FLOAT_803e6a80;
      if (*pfVar6 < FLOAT_803e6a3c) {
        fVar1 = FLOAT_803e6a7c;
      }
      pfVar6[0x45] = pfVar6[0x45] + fVar1;
    }
    break;
  case 7:
    if (*pfVar6 <= FLOAT_803e6a3c) {
      *(byte *)(pfVar6 + 0x5e) = *(byte *)(pfVar6 + 0x5e) & 0xe1 | 6;
      *pfVar6 = fVar1;
      FUN_8000bb18(iVar5,0x30b);
    }
    break;
  case 9:
    if (pfVar6[0x44] < FLOAT_803e6a3c) {
      iVar5 = FUN_8001ffb4(0x661);
      if (iVar5 == 0) {
        *(byte *)(pfVar6 + 0x5e) = *(byte *)(pfVar6 + 0x5e) & 0xe1 | 2;
        *pfVar6 = FLOAT_803e6a3c;
      }
      else {
        fVar1 = FLOAT_803e6a38;
        if (*pfVar6 < FLOAT_803e6a3c) {
          fVar1 = FLOAT_803e6a74;
        }
        pfVar6[0x45] = pfVar6[0x45] + fVar1;
      }
    }
    break;
  case 10:
    if (((*(byte *)((int)pfVar6 + 0x179) >> 6 & 1) != 0) &&
       (iVar5 = FUN_8001ffb4(0x689), iVar5 == 0)) {
      FUN_800200e8(0x689,1);
    }
    break;
  case 0xb:
    if (((*(byte *)((int)pfVar6 + 0x179) >> 6 & 1) != 0) && (*(int *)(iVar4 + 0x30) == iVar5)) {
      FUN_800200e8(0x68a,1);
    }
    break;
  case 0xc:
    if (((*(byte *)((int)pfVar6 + 0x179) >> 6 & 1) != 0) && (*(int *)(iVar4 + 0x30) == iVar5)) {
      FUN_800200e8(0x68b,1);
    }
    break;
  case 0xd:
    iVar4 = FUN_8001ffb4(0x68a);
    if ((iVar4 != 0) && (FLOAT_803e6a3c <= *pfVar6)) {
      iVar4 = FUN_8002b9ec();
      pfVar6[0x44] = FLOAT_803e6a78 * -pfVar6[0x44];
      *pfVar6 = FLOAT_803e6a3c;
      if (*(int *)(iVar4 + 0x30) == iVar5) {
        FUN_8000fad8();
        dVar7 = (double)pfVar6[0x44];
        if (dVar7 < (double)FLOAT_803e6a3c) {
          dVar7 = -dVar7;
        }
        FUN_8000e67c(dVar7);
      }
    }
    break;
  case 0xe:
    if (((*(byte *)((int)pfVar6 + 0x179) >> 6 & 1) != 0) && (*pfVar6 <= FLOAT_803e6a3c)) {
      iVar4 = FUN_8002b9ec();
      pfVar6[0x44] = FLOAT_803e6a78 * -pfVar6[0x44];
      *pfVar6 = FLOAT_803e6a3c;
      if (*(int *)(iVar4 + 0x30) == iVar5) {
        FUN_8000fad8();
        dVar7 = (double)pfVar6[0x44];
        if (dVar7 < (double)FLOAT_803e6a3c) {
          dVar7 = -dVar7;
        }
        FUN_8000e67c(dVar7);
      }
    }
    break;
  case 0xf:
    if ((*(byte *)(pfVar6 + 0x5e) >> 6 & 1) == 0) {
      FUN_800200e8(0x788,1);
    }
    break;
  case 0x10:
    fVar1 = *pfVar6;
    fVar2 = fVar1;
    if (fVar1 < FLOAT_803e6a3c) {
      fVar2 = -fVar1;
    }
    if (FLOAT_803e6a38 == fVar2) {
      *pfVar6 = fVar1 * FLOAT_803e6a84;
    }
    else {
      *pfVar6 = FLOAT_803e6a38 * fVar1;
    }
    FUN_8000bb18(iVar5,0x309);
    break;
  case 0x11:
    if (FLOAT_803e6a3c <= *pfVar6) {
      *(byte *)(pfVar6 + 0x5e) = *(byte *)(pfVar6 + 0x5e) & 0xe1 | 8;
      *pfVar6 = fVar1;
      FUN_8000bb18(iVar5,0x30b);
    }
    break;
  case 0x14:
    uVar3 = countLeadingZeros(*(byte *)((int)pfVar6 + 0x179) >> 4 & 1);
    *(byte *)((int)pfVar6 + 0x179) =
         (byte)((uVar3 >> 5 & 0xff) << 4) & 0x10 | *(byte *)((int)pfVar6 + 0x179) & 0xef;
    break;
  case 0x15:
    *(byte *)((int)pfVar6 + 0x179) = *(byte *)((int)pfVar6 + 0x179) & 0xfd | 2;
    *pfVar6 = FLOAT_803e6a3c;
  }
  param_3 = param_3 & 0xff;
  if (param_3 == 8) {
    iVar5 = FUN_8001ffb4(0x67f);
    if (iVar5 == 0) {
      *param_4 = 0;
    }
    else {
      *param_4 = 1;
    }
  }
  else if (param_3 < 8) {
    if (param_3 == 2) {
      FUN_800200e8(0x7ba,1);
    }
  }
  else if (param_3 == 0x13) {
    *param_4 = 1;
  }
  else if ((param_3 < 0x13) && (0x11 < param_3)) {
    *param_4 = 0;
  }
LAB_8021c67c:
  FUN_80286128(1);
  return;
}

