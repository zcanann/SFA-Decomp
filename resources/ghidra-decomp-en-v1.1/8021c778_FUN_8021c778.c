// Function: FUN_8021c778
// Entry: 8021c778
// Size: 1476 bytes

void FUN_8021c778(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 *param_4)

{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  float *pfVar6;
  double dVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_80286840();
  uVar5 = (uint)((ulonglong)uVar8 >> 0x20);
  pfVar6 = *(float **)(uVar5 + 0xb8);
  iVar3 = FUN_8002bac4();
  *param_4 = 0xffffffff;
  fVar1 = FLOAT_803e76d4;
  switch((uint)uVar8 & 0xff) {
  case 1:
    iVar3 = FUN_8002bac4();
    pfVar6[0x44] = FLOAT_803e7710 * -pfVar6[0x44];
    *pfVar6 = FLOAT_803e76d4;
    if (*(uint *)(iVar3 + 0x30) == uVar5) {
      FUN_8000faf8();
      dVar7 = (double)pfVar6[0x44];
      if (dVar7 < (double)FLOAT_803e76d4) {
        dVar7 = -dVar7;
      }
      FUN_8000e69c(dVar7);
    }
    break;
  case 3:
    if ((((*(byte *)(pfVar6 + 0x5e) >> 6 & 1) == 0) && (FLOAT_803e76d4 < pfVar6[0x44])) &&
       (-1 < (char)*(byte *)(pfVar6 + 0x5e))) {
      iVar3 = FUN_8002bac4();
      pfVar6[0x44] = FLOAT_803e7710 * -pfVar6[0x44];
      *pfVar6 = FLOAT_803e76d4;
      if (*(uint *)(iVar3 + 0x30) == uVar5) {
        FUN_8000faf8();
        dVar7 = (double)pfVar6[0x44];
        if (dVar7 < (double)FLOAT_803e76d4) {
          dVar7 = -dVar7;
        }
        FUN_8000e69c(dVar7);
      }
      goto LAB_8021cd24;
    }
    break;
  case 4:
    if (FLOAT_803e76d4 < pfVar6[0x44]) {
      if ((*(byte *)(pfVar6 + 0x5e) >> 6 & 1) == 0) {
        uVar5 = FUN_80020078(0x661);
        if (uVar5 == 0) {
          FUN_800201ac(0x788,1);
          *(byte *)(pfVar6 + 0x5e) = *(byte *)(pfVar6 + 0x5e) & 0xe1 | 2;
          *pfVar6 = FLOAT_803e76d4;
        }
        else {
          fVar1 = FLOAT_803e76d0;
          if (*pfVar6 < FLOAT_803e76d4) {
            fVar1 = FLOAT_803e770c;
          }
          pfVar6[0x45] = pfVar6[0x45] + fVar1;
        }
      }
      else {
        FUN_800201ac(0x660,1);
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
      fVar1 = FLOAT_803e7718;
      if (*pfVar6 < FLOAT_803e76d4) {
        fVar1 = FLOAT_803e7714;
      }
      pfVar6[0x45] = pfVar6[0x45] + fVar1;
    }
    break;
  case 7:
    if (*pfVar6 <= FLOAT_803e76d4) {
      *(byte *)(pfVar6 + 0x5e) = *(byte *)(pfVar6 + 0x5e) & 0xe1 | 6;
      *pfVar6 = fVar1;
      FUN_8000bb38(uVar5,0x30b);
    }
    break;
  case 9:
    if (pfVar6[0x44] < FLOAT_803e76d4) {
      uVar5 = FUN_80020078(0x661);
      if (uVar5 == 0) {
        *(byte *)(pfVar6 + 0x5e) = *(byte *)(pfVar6 + 0x5e) & 0xe1 | 2;
        *pfVar6 = FLOAT_803e76d4;
      }
      else {
        fVar1 = FLOAT_803e76d0;
        if (*pfVar6 < FLOAT_803e76d4) {
          fVar1 = FLOAT_803e770c;
        }
        pfVar6[0x45] = pfVar6[0x45] + fVar1;
      }
    }
    break;
  case 10:
    if (((*(byte *)((int)pfVar6 + 0x179) >> 6 & 1) != 0) &&
       (uVar5 = FUN_80020078(0x689), uVar5 == 0)) {
      FUN_800201ac(0x689,1);
    }
    break;
  case 0xb:
    if (((*(byte *)((int)pfVar6 + 0x179) >> 6 & 1) != 0) && (*(uint *)(iVar3 + 0x30) == uVar5)) {
      FUN_800201ac(0x68a,1);
    }
    break;
  case 0xc:
    if (((*(byte *)((int)pfVar6 + 0x179) >> 6 & 1) != 0) && (*(uint *)(iVar3 + 0x30) == uVar5)) {
      FUN_800201ac(0x68b,1);
    }
    break;
  case 0xd:
    uVar4 = FUN_80020078(0x68a);
    if ((uVar4 != 0) && (FLOAT_803e76d4 <= *pfVar6)) {
      iVar3 = FUN_8002bac4();
      pfVar6[0x44] = FLOAT_803e7710 * -pfVar6[0x44];
      *pfVar6 = FLOAT_803e76d4;
      if (*(uint *)(iVar3 + 0x30) == uVar5) {
        FUN_8000faf8();
        dVar7 = (double)pfVar6[0x44];
        if (dVar7 < (double)FLOAT_803e76d4) {
          dVar7 = -dVar7;
        }
        FUN_8000e69c(dVar7);
      }
    }
    break;
  case 0xe:
    if (((*(byte *)((int)pfVar6 + 0x179) >> 6 & 1) != 0) && (*pfVar6 <= FLOAT_803e76d4)) {
      iVar3 = FUN_8002bac4();
      pfVar6[0x44] = FLOAT_803e7710 * -pfVar6[0x44];
      *pfVar6 = FLOAT_803e76d4;
      if (*(uint *)(iVar3 + 0x30) == uVar5) {
        FUN_8000faf8();
        dVar7 = (double)pfVar6[0x44];
        if (dVar7 < (double)FLOAT_803e76d4) {
          dVar7 = -dVar7;
        }
        FUN_8000e69c(dVar7);
      }
    }
    break;
  case 0xf:
    if ((*(byte *)(pfVar6 + 0x5e) >> 6 & 1) == 0) {
      FUN_800201ac(0x788,1);
    }
    break;
  case 0x10:
    fVar1 = *pfVar6;
    fVar2 = fVar1;
    if (fVar1 < FLOAT_803e76d4) {
      fVar2 = -fVar1;
    }
    if (FLOAT_803e76d0 == fVar2) {
      *pfVar6 = fVar1 * FLOAT_803e771c;
    }
    else {
      *pfVar6 = FLOAT_803e76d0 * fVar1;
    }
    FUN_8000bb38(uVar5,0x309);
    break;
  case 0x11:
    if (FLOAT_803e76d4 <= *pfVar6) {
      *(byte *)(pfVar6 + 0x5e) = *(byte *)(pfVar6 + 0x5e) & 0xe1 | 8;
      *pfVar6 = fVar1;
      FUN_8000bb38(uVar5,0x30b);
    }
    break;
  case 0x14:
    uVar5 = countLeadingZeros(*(byte *)((int)pfVar6 + 0x179) >> 4 & 1);
    *(byte *)((int)pfVar6 + 0x179) =
         (byte)((uVar5 >> 5 & 0xff) << 4) & 0x10 | *(byte *)((int)pfVar6 + 0x179) & 0xef;
    break;
  case 0x15:
    *(byte *)((int)pfVar6 + 0x179) = *(byte *)((int)pfVar6 + 0x179) & 0xfd | 2;
    *pfVar6 = FLOAT_803e76d4;
  }
  uVar5 = param_3 & 0xff;
  if (uVar5 == 8) {
    uVar5 = FUN_80020078(0x67f);
    if (uVar5 == 0) {
      *param_4 = 0;
    }
    else {
      *param_4 = 1;
    }
  }
  else if (uVar5 < 8) {
    if (uVar5 == 2) {
      FUN_800201ac(0x7ba,1);
    }
  }
  else if (uVar5 == 0x13) {
    *param_4 = 1;
  }
  else if ((uVar5 < 0x13) && (0x11 < uVar5)) {
    *param_4 = 0;
  }
LAB_8021cd24:
  FUN_8028688c();
  return;
}

