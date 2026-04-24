// Function: FUN_801ce2bc
// Entry: 801ce2bc
// Size: 1880 bytes

void FUN_801ce2bc(undefined4 param_1,undefined4 param_2,int param_3)

{
  char cVar2;
  uint uVar1;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  float fVar6;
  int iVar7;
  int iVar8;
  float *pfVar9;
  int iVar10;
  undefined4 *puVar11;
  undefined4 *puVar12;
  double dVar13;
  undefined8 uVar14;
  double local_28;
  
  uVar14 = FUN_802860d0();
  iVar7 = (int)((ulonglong)uVar14 >> 0x20);
  pfVar9 = (float *)uVar14;
  uVar3 = FUN_80036e58(0xf,iVar7,0);
  switch(*(undefined *)(pfVar9 + 0x102)) {
  case 9:
    *pfVar9 = *pfVar9 + FLOAT_803db414;
    if (FLOAT_803e5228 < *pfVar9) {
      FUN_8000bb18(iVar7,0x150);
      *pfVar9 = *pfVar9 - FLOAT_803e5228;
    }
    local_28 = (double)CONCAT44(0x43300000,
                                (int)*(short *)(param_3 + 0x18) * (int)*(short *)(param_3 + 0x18) ^
                                0x80000000);
    if (pfVar9[6] < (float)(local_28 - DOUBLE_803e5220)) {
      *(undefined *)(pfVar9 + 0x102) = 10;
    }
    break;
  case 10:
    if ((*(byte *)(pfVar9 + 0x10f) & 2) != 0) {
      *(undefined *)(pfVar9 + 0x102) = 0xb;
    }
    break;
  case 0xb:
    *pfVar9 = *pfVar9 + FLOAT_803db414;
    if (FLOAT_803e5228 < *pfVar9) {
      FUN_8000bb18(iVar7,0x150);
      *pfVar9 = *pfVar9 - FLOAT_803e5228;
    }
    iVar7 = FUN_80038024(iVar7);
    if (iVar7 != 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(3,uVar3,0xffffffff);
      *(byte *)(pfVar9 + 0x10f) = *(byte *)(pfVar9 + 0x10f) | 0x10;
      *(undefined *)(pfVar9 + 0x102) = 0xd;
      FUN_800200e8(0xce1,1);
      FUN_800200e8(0xd32,1);
    }
    break;
  case 0xc:
    (**(code **)(*DAT_803dca54 + 0x54))(uVar3,0x5aa);
    (**(code **)(*DAT_803dca54 + 0x48))(3,uVar3,0x30);
    *(undefined *)(pfVar9 + 0x102) = 0xd;
    break;
  case 0xd:
    iVar10 = 4;
    iVar8 = FUN_8001ffb4(0x120);
    if (iVar8 == 0) {
      iVar10 = 3;
    }
    iVar8 = FUN_8001ffb4(0x121);
    if (iVar8 == 0) {
      iVar10 = iVar10 + -1;
    }
    puVar12 = &DAT_803268dc;
    puVar11 = &DAT_803268cc;
    for (iVar8 = 0; iVar8 < iVar10; iVar8 = iVar8 + 1) {
      iVar4 = FUN_8001ffb4(*puVar12);
      if (iVar4 != 0) {
        FUN_800200e8(*puVar12,0);
      }
      iVar4 = FUN_8002e0b4(*puVar11);
      iVar5 = FUN_80296118(pfVar9[10]);
      if (iVar5 == iVar4) {
        FUN_8014c66c(iVar4,pfVar9[10]);
      }
      else {
        iVar5 = FUN_801638bc(iVar4 + 0x18);
        if ((iVar5 == 0) ||
           (dVar13 = (double)FUN_800216d0(iVar5 + 0x18,iVar4 + 0x18),
           (double)FLOAT_803e522c <= dVar13)) {
          dVar13 = (double)FUN_800216d0((int)pfVar9[10] + 0x18,iVar4 + 0x18);
          if (dVar13 < (double)FLOAT_803e522c) {
            FUN_8014c66c(iVar4,pfVar9[10]);
          }
          else {
            FUN_8014c66c(iVar4,iVar7);
          }
        }
        else {
          FUN_8014c66c(iVar4,iVar5);
        }
      }
      puVar12 = puVar12 + 1;
      puVar11 = puVar11 + 1;
    }
    fVar6 = (float)FUN_801638bc(pfVar9 + 3);
    if (fVar6 != 0.0) {
      iVar8 = FUN_8002b9ac();
      (**(code **)(**(int **)(iVar8 + 0x68) + 0x28))(iVar8,iVar7,1,1);
    }
    pfVar9[0x12] = (float)&DAT_803dbfa8;
    if (((pfVar9[9] == 0.0) && (iVar8 = *(int *)(iVar7 + 0x4c), fVar6 != 0.0)) &&
       (*(short *)((int)fVar6 + 0x46) == 0x3fb)) {
      dVar13 = (double)FUN_8002166c(iVar7 + 0x18,(int)fVar6 + 0x18);
      iVar8 = (int)*(short *)(iVar8 + 0x18);
      local_28 = (double)CONCAT44(0x43300000,iVar8 * iVar8 ^ 0x80000000);
      if (dVar13 < (double)(float)(local_28 - DOUBLE_803e5220)) {
        iVar8 = FUN_8000b578(iVar7,0x10);
        if (iVar8 == 0) {
          FUN_8000bb18(iVar7,0x38a);
        }
        iVar7 = (**(code **)(**(int **)((int)fVar6 + 0x68) + 0x30))(fVar6);
        if (iVar7 == 0) {
          (**(code **)(**(int **)((int)fVar6 + 0x68) + 0x2c))(fVar6,pfVar9 + 3);
          pfVar9[9] = fVar6;
          *(undefined *)(pfVar9 + 0x102) = 0xe;
        }
      }
    }
    if ((*(byte *)(pfVar9 + 0x10f) & 0x40) == 0) {
      (**(code **)(*DAT_803dca68 + 0x58))(200,0x5d0);
      *(byte *)(pfVar9 + 0x10f) = *(byte *)(pfVar9 + 0x10f) | 0x40;
    }
    break;
  case 0xe:
    dVar13 = (double)FUN_8002166c(pfVar9 + 3,(int)pfVar9[9] + 0x18);
    if (dVar13 < (double)FLOAT_803e5230) {
      FUN_8000bb18(iVar7,0x38b);
      FUN_80163980(pfVar9[9]);
      *(undefined *)(pfVar9 + 0x102) = 0xf;
    }
    break;
  case 0xf:
    if ((*(byte *)(pfVar9 + 0x10f) & 2) != 0) {
      FUN_8002cbc4(pfVar9[9]);
      pfVar9[9] = 0.0;
      cVar2 = *(char *)((int)pfVar9 + 0x43f) + '\x01';
      *(char *)((int)pfVar9 + 0x43f) = cVar2;
      if ('\x03' < cVar2) {
        *(undefined *)((int)pfVar9 + 0x43f) = 3;
      }
      FUN_800200e8(0x48b,(int)*(char *)((int)pfVar9 + 0x43f));
      uVar1 = (uint)*(char *)((int)pfVar9 + 0x43f);
      if ((int)uVar1 < 3) {
        if ((uVar1 & 1 ^ uVar1 >> 0x1f) == uVar1 >> 0x1f) {
          FUN_8000bb18(iVar7,0x14f);
        }
        *(undefined *)(pfVar9 + 0x102) = 0xd;
      }
      else {
        *(undefined *)(pfVar9 + 0x102) = 0x11;
      }
    }
    break;
  case 0x10:
    (**(code **)(*DAT_803dca54 + 0x54))(uVar3,0x157c);
    (**(code **)(*DAT_803dca54 + 0x48))(1,uVar3,2);
    *(undefined *)(pfVar9 + 0x102) = 0x13;
    break;
  case 0x11:
    if (((*(ushort *)((int)pfVar9[10] + 0xb0) & 0x1000) == 0) && (FLOAT_803e5234 <= pfVar9[2])) {
      FUN_8000bb18(iVar7,0x109);
      (**(code **)(*DAT_803dca4c + 8))(0x14,1);
      *(undefined *)(pfVar9 + 0x102) = 0x12;
      FUN_800200e8(0xd32,0);
      *(byte *)(pfVar9 + 0x10f) = *(byte *)(pfVar9 + 0x10f) & 0xbf;
      (**(code **)(*DAT_803dca68 + 100))();
    }
    break;
  case 0x12:
    if (((*(ushort *)((int)pfVar9[10] + 0xb0) & 0x1000) == 0) &&
       (iVar7 = (**(code **)(*DAT_803dca4c + 0x14))(), iVar7 != 0)) {
      FUN_800200e8(0x102,1);
      (**(code **)(*DAT_803dca54 + 0x48))(1,uVar3,0xffffffff);
      *(undefined *)(pfVar9 + 0x102) = 0x13;
    }
    break;
  default:
    iVar8 = FUN_8001ffb4(0x224);
    if (iVar8 == 0) {
      iVar8 = FUN_8001ffb4(0xea7);
      if (iVar8 == 0) {
        FUN_800200e8(0xea7,1);
        FUN_800200e8(0x9d5,1);
      }
      pfVar9[0x12] = (float)&DAT_803dbfac;
    }
    else {
      pfVar9[0x12] = (float)&DAT_803dbfb0;
    }
    FUN_801ce078(iVar7,pfVar9);
  }
  if ((*(byte *)(pfVar9 + 0x10f) & 0x40) != 0) {
    local_28 = (double)CONCAT44(0x43300000,(int)*(char *)((int)pfVar9 + 0x43f) ^ 0x80000000);
    if (pfVar9[2] < FLOAT_803e5238 * (float)(local_28 - DOUBLE_803e5220)) {
      pfVar9[2] = pfVar9[2] + FLOAT_803db414;
    }
    if (pfVar9[2] < FLOAT_803e5234) {
      (**(code **)(*DAT_803dca68 + 0x5c))((int)pfVar9[2]);
    }
    else {
      (**(code **)(*DAT_803dca68 + 0x5c))(200);
    }
  }
  FUN_8028611c();
  return;
}

