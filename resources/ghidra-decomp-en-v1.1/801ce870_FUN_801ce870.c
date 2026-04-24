// Function: FUN_801ce870
// Entry: 801ce870
// Size: 1880 bytes

void FUN_801ce870(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)

{
  char cVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  float fVar6;
  bool bVar9;
  int iVar7;
  uint uVar8;
  float *pfVar10;
  int iVar11;
  int *piVar12;
  uint *puVar13;
  undefined8 extraout_f1;
  double dVar14;
  undefined8 uVar15;
  undefined8 local_28;
  
  uVar15 = FUN_80286834();
  uVar2 = (uint)((ulonglong)uVar15 >> 0x20);
  pfVar10 = (float *)uVar15;
  uVar3 = FUN_80036f50(0xf,uVar2,(float *)0x0);
  switch(*(undefined *)(pfVar10 + 0x102)) {
  case 9:
    *pfVar10 = *pfVar10 + FLOAT_803dc074;
    if (FLOAT_803e5ec0 < *pfVar10) {
      FUN_8000bb38(uVar2,0x150);
      *pfVar10 = *pfVar10 - FLOAT_803e5ec0;
    }
    local_28 = (double)CONCAT44(0x43300000,
                                (int)*(short *)(param_11 + 0x18) * (int)*(short *)(param_11 + 0x18)
                                ^ 0x80000000);
    if (pfVar10[6] < (float)(local_28 - DOUBLE_803e5eb8)) {
      *(undefined *)(pfVar10 + 0x102) = 10;
    }
    break;
  case 10:
    if ((*(byte *)(pfVar10 + 0x10f) & 2) != 0) {
      *(undefined *)(pfVar10 + 0x102) = 0xb;
    }
    break;
  case 0xb:
    *pfVar10 = *pfVar10 + FLOAT_803dc074;
    if (FLOAT_803e5ec0 < *pfVar10) {
      FUN_8000bb38(uVar2,0x150);
      *pfVar10 = *pfVar10 - FLOAT_803e5ec0;
    }
    iVar7 = FUN_8003811c(uVar2);
    if (iVar7 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(3,uVar3,0xffffffff);
      *(byte *)(pfVar10 + 0x10f) = *(byte *)(pfVar10 + 0x10f) | 0x10;
      *(undefined *)(pfVar10 + 0x102) = 0xd;
      FUN_800201ac(0xce1,1);
      FUN_800201ac(0xd32,1);
    }
    break;
  case 0xc:
    (**(code **)(*DAT_803dd6d4 + 0x54))(uVar3,0x5aa);
    (**(code **)(*DAT_803dd6d4 + 0x48))(3,uVar3,0x30);
    *(undefined *)(pfVar10 + 0x102) = 0xd;
    break;
  case 0xd:
    iVar7 = 4;
    uVar8 = FUN_80020078(0x120);
    if (uVar8 == 0) {
      iVar7 = 3;
    }
    uVar8 = FUN_80020078(0x121);
    if (uVar8 == 0) {
      iVar7 = iVar7 + -1;
    }
    puVar13 = &DAT_8032751c;
    piVar12 = &DAT_8032750c;
    for (iVar11 = 0; iVar11 < iVar7; iVar11 = iVar11 + 1) {
      uVar8 = FUN_80020078(*puVar13);
      if (uVar8 != 0) {
        FUN_800201ac(*puVar13,0);
      }
      iVar4 = FUN_8002e1ac(*piVar12);
      iVar5 = FUN_80296878((int)pfVar10[10]);
      if (iVar5 == iVar4) {
        FUN_8014cae4(iVar4,pfVar10[10]);
      }
      else {
        iVar5 = FUN_80163d68((float *)(iVar4 + 0x18));
        if ((iVar5 == 0) ||
           (dVar14 = FUN_80021794((float *)(iVar5 + 0x18),(float *)(iVar4 + 0x18)),
           (double)FLOAT_803e5ec4 <= dVar14)) {
          dVar14 = FUN_80021794((float *)((int)pfVar10[10] + 0x18),(float *)(iVar4 + 0x18));
          if (dVar14 < (double)FLOAT_803e5ec4) {
            FUN_8014cae4(iVar4,pfVar10[10]);
          }
          else {
            FUN_8014cae4(iVar4,uVar2);
          }
        }
        else {
          FUN_8014cae4(iVar4,iVar5);
        }
      }
      puVar13 = puVar13 + 1;
      piVar12 = piVar12 + 1;
    }
    fVar6 = (float)FUN_80163d68(pfVar10 + 3);
    if (fVar6 != 0.0) {
      iVar7 = FUN_8002ba84();
      (**(code **)(**(int **)(iVar7 + 0x68) + 0x28))(iVar7,uVar2,1,1);
    }
    pfVar10[0x12] = (float)&DAT_803dcc10;
    if (((pfVar10[9] == 0.0) && (iVar7 = *(int *)(uVar2 + 0x4c), fVar6 != 0.0)) &&
       (*(short *)((int)fVar6 + 0x46) == 0x3fb)) {
      dVar14 = FUN_80021730((float *)(uVar2 + 0x18),(float *)((int)fVar6 + 0x18));
      iVar7 = (int)*(short *)(iVar7 + 0x18);
      local_28 = (double)CONCAT44(0x43300000,iVar7 * iVar7 ^ 0x80000000);
      if (dVar14 < (double)(float)(local_28 - DOUBLE_803e5eb8)) {
        bVar9 = FUN_8000b598(uVar2,0x10);
        if (!bVar9) {
          FUN_8000bb38(uVar2,0x38a);
        }
        iVar7 = (**(code **)(**(int **)((int)fVar6 + 0x68) + 0x30))(fVar6);
        if (iVar7 == 0) {
          (**(code **)(**(int **)((int)fVar6 + 0x68) + 0x2c))(fVar6,pfVar10 + 3);
          pfVar10[9] = fVar6;
          *(undefined *)(pfVar10 + 0x102) = 0xe;
        }
      }
    }
    if ((*(byte *)(pfVar10 + 0x10f) & 0x40) == 0) {
      (**(code **)(*DAT_803dd6e8 + 0x58))(200,0x5d0);
      *(byte *)(pfVar10 + 0x10f) = *(byte *)(pfVar10 + 0x10f) | 0x40;
    }
    break;
  case 0xe:
    dVar14 = FUN_80021730(pfVar10 + 3,(float *)((int)pfVar10[9] + 0x18));
    if (dVar14 < (double)FLOAT_803e5ec8) {
      FUN_8000bb38(uVar2,0x38b);
      FUN_80163e2c((int)pfVar10[9]);
      *(undefined *)(pfVar10 + 0x102) = 0xf;
    }
    break;
  case 0xf:
    if ((*(byte *)(pfVar10 + 0x10f) & 2) != 0) {
      FUN_8002cc9c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)pfVar10[9]);
      pfVar10[9] = 0.0;
      cVar1 = *(char *)((int)pfVar10 + 0x43f) + '\x01';
      *(char *)((int)pfVar10 + 0x43f) = cVar1;
      if ('\x03' < cVar1) {
        *(undefined *)((int)pfVar10 + 0x43f) = 3;
      }
      FUN_800201ac(0x48b,(int)*(char *)((int)pfVar10 + 0x43f));
      uVar8 = (uint)*(char *)((int)pfVar10 + 0x43f);
      if ((int)uVar8 < 3) {
        if ((uVar8 & 1 ^ uVar8 >> 0x1f) == uVar8 >> 0x1f) {
          FUN_8000bb38(uVar2,0x14f);
        }
        *(undefined *)(pfVar10 + 0x102) = 0xd;
      }
      else {
        *(undefined *)(pfVar10 + 0x102) = 0x11;
      }
    }
    break;
  case 0x10:
    (**(code **)(*DAT_803dd6d4 + 0x54))(uVar3,0x157c);
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,uVar3,2);
    *(undefined *)(pfVar10 + 0x102) = 0x13;
    break;
  case 0x11:
    if (((*(ushort *)((int)pfVar10[10] + 0xb0) & 0x1000) == 0) && (FLOAT_803e5ecc <= pfVar10[2])) {
      FUN_8000bb38(uVar2,0x109);
      (**(code **)(*DAT_803dd6cc + 8))(0x14,1);
      *(undefined *)(pfVar10 + 0x102) = 0x12;
      FUN_800201ac(0xd32,0);
      *(byte *)(pfVar10 + 0x10f) = *(byte *)(pfVar10 + 0x10f) & 0xbf;
      (**(code **)(*DAT_803dd6e8 + 100))();
    }
    break;
  case 0x12:
    if (((*(ushort *)((int)pfVar10[10] + 0xb0) & 0x1000) == 0) &&
       (iVar7 = (**(code **)(*DAT_803dd6cc + 0x14))(), iVar7 != 0)) {
      FUN_800201ac(0x102,1);
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,uVar3,0xffffffff);
      *(undefined *)(pfVar10 + 0x102) = 0x13;
    }
    break;
  default:
    uVar8 = FUN_80020078(0x224);
    if (uVar8 == 0) {
      uVar8 = FUN_80020078(0xea7);
      if (uVar8 == 0) {
        FUN_800201ac(0xea7,1);
        FUN_800201ac(0x9d5,1);
      }
      pfVar10[0x12] = (float)&DAT_803dcc14;
    }
    else {
      pfVar10[0x12] = (float)&DAT_803dcc18;
    }
    FUN_801ce62c(uVar2,(int)pfVar10);
  }
  if ((*(byte *)(pfVar10 + 0x10f) & 0x40) != 0) {
    local_28 = (double)CONCAT44(0x43300000,(int)*(char *)((int)pfVar10 + 0x43f) ^ 0x80000000);
    if (pfVar10[2] < FLOAT_803e5ed0 * (float)(local_28 - DOUBLE_803e5eb8)) {
      pfVar10[2] = pfVar10[2] + FLOAT_803dc074;
    }
    if (pfVar10[2] < FLOAT_803e5ecc) {
      (**(code **)(*DAT_803dd6e8 + 0x5c))((int)pfVar10[2]);
    }
    else {
      (**(code **)(*DAT_803dd6e8 + 0x5c))(200);
    }
  }
  FUN_80286880();
  return;
}

