// Function: FUN_802a48ec
// Entry: 802a48ec
// Size: 2076 bytes

void FUN_802a48ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  uint uVar2;
  short *psVar3;
  char cVar7;
  int *piVar4;
  byte bVar8;
  int iVar5;
  undefined2 *puVar6;
  undefined *puVar9;
  undefined4 uVar10;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar11;
  int iVar12;
  int iVar13;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  double dVar14;
  undefined8 uVar15;
  int local_68;
  int local_64;
  int local_60;
  float local_5c;
  undefined auStack_58 [88];
  
  uVar15 = FUN_80286840();
  psVar3 = (short *)((ulonglong)uVar15 >> 0x20);
  iVar5 = (int)uVar15;
  iVar13 = *(int *)(psVar3 + 0x5c);
  local_5c = FLOAT_803e8ce8;
  if (*(char *)(iVar13 + 0x8c8) == 'D') goto LAB_802a4c24;
  if (*(int *)(iVar13 + 0x7f8) == 0) {
    puVar9 = auStack_58;
    uVar10 = 0xfffffebf;
    cVar7 = FUN_802a7c04(psVar3,iVar13,iVar5,puVar9,0xfffffebf);
    uVar15 = extraout_f1_00;
  }
  else {
    puVar9 = auStack_58;
    uVar10 = 0x22;
    cVar7 = FUN_802a7c04(psVar3,iVar13,iVar5,puVar9,0x22);
    uVar15 = extraout_f1;
  }
  if (cVar7 == -1) {
    *(undefined *)(iVar13 + 0x8c2) = 0xff;
    *(undefined *)(iVar13 + 0x8c3) = 0;
  }
  else if (cVar7 == *(char *)(iVar13 + 0x8c2)) {
    bVar8 = *(char *)(iVar13 + 0x8c3) + 1;
    *(byte *)(iVar13 + 0x8c3) = bVar8;
    if (200 < bVar8) {
      *(undefined *)(iVar13 + 0x8c3) = 200;
    }
  }
  else {
    *(char *)(iVar13 + 0x8c2) = cVar7;
    *(undefined *)(iVar13 + 0x8c3) = 0;
  }
  switch(*(undefined *)(iVar13 + 0x8c2)) {
  case 0:
    if ((*(byte *)(iVar13 + 0x3f1) & 1) != 0) {
      *(code **)(iVar5 + 0x308) = FUN_802a0730;
      break;
    }
  default:
    goto switchD_802a49e4_caseD_1;
  case 4:
    DAT_803dd308 = 0xffff;
    *(undefined4 *)(iVar5 + 0x308) = 0;
    break;
  case 5:
    if (*(int *)(iVar13 + 0x7f8) == 0) {
      DAT_803dd308 = 0xffff;
      *(undefined4 *)(iVar5 + 0x308) = 0;
      break;
    }
    goto switchD_802a49e4_caseD_1;
  case 6:
    *(code **)(iVar5 + 0x308) = FUN_8029e240;
    break;
  case 7:
    FUN_802af128(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar3,iVar13,iVar5,
                 puVar9,uVar10,in_r8,in_r9,in_r10);
    break;
  case 8:
    *(undefined4 *)(iVar5 + 0x308) = 0;
    break;
  case 9:
    if ((*(byte *)(iVar13 + 0x3f1) & 1) != 0) {
      *(code **)(iVar5 + 0x308) = FUN_802a0730;
      break;
    }
switchD_802a49e4_caseD_1:
    if ((*(int *)(iVar13 + 0x7f8) == 0) && ((*(byte *)(iVar13 + 0x3f4) >> 6 & 1) != 0)) {
      piVar4 = FUN_80037048(0x41,&local_60);
      for (iVar12 = 0; iVar12 < local_60; iVar12 = iVar12 + 1) {
        DAT_803df0b4 = *piVar4;
        if (((*(byte *)(DAT_803df0b4 + 0xaf) & 4) != 0) &&
           ((*(byte *)(DAT_803df0b4 + 0xaf) & 0x10) == 0)) {
          bVar8 = FUN_8018a778(DAT_803df0b4);
          if (bVar8 == 2) {
            FUN_8011f6d0(2);
            if ((*(uint *)(iVar5 + 0x31c) & 0x100) != 0) {
              FUN_80014b68(0,0x100);
              *(code **)(iVar5 + 0x308) = FUN_80299084;
              goto LAB_802a50f0;
            }
          }
          else if ((1 < bVar8) && (bVar8 < 6)) {
            if (bVar8 < 4) {
              FUN_8011f6d0(2);
              if ((*(uint *)(iVar5 + 0x31c) & 0x100) != 0) {
                FUN_80014b68(0,0x100);
                *(code **)(iVar5 + 0x308) = FUN_80299084;
                goto LAB_802a50f0;
              }
            }
            else {
              FUN_8011f6d0(0xe);
              if ((*(uint *)(iVar5 + 0x31c) & 0x100) != 0) {
                FUN_80014b68(0,0x100);
                *(code **)(iVar5 + 0x308) = FUN_80299084;
                goto LAB_802a50f0;
              }
            }
          }
        }
        piVar4 = piVar4 + 1;
      }
    }
LAB_802a4c24:
    FUN_80037048(0x20,&local_64);
    uVar2 = countLeadingZeros(local_64);
    FUN_800201ac(0xeb5,uVar2 >> 5);
    iVar12 = (**(code **)(*DAT_803dd6e8 + 0x1c))();
    if (iVar12 != 0) {
      iVar12 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x1ee);
      if (iVar12 != 0) {
        psVar11 = (short *)0x0;
        FUN_80014b68(0,0x100);
        iVar5 = FUN_80036f50(0xf,psVar3,&local_5c);
        if (iVar5 != 0) {
          psVar11 = *(short **)(iVar5 + 0x4c);
        }
        if (((psVar11 != (short *)0x0) && (*psVar11 == 0x860)) &&
           ((*(byte *)(iVar5 + 0xaf) & 4) != 0)) {
          FUN_800201ac(0x3f1,1);
          FUN_800201ac(0x3d8,1);
          FUN_800201ac(0x651,1);
        }
        break;
      }
      iVar12 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x953);
      if ((iVar12 != 0) && (DAT_803df0c4 == 0)) {
        uVar15 = FUN_80014b68(0,0x100);
        if ((DAT_803df0cc != 0) && ((*(byte *)(iVar13 + 0x3f4) >> 6 & 1) != 0)) {
          *(undefined *)(iVar13 + 0x8b4) = 1;
          *(byte *)(iVar13 + 0x3f4) = *(byte *)(iVar13 + 0x3f4) & 0xf7 | 8;
        }
        iVar12 = FUN_8002bac4();
        uVar2 = FUN_8002e144();
        if ((uVar2 & 0xff) == 0) {
          DAT_803df0c4 = 0;
        }
        else {
          puVar6 = FUN_8002becc(0x24,0x62d);
          *puVar6 = 0x62d;
          *(undefined *)(puVar6 + 2) = 2;
          *(undefined *)(puVar6 + 3) = 0xff;
          *(undefined *)((int)puVar6 + 5) = 1;
          *(undefined *)((int)puVar6 + 7) = 0xff;
          *(undefined4 *)(puVar6 + 4) = *(undefined4 *)(iVar12 + 0xc);
          *(undefined4 *)(puVar6 + 6) = *(undefined4 *)(iVar12 + 0x10);
          *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(iVar12 + 0x14);
          DAT_803df0c4 = FUN_8002e088(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,puVar6,4,*(undefined *)(iVar12 + 0xac),0xffffffff,
                                      *(uint **)(iVar12 + 0x30),in_r8,in_r9,in_r10);
        }
        FUN_80037e24((int)psVar3,DAT_803df0c4,1);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0xd,psVar3,0xffffffff);
      }
    }
    if (((*(char *)(iVar13 + 0x8c8) == 'D') ||
        (iVar12 = (**(code **)(*DAT_803dd6e8 + 0x1c))(), iVar12 == 0)) ||
       ((iVar12 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x13e), iVar12 == 0 ||
        (FUN_80037048(0x30,&local_68), local_68 != 0)))) {
      if (*(char *)(iVar13 + 0x8b3) == '\0') {
        if ((*(uint *)(iVar5 + 0x31c) & 0x100) != 0) {
          if ((((*(int *)(iVar13 + 0x7f8) == 0) && ((*(byte *)(iVar13 + 0x3f4) >> 6 & 1) != 0)) &&
              ((*(byte *)(iVar13 + 0x3f0) >> 5 & 1) == 0)) &&
             ((*(byte *)(iVar13 + 0x3f0) >> 4 & 1) == 0)) {
            bVar1 = true;
          }
          else {
            bVar1 = false;
          }
          if (bVar1) {
            if ((*(char *)(iVar13 + 0x8b4) == '\x02') ||
               (((*(int *)(iVar13 + 0x4b8) != 0 && (*(float *)(iVar13 + 0x4b0) < FLOAT_803e8cec)) &&
                ((*(int *)(iVar13 + 0x4a8) < 0x4000 && (*(short *)(iVar13 + 0x4b4) == 1)))))) {
              if ((DAT_803df0cc != 0) && ((*(byte *)(iVar13 + 0x3f4) >> 6 & 1) != 0)) {
                *(undefined *)(iVar13 + 0x8b4) = 4;
                *(byte *)(iVar13 + 0x3f4) = *(byte *)(iVar13 + 0x3f4) & 0xf7 | 8;
              }
              *(undefined4 *)(iVar5 + 0x308) = 0;
            }
            else if ((DAT_803df0cc != 0) && ((*(byte *)(iVar13 + 0x3f4) >> 6 & 1) != 0)) {
              *(undefined *)(iVar13 + 0x8b4) = 2;
              *(byte *)(iVar13 + 0x3f4) = *(byte *)(iVar13 + 0x3f4) & 0xf7;
            }
          }
        }
      }
      else {
        if ((((*(uint *)(iVar5 + 0x31c) & 0x200) != 0) && (DAT_803df0cc != 0)) &&
           ((*(byte *)(iVar13 + 0x3f4) >> 6 & 1) != 0)) {
          *(undefined *)(iVar13 + 0x8b4) = 0;
          *(byte *)(iVar13 + 0x3f4) = *(byte *)(iVar13 + 0x3f4) & 0xf7;
        }
        iVar13 = *(int *)(psVar3 + 0x5c);
        if (((*(uint *)(iVar5 + 0x31c) & 0x100) != 0) &&
           (bVar8 = *(byte *)(iVar13 + 0x3f4) >> 6 & 1, bVar8 != 0)) {
          if ((DAT_803df0cc != 0) && (bVar8 != 0)) {
            *(undefined *)(iVar13 + 0x8b4) = 4;
            *(byte *)(iVar13 + 0x3f4) = *(byte *)(iVar13 + 0x3f4) & 0xf7 | 8;
          }
          *(undefined4 *)(iVar5 + 0x308) = 0;
        }
      }
    }
    else {
      FUN_8001ffac(0x13d);
      uVar2 = FUN_8002e144();
      if ((uVar2 & 0xff) != 0) {
        puVar6 = FUN_8002becc(0x24,0x43b);
        *puVar6 = 0x43b;
        *(undefined *)(puVar6 + 1) = 9;
        *(undefined *)(puVar6 + 2) = 2;
        *(undefined *)(puVar6 + 3) = 0xff;
        *(undefined *)((int)puVar6 + 5) = 1;
        *(undefined *)((int)puVar6 + 7) = 0xff;
        *(undefined4 *)(puVar6 + 4) = *(undefined4 *)(psVar3 + 6);
        dVar14 = (double)FLOAT_803e8bf0;
        *(float *)(puVar6 + 6) = (float)(dVar14 + (double)*(float *)(psVar3 + 8));
        *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(psVar3 + 10);
        *(undefined *)((int)puVar6 + 0x19) = 1;
        FUN_8002e088(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar6,5,0xff,
                     0xffffffff,*(uint **)(psVar3 + 0x18),in_r8,in_r9,in_r10);
      }
      (**(code **)(*DAT_803dd6e8 + 0x10))();
    }
    break;
  case 10:
    *(undefined4 *)(iVar5 + 0x308) = 0;
    break;
  case 0xb:
    *(code **)(iVar5 + 0x308) = FUN_802a0820;
    break;
  case 0xd:
    *(undefined4 *)(iVar5 + 0x308) = 0;
  }
LAB_802a50f0:
  FUN_8028688c();
  return;
}

