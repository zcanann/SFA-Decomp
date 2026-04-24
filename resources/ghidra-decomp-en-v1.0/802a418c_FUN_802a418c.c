// Function: FUN_802a418c
// Entry: 802a418c
// Size: 2076 bytes

void FUN_802a418c(void)

{
  bool bVar1;
  uint uVar2;
  char cVar6;
  int *piVar3;
  byte bVar7;
  int iVar4;
  undefined2 *puVar5;
  int iVar8;
  short *psVar9;
  int iVar10;
  int iVar11;
  undefined8 uVar12;
  int local_68;
  undefined4 local_64;
  int local_60;
  float local_5c;
  undefined auStack88 [88];
  
  uVar12 = FUN_802860dc();
  iVar4 = (int)((ulonglong)uVar12 >> 0x20);
  iVar8 = (int)uVar12;
  iVar11 = *(int *)(iVar4 + 0xb8);
  local_5c = FLOAT_803e8050;
  if (*(char *)(iVar11 + 0x8c8) == 'D') goto LAB_802a44c4;
  if (*(int *)(iVar11 + 0x7f8) == 0) {
    cVar6 = FUN_802a74a4(iVar4,iVar11,iVar8,auStack88,0xfffffebf);
  }
  else {
    cVar6 = FUN_802a74a4(iVar4,iVar11,iVar8,auStack88,0x22);
  }
  if (cVar6 == -1) {
    *(undefined *)(iVar11 + 0x8c2) = 0xff;
    *(undefined *)(iVar11 + 0x8c3) = 0;
  }
  else if (cVar6 == *(char *)(iVar11 + 0x8c2)) {
    bVar7 = *(char *)(iVar11 + 0x8c3) + 1;
    *(byte *)(iVar11 + 0x8c3) = bVar7;
    if (200 < bVar7) {
      *(undefined *)(iVar11 + 0x8c3) = 200;
    }
  }
  else {
    *(char *)(iVar11 + 0x8c2) = cVar6;
    *(undefined *)(iVar11 + 0x8c3) = 0;
  }
  switch(*(undefined *)(iVar11 + 0x8c2)) {
  case 0:
    if ((*(byte *)(iVar11 + 0x3f1) & 1) != 0) {
      *(code **)(iVar8 + 0x308) = FUN_8029ffd0;
      iVar4 = 0xf;
      break;
    }
  default:
    goto switchD_802a4284_caseD_1;
  case 4:
    DAT_803dc6a0 = 0xffff;
    *(undefined4 *)(iVar8 + 0x308) = 0;
    iVar4 = 0xd;
    break;
  case 5:
    if (*(int *)(iVar11 + 0x7f8) == 0) {
      DAT_803dc6a0 = 0xffff;
      *(undefined4 *)(iVar8 + 0x308) = 0;
      iVar4 = 0xc;
      break;
    }
    goto switchD_802a4284_caseD_1;
  case 6:
    *(code **)(iVar8 + 0x308) = FUN_8029dae0;
    iVar4 = -0x1d;
    break;
  case 7:
    FUN_802ae9c8(iVar4,iVar11,iVar8);
    iVar4 = 0;
    break;
  case 8:
    *(undefined4 *)(iVar8 + 0x308) = 0;
    iVar4 = 0xb;
    break;
  case 9:
    if ((*(byte *)(iVar11 + 0x3f1) & 1) != 0) {
      *(code **)(iVar8 + 0x308) = FUN_8029ffd0;
      iVar4 = 0x13;
      break;
    }
switchD_802a4284_caseD_1:
    if ((*(int *)(iVar11 + 0x7f8) == 0) && ((*(byte *)(iVar11 + 0x3f4) >> 6 & 1) != 0)) {
      piVar3 = (int *)FUN_80036f50(0x41,&local_60);
      for (iVar10 = 0; iVar10 < local_60; iVar10 = iVar10 + 1) {
        DAT_803de434 = *piVar3;
        if (((*(byte *)(DAT_803de434 + 0xaf) & 4) != 0) &&
           ((*(byte *)(DAT_803de434 + 0xaf) & 0x10) == 0)) {
          bVar7 = FUN_8018a220();
          if (bVar7 == 2) {
            FUN_8011f3ec(2);
            if ((*(uint *)(iVar8 + 0x31c) & 0x100) != 0) {
              FUN_80014b3c(0,0x100);
              *(code **)(iVar8 + 0x308) = FUN_80298924;
              iVar4 = 0x34;
              goto LAB_802a4990;
            }
          }
          else if ((1 < bVar7) && (bVar7 < 6)) {
            if (bVar7 < 4) {
              FUN_8011f3ec(2);
              if ((*(uint *)(iVar8 + 0x31c) & 0x100) != 0) {
                FUN_80014b3c(0,0x100);
                *(code **)(iVar8 + 0x308) = FUN_80298924;
                iVar4 = 0x35;
                goto LAB_802a4990;
              }
            }
            else {
              FUN_8011f3ec(0xe);
              if ((*(uint *)(iVar8 + 0x31c) & 0x100) != 0) {
                FUN_80014b3c(0,0x100);
                *(code **)(iVar8 + 0x308) = FUN_80298924;
                iVar4 = 0x36;
                goto LAB_802a4990;
              }
            }
          }
        }
        piVar3 = piVar3 + 1;
      }
    }
LAB_802a44c4:
    FUN_80036f50(0x20,&local_64);
    uVar2 = countLeadingZeros(local_64);
    FUN_800200e8(0xeb5,uVar2 >> 5);
    iVar10 = (**(code **)(*DAT_803dca68 + 0x1c))();
    if (iVar10 != 0) {
      iVar10 = (**(code **)(*DAT_803dca68 + 0x20))(0x1ee);
      if (iVar10 != 0) {
        psVar9 = (short *)0x0;
        FUN_80014b3c(0,0x100);
        iVar4 = FUN_80036e58(0xf,iVar4,&local_5c);
        if (iVar4 != 0) {
          psVar9 = *(short **)(iVar4 + 0x4c);
        }
        if (((psVar9 != (short *)0x0) && (*psVar9 == 0x860)) && ((*(byte *)(iVar4 + 0xaf) & 4) != 0)
           ) {
          FUN_800200e8(0x3f1,1);
          FUN_800200e8(0x3d8,1);
          FUN_800200e8(0x651,1);
        }
        iVar4 = 0;
        break;
      }
      iVar10 = (**(code **)(*DAT_803dca68 + 0x20))(0x953);
      if ((iVar10 != 0) && (DAT_803de444 == 0)) {
        FUN_80014b3c(0,0x100);
        if ((DAT_803de44c != 0) && ((*(byte *)(iVar11 + 0x3f4) >> 6 & 1) != 0)) {
          *(undefined *)(iVar11 + 0x8b4) = 1;
          *(byte *)(iVar11 + 0x3f4) = *(byte *)(iVar11 + 0x3f4) & 0xf7 | 8;
        }
        iVar10 = FUN_8002b9ec();
        cVar6 = FUN_8002e04c();
        if (cVar6 == '\0') {
          DAT_803de444 = 0;
        }
        else {
          puVar5 = (undefined2 *)FUN_8002bdf4(0x24,0x62d);
          *puVar5 = 0x62d;
          *(undefined *)(puVar5 + 2) = 2;
          *(undefined *)(puVar5 + 3) = 0xff;
          *(undefined *)((int)puVar5 + 5) = 1;
          *(undefined *)((int)puVar5 + 7) = 0xff;
          *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar10 + 0xc);
          *(undefined4 *)(puVar5 + 6) = *(undefined4 *)(iVar10 + 0x10);
          *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(iVar10 + 0x14);
          DAT_803de444 = FUN_8002df90(puVar5,4,(int)*(char *)(iVar10 + 0xac),0xffffffff,
                                      *(undefined4 *)(iVar10 + 0x30));
        }
        FUN_80037d2c(iVar4,DAT_803de444,1);
        (**(code **)(*DAT_803dca54 + 0x48))(0xd,iVar4,0xffffffff);
      }
    }
    if (((*(char *)(iVar11 + 0x8c8) == 'D') ||
        (iVar10 = (**(code **)(*DAT_803dca68 + 0x1c))(), iVar10 == 0)) ||
       ((iVar10 = (**(code **)(*DAT_803dca68 + 0x20))(0x13e), iVar10 == 0 ||
        (FUN_80036f50(0x30,&local_68), local_68 != 0)))) {
      if (*(char *)(iVar11 + 0x8b3) == '\0') {
        if ((*(uint *)(iVar8 + 0x31c) & 0x100) != 0) {
          if ((((*(int *)(iVar11 + 0x7f8) == 0) && ((*(byte *)(iVar11 + 0x3f4) >> 6 & 1) != 0)) &&
              ((*(byte *)(iVar11 + 0x3f0) >> 5 & 1) == 0)) &&
             ((*(byte *)(iVar11 + 0x3f0) >> 4 & 1) == 0)) {
            bVar1 = true;
          }
          else {
            bVar1 = false;
          }
          if (bVar1) {
            if ((*(char *)(iVar11 + 0x8b4) == '\x02') ||
               (((*(int *)(iVar11 + 0x4b8) != 0 && (*(float *)(iVar11 + 0x4b0) < FLOAT_803e8054)) &&
                ((*(int *)(iVar11 + 0x4a8) < 0x4000 && (*(short *)(iVar11 + 0x4b4) == 1)))))) {
              if ((DAT_803de44c != 0) && ((*(byte *)(iVar11 + 0x3f4) >> 6 & 1) != 0)) {
                *(undefined *)(iVar11 + 0x8b4) = 4;
                *(byte *)(iVar11 + 0x3f4) = *(byte *)(iVar11 + 0x3f4) & 0xf7 | 8;
              }
              *(undefined4 *)(iVar8 + 0x308) = 0;
              iVar4 = 0x32;
              break;
            }
            if ((DAT_803de44c != 0) && ((*(byte *)(iVar11 + 0x3f4) >> 6 & 1) != 0)) {
              *(undefined *)(iVar11 + 0x8b4) = 2;
              *(byte *)(iVar11 + 0x3f4) = *(byte *)(iVar11 + 0x3f4) & 0xf7;
            }
          }
        }
      }
      else {
        if ((((*(uint *)(iVar8 + 0x31c) & 0x200) != 0) && (DAT_803de44c != 0)) &&
           ((*(byte *)(iVar11 + 0x3f4) >> 6 & 1) != 0)) {
          *(undefined *)(iVar11 + 0x8b4) = 0;
          *(byte *)(iVar11 + 0x3f4) = *(byte *)(iVar11 + 0x3f4) & 0xf7;
        }
        iVar4 = *(int *)(iVar4 + 0xb8);
        if (((*(uint *)(iVar8 + 0x31c) & 0x100) == 0) ||
           (bVar7 = *(byte *)(iVar4 + 0x3f4) >> 6 & 1, bVar7 == 0)) {
          iVar4 = 0;
        }
        else {
          if ((DAT_803de44c != 0) && (bVar7 != 0)) {
            *(undefined *)(iVar4 + 0x8b4) = 4;
            *(byte *)(iVar4 + 0x3f4) = *(byte *)(iVar4 + 0x3f4) & 0xf7 | 8;
          }
          *(undefined4 *)(iVar8 + 0x308) = 0;
          iVar4 = 0x32;
        }
        if (iVar4 != 0) break;
      }
      iVar4 = 0;
    }
    else {
      FUN_8001fee8(0x13d);
      cVar6 = FUN_8002e04c();
      if (cVar6 != '\0') {
        puVar5 = (undefined2 *)FUN_8002bdf4(0x24,0x43b);
        *puVar5 = 0x43b;
        *(undefined *)(puVar5 + 1) = 9;
        *(undefined *)(puVar5 + 2) = 2;
        *(undefined *)(puVar5 + 3) = 0xff;
        *(undefined *)((int)puVar5 + 5) = 1;
        *(undefined *)((int)puVar5 + 7) = 0xff;
        *(undefined4 *)(puVar5 + 4) = *(undefined4 *)(iVar4 + 0xc);
        *(float *)(puVar5 + 6) = FLOAT_803e7f58 + *(float *)(iVar4 + 0x10);
        *(undefined4 *)(puVar5 + 8) = *(undefined4 *)(iVar4 + 0x14);
        *(undefined *)((int)puVar5 + 0x19) = 1;
        FUN_8002df90(puVar5,5,0xffffffff,0xffffffff,*(undefined4 *)(iVar4 + 0x30));
      }
      (**(code **)(*DAT_803dca68 + 0x10))();
      iVar4 = 0;
    }
    break;
  case 10:
    *(undefined4 *)(iVar8 + 0x308) = 0;
    iVar4 = 0x17;
    break;
  case 0xb:
    *(code **)(iVar8 + 0x308) = FUN_802a00c0;
    iVar4 = 0x1c;
    break;
  case 0xd:
    *(undefined4 *)(iVar8 + 0x308) = 0;
    iVar4 = 0x1d;
  }
LAB_802a4990:
  FUN_80286128(iVar4);
  return;
}

