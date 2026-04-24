// Function: FUN_801b2b04
// Entry: 801b2b04
// Size: 1504 bytes

void FUN_801b2b04(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)

{
  short sVar1;
  short sVar3;
  int iVar2;
  short *psVar4;
  int iVar5;
  uint uVar6;
  char cVar7;
  bool bVar8;
  bool bVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  double dVar14;
  double dVar15;
  short *local_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  
  psVar4 = (short *)FUN_80286838();
  iVar13 = *(int *)(psVar4 + 0x26);
  bVar9 = false;
  *(undefined *)(param_11 + 0x56) = 0;
  *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xf9f7;
  iVar12 = *(int *)(psVar4 + 0x5c);
  if (*(char *)(iVar12 + 0xac) == '\x03') {
    iVar13 = FUN_8002bac4();
    FUN_8011f6d0(0x16);
    FUN_8011f6ac(0x17);
    FUN_8011f670(1);
    iVar5 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if ((iVar5 != 0x51) && (iVar5 != 0x4c)) {
      local_38[0] = psVar4;
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x51,1,0,4,local_38,0x32,0xff);
    }
    if (iVar5 == 0x51) {
      iVar5 = FUN_800396d0((int)psVar4,0);
      if (*(char *)(iVar12 + 0xb0) < '\x01') {
        uVar6 = FUN_80020078(0xdb);
        if (uVar6 == 0) {
          (**(code **)(*DAT_803dd6e8 + 0x38))(0x4b9,0x14,0x8c,1);
          FUN_800201ac(0xdb,1);
        }
        cVar7 = FUN_80014cec(0);
        uStack_2c = (int)cVar7 ^ 0x80000000;
        local_30 = 0x43300000;
        iVar11 = (int)(-FLOAT_803dcb70 *
                      (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5558));
        local_28 = (double)(longlong)iVar11;
        if (iVar11 == 0) {
          if (*(int *)(iVar12 + 0xa8) != 0) {
            FUN_8000bb38((uint)psVar4,0x1fe);
          }
        }
        else {
          sVar1 = *(short *)(iVar5 + 2);
          sVar3 = sVar1;
          if (sVar1 < 0) {
            sVar3 = -sVar1;
          }
          if ((int)DAT_803dcb6a - (int)DAT_803dcb6c < (int)sVar3) {
            if (iVar11 < 0) {
              iVar10 = -1;
            }
            else if (iVar11 < 1) {
              iVar10 = 0;
            }
            else {
              iVar10 = 1;
            }
            if (sVar1 < 0) {
              iVar2 = -1;
            }
            else if (sVar1 < 1) {
              iVar2 = 0;
            }
            else {
              iVar2 = 1;
            }
            if (iVar2 == iVar10) {
              iVar11 = (iVar11 * ((int)DAT_803dcb6a - (int)sVar3)) / (int)DAT_803dcb6c;
            }
          }
          *(short *)(iVar5 + 2) = *(short *)(iVar5 + 2) + (short)iVar11;
          FUN_8000da78((uint)psVar4,0x1ff);
        }
        *(int *)(iVar12 + 0xa8) = iVar11;
        if (0 < *(short *)(iVar12 + 0xa4)) {
          *(ushort *)(iVar12 + 0xa4) = *(short *)(iVar12 + 0xa4) - (ushort)DAT_803dc070;
        }
        if (0 < *(short *)(iVar12 + 0xa6)) {
          *(ushort *)(iVar12 + 0xa6) = *(short *)(iVar12 + 0xa6) - (ushort)DAT_803dc070;
        }
        uVar6 = FUN_80014f14(0);
        if (((uVar6 & 0x100) == 0) || (0 < *(short *)(iVar12 + 0xa4))) {
          FUN_8000b7dc((int)psVar4,2);
        }
        else {
          FUN_80014b68(0,0x100);
          iVar5 = FUN_80297174(iVar13);
          if (iVar5 < 1) {
            FUN_8000bb38((uint)psVar4,0x40c);
          }
          else {
            *(byte *)(iVar12 + 0xae) = *(char *)(iVar12 + 0xae) + DAT_803dc070;
            bVar8 = FUN_8000b598((int)psVar4,2);
            if (!bVar8) {
              FUN_8000bb38((uint)psVar4,0x201);
              FUN_8000bb38((uint)psVar4,0x202);
            }
          }
        }
        if (DAT_803dcb68 < *(byte *)(iVar12 + 0xae)) {
          *(byte *)(iVar12 + 0xae) = DAT_803dcb68;
        }
        (**(code **)(*DAT_803dd6e8 + 0x5c))(*(undefined *)(iVar12 + 0xae));
        local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar12 + 0xae));
        dVar15 = (double)(float)(local_28 - DOUBLE_803e5578);
        dVar14 = (double)FLOAT_803dcb64;
        *(float *)(iVar12 + 0x98) = (float)(dVar15 * dVar14 + (double)FLOAT_803dcb60);
        uVar6 = FUN_80014e40(0);
        if (((((uVar6 & 0x100) != 0) || (*(byte *)(iVar12 + 0xae) == DAT_803dcb68)) &&
            (*(short *)(iVar12 + 0xa4) < 1)) && (iVar5 = FUN_80297174(iVar13), 0 < iVar5)) {
          FUN_80014b68(0,0x100);
          dVar14 = (double)FUN_80297184(iVar13,-1);
          *(undefined *)(iVar12 + 0xad) = 1;
          *(undefined *)(iVar12 + 0xae) = 0;
        }
        FUN_801b25a8(dVar14,dVar15,param_3,param_4,param_5,param_6,param_7,param_8);
        if (((*(char *)(psVar4 + 0x56) == '\x13') && (*(char *)(iVar12 + 0xb2) == '\0')) &&
           ((uVar6 = FUN_80020078(0xc17), uVar6 != 0 && (uVar6 = FUN_80020078(0xa21), uVar6 != 0))))
        {
          *(undefined *)(iVar12 + 0xb2) = 1;
          *(undefined *)(iVar12 + 0xb1) = 1;
        }
        if ((*(char *)(iVar12 + 0xb1) != '\0') &&
           (*(byte *)(iVar12 + 0xb1) = *(char *)(iVar12 + 0xb1) + DAT_803dc070,
           0x3c < *(byte *)(iVar12 + 0xb1))) {
          bVar9 = true;
        }
        if ((bVar9) || (uVar6 = FUN_80014e9c(0), (uVar6 & 0x200) != 0)) {
          FUN_80014b68(0,0x200);
          FUN_8011f670(0);
          (**(code **)(*DAT_803dd6e8 + 0x60))();
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
          *(undefined *)(iVar12 + 0xac) = 5;
          *(undefined *)(iVar12 + 0xb0) = 0x3c;
          *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 4;
          *(byte *)((int)psVar4 + 0xaf) = *(byte *)((int)psVar4 + 0xaf) & 0xf7;
          bVar9 = FUN_8000b598((int)psVar4,8);
          if (bVar9) {
            FUN_8000b598((int)psVar4,0);
          }
          FUN_8000b7dc((int)psVar4,2);
        }
        FUN_8002fb40((double)FLOAT_803dcb5c,(double)FLOAT_803dc074);
      }
      else {
        *(byte *)(iVar12 + 0xb0) = *(char *)(iVar12 + 0xb0) - DAT_803dc070;
        if (*(char *)(iVar12 + 0xb0) < '\x01') {
          (**(code **)(*DAT_803dd6e8 + 0x58))(DAT_803dcb68,0x5d5);
        }
      }
    }
  }
  else {
    psVar4[3] = psVar4[3] & 0xbfff;
    iVar5 = FUN_800396d0((int)psVar4,0);
    *(short *)(iVar5 + 2) = *psVar4 - (short)((int)*(char *)(iVar13 + 0x28) << 8);
    *psVar4 = (short)((int)*(char *)(iVar13 + 0x28) << 8);
    *(undefined *)(iVar12 + 0xac) = 4;
  }
  FUN_80286884();
  return;
}

