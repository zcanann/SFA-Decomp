// Function: FUN_801b2550
// Entry: 801b2550
// Size: 1504 bytes

void FUN_801b2550(undefined4 param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  bool bVar2;
  short sVar4;
  int iVar3;
  short *psVar5;
  undefined4 uVar6;
  int iVar7;
  char cVar9;
  uint uVar8;
  int iVar10;
  int iVar11;
  int iVar12;
  short *local_38 [2];
  undefined4 local_30;
  uint uStack44;
  double local_28;
  
  psVar5 = (short *)FUN_802860d4();
  iVar12 = *(int *)(psVar5 + 0x26);
  bVar2 = false;
  *(undefined *)(param_3 + 0x56) = 0;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xf9f7;
  iVar11 = *(int *)(psVar5 + 0x5c);
  if (*(char *)(iVar11 + 0xac) == '\x03') {
    uVar6 = FUN_8002b9ec();
    FUN_8011f3ec(0x16);
    FUN_8011f3c8(0x17);
    FUN_8011f38c(1);
    iVar12 = (**(code **)(*DAT_803dca50 + 0x10))();
    if ((iVar12 != 0x51) && (iVar12 != 0x4c)) {
      local_38[0] = psVar5;
      (**(code **)(*DAT_803dca50 + 0x1c))(0x51,1,0,4,local_38,0x32,0xff);
    }
    if (iVar12 == 0x51) {
      iVar12 = FUN_800395d8(psVar5,0);
      if (*(char *)(iVar11 + 0xb0) < '\x01') {
        iVar7 = FUN_8001ffb4(0xdb);
        if (iVar7 == 0) {
          (**(code **)(*DAT_803dca68 + 0x38))(0x4b9,0x14,0x8c,1);
          FUN_800200e8(0xdb,1);
        }
        cVar9 = FUN_80014cc0(0);
        uStack44 = (int)cVar9 ^ 0x80000000;
        local_30 = 0x43300000;
        iVar7 = (int)(-FLOAT_803dbf08 *
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e48c0));
        local_28 = (double)(longlong)iVar7;
        if (iVar7 == 0) {
          if (*(int *)(iVar11 + 0xa8) != 0) {
            FUN_8000bb18(psVar5,0x1fe);
          }
        }
        else {
          sVar1 = *(short *)(iVar12 + 2);
          sVar4 = sVar1;
          if (sVar1 < 0) {
            sVar4 = -sVar1;
          }
          if ((int)DAT_803dbf02 - (int)DAT_803dbf04 < (int)sVar4) {
            if (iVar7 < 0) {
              iVar10 = -1;
            }
            else if (iVar7 < 1) {
              iVar10 = 0;
            }
            else {
              iVar10 = 1;
            }
            if (sVar1 < 0) {
              iVar3 = -1;
            }
            else if (sVar1 < 1) {
              iVar3 = 0;
            }
            else {
              iVar3 = 1;
            }
            if (iVar3 == iVar10) {
              iVar7 = (iVar7 * ((int)DAT_803dbf02 - (int)sVar4)) / (int)DAT_803dbf04;
            }
          }
          *(short *)(iVar12 + 2) = *(short *)(iVar12 + 2) + (short)iVar7;
          FUN_8000da58(psVar5,0x1ff);
        }
        *(int *)(iVar11 + 0xa8) = iVar7;
        if (0 < *(short *)(iVar11 + 0xa4)) {
          *(ushort *)(iVar11 + 0xa4) = *(short *)(iVar11 + 0xa4) - (ushort)DAT_803db410;
        }
        if (0 < *(short *)(iVar11 + 0xa6)) {
          *(ushort *)(iVar11 + 0xa6) = *(short *)(iVar11 + 0xa6) - (ushort)DAT_803db410;
        }
        uVar8 = FUN_80014ee8(0);
        if (((uVar8 & 0x100) == 0) || (0 < *(short *)(iVar11 + 0xa4))) {
          FUN_8000b7bc(psVar5,2);
        }
        else {
          FUN_80014b3c(0,0x100);
          iVar12 = FUN_80296a14(uVar6);
          if (iVar12 < 1) {
            FUN_8000bb18(psVar5,0x40c);
          }
          else {
            *(byte *)(iVar11 + 0xae) = *(char *)(iVar11 + 0xae) + DAT_803db410;
            iVar12 = FUN_8000b578(psVar5,2);
            if (iVar12 == 0) {
              FUN_8000bb18(psVar5,0x201);
              FUN_8000bb18(psVar5,0x202);
            }
          }
        }
        if (DAT_803dbf00 < *(byte *)(iVar11 + 0xae)) {
          *(byte *)(iVar11 + 0xae) = DAT_803dbf00;
        }
        (**(code **)(*DAT_803dca68 + 0x5c))(*(undefined *)(iVar11 + 0xae));
        local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar11 + 0xae));
        *(float *)(iVar11 + 0x98) =
             (float)(local_28 - DOUBLE_803e48e0) * FLOAT_803dbefc + FLOAT_803dbef8;
        uVar8 = FUN_80014e14(0);
        if (((((uVar8 & 0x100) != 0) || (*(byte *)(iVar11 + 0xae) == DAT_803dbf00)) &&
            (*(short *)(iVar11 + 0xa4) < 1)) && (iVar12 = FUN_80296a14(uVar6), 0 < iVar12)) {
          FUN_80014b3c(0,0x100);
          FUN_80296a24(uVar6,0xffffffff);
          *(undefined *)(iVar11 + 0xad) = 1;
          *(undefined *)(iVar11 + 0xae) = 0;
        }
        FUN_801b1ff4(psVar5,1);
        if (((*(char *)(psVar5 + 0x56) == '\x13') && (*(char *)(iVar11 + 0xb2) == '\0')) &&
           ((iVar12 = FUN_8001ffb4(0xc17), iVar12 != 0 &&
            (iVar12 = FUN_8001ffb4(0xa21), iVar12 != 0)))) {
          *(undefined *)(iVar11 + 0xb2) = 1;
          *(undefined *)(iVar11 + 0xb1) = 1;
        }
        if ((*(char *)(iVar11 + 0xb1) != '\0') &&
           (*(byte *)(iVar11 + 0xb1) = *(char *)(iVar11 + 0xb1) + DAT_803db410,
           0x3c < *(byte *)(iVar11 + 0xb1))) {
          bVar2 = true;
        }
        if ((bVar2) || (uVar8 = FUN_80014e70(0), (uVar8 & 0x200) != 0)) {
          FUN_80014b3c(0,0x200);
          FUN_8011f38c(0);
          (**(code **)(*DAT_803dca68 + 0x60))();
          (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0,0xff);
          *(undefined *)(iVar11 + 0xac) = 5;
          *(undefined *)(iVar11 + 0xb0) = 0x3c;
          *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
          *(byte *)((int)psVar5 + 0xaf) = *(byte *)((int)psVar5 + 0xaf) & 0xf7;
          iVar11 = FUN_8000b578(psVar5,8);
          if (iVar11 != 0) {
            FUN_8000b578(psVar5,0);
          }
          FUN_8000b7bc(psVar5,2);
        }
        FUN_8002fa48((double)FLOAT_803dbef4,(double)FLOAT_803db414,psVar5,0);
      }
      else {
        *(byte *)(iVar11 + 0xb0) = *(char *)(iVar11 + 0xb0) - DAT_803db410;
        if (*(char *)(iVar11 + 0xb0) < '\x01') {
          (**(code **)(*DAT_803dca68 + 0x58))(DAT_803dbf00,0x5d5);
        }
      }
    }
  }
  else {
    psVar5[3] = psVar5[3] & 0xbfff;
    iVar7 = FUN_800395d8(psVar5,0);
    *(short *)(iVar7 + 2) = *psVar5 - (short)((int)*(char *)(iVar12 + 0x28) << 8);
    *psVar5 = (short)((int)*(char *)(iVar12 + 0x28) << 8);
    *(undefined *)(iVar11 + 0xac) = 4;
  }
  FUN_80286120(0);
  return;
}

