// Function: FUN_80236f90
// Entry: 80236f90
// Size: 1500 bytes

void FUN_80236f90(void)

{
  int iVar1;
  short sVar2;
  float fVar3;
  byte bVar4;
  short *psVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  double dVar12;
  undefined8 uVar13;
  undefined auStack88 [8];
  double local_50;
  double local_48;
  undefined4 local_40;
  uint uStack60;
  longlong local_38;
  undefined4 local_30;
  uint uStack44;
  double local_28;
  
  uVar13 = FUN_802860d8();
  psVar5 = (short *)((ulonglong)uVar13 >> 0x20);
  iVar8 = (int)uVar13;
  piVar11 = *(int **)(psVar5 + 0x5c);
  sVar2 = psVar5[0x23];
  psVar5[2] = (ushort)*(byte *)(iVar8 + 0x18) << 8;
  psVar5[1] = (ushort)*(byte *)(iVar8 + 0x19) << 8;
  *psVar5 = (ushort)*(byte *)(iVar8 + 0x1a) << 8;
  *(undefined *)((int)piVar11 + 0x25) = 1;
  *(undefined *)((int)piVar11 + 0x26) = 0xf;
  if (*(byte *)(iVar8 + 0x2b) == 0) {
    *(undefined2 *)(piVar11 + 8) = 600;
  }
  else {
    *(ushort *)(piVar11 + 8) = (ushort)*(byte *)(iVar8 + 0x2b) * 0x3c;
  }
  if ((*(byte *)(iVar8 + 0x29) & 1) != 0) {
    *(byte *)((int)piVar11 + 0x22) = *(byte *)((int)piVar11 + 0x22) | 2;
  }
  if ((*(byte *)(iVar8 + 0x2a) & 1) != 0) {
    *(byte *)((int)piVar11 + 0x22) = *(byte *)((int)piVar11 + 0x22) | 4;
  }
  if ((*(byte *)(iVar8 + 0x2a) & 0x80) != 0) {
    *(byte *)((int)piVar11 + 0x22) = *(byte *)((int)piVar11 + 0x22) | 8;
  }
  if ((*(byte *)(iVar8 + 0x29) & 0x10) != 0) {
    if (*piVar11 == 0) {
      iVar6 = FUN_8001f4c8(psVar5,1);
      *piVar11 = iVar6;
    }
    if (*piVar11 != 0) {
      FUN_8001db2c(*piVar11,2);
      if (psVar5[0x23] == 0x758) {
        dVar12 = (double)FLOAT_803e7360;
        FUN_8001dd88(dVar12,dVar12,dVar12,*piVar11);
      }
      else {
        FUN_8001dd88((double)FLOAT_803e7360,(double)FLOAT_803e73a8,(double)FLOAT_803e7360,*piVar11);
      }
      iVar6 = (uint)*(byte *)(iVar8 + 0x1b) * 3;
      iVar9 = (uint)(sVar2 == 0x758) * 0x30;
      FUN_8001daf0(*piVar11,(&DAT_8032bd50)[iVar6 + iVar9],(&DAT_8032bd51)[iVar6 + iVar9],
                   (&DAT_8032bd52)[iVar6 + iVar9],0xff);
      iVar6 = (uint)*(byte *)(iVar8 + 0x1b) * 3;
      FUN_8001da18(*piVar11,(&DAT_8032bd50)[iVar6 + iVar9],(&DAT_8032bd51)[iVar6 + iVar9],
                   (&DAT_8032bd52)[iVar6 + iVar9],0xff);
      fVar3 = FLOAT_803e73b0;
      if ((*(byte *)(iVar8 + 0x2a) & 8) != 0) {
        fVar3 = FLOAT_803e73ac;
      }
      local_50 = (double)(longlong)(int)(fVar3 * *(float *)(psVar5 + 4));
      uStack60 = (int)(fVar3 * *(float *)(psVar5 + 4)) ^ 0x80000000;
      local_48 = (double)CONCAT44(0x43300000,uStack60);
      local_40 = 0x43300000;
      FUN_8001dc38((double)(float)(local_48 - DOUBLE_803e73a0),
                   (double)(FLOAT_803e73b4 +
                           (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e73a0)),
                   *piVar11);
      if ((*(byte *)((int)piVar11 + 0x22) & 4) != 0) {
        iVar6 = (**(code **)(*DAT_803dca58 + 0x24))(auStack88);
        if (iVar6 == 0) {
          FUN_8001db6c((double)FLOAT_803e7374,*piVar11,0);
          *(undefined *)((int)piVar11 + 0x25) = 0;
        }
        else {
          FUN_8001db6c((double)FLOAT_803e7374,*piVar11,1);
        }
      }
      FUN_8001d620(*piVar11,1,3);
      iVar10 = (uint)*(byte *)(iVar8 + 0x1b) * 3;
      uStack60 = (uint)(byte)(&DAT_8032bd50)[iVar10 + iVar9];
      local_40 = 0x43300000;
      iVar6 = (int)(FLOAT_803e7368 *
                   (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7358));
      local_48 = (double)(longlong)iVar6;
      local_50 = (double)CONCAT44(0x43300000,(uint)(byte)(&DAT_8032bd51)[iVar10 + iVar9]);
      iVar1 = (int)(FLOAT_803e7368 * (float)(local_50 - DOUBLE_803e7358));
      local_38 = (longlong)iVar1;
      uStack44 = (uint)(byte)(&DAT_8032bd52)[iVar10 + iVar9];
      local_30 = 0x43300000;
      iVar10 = (int)(FLOAT_803e7368 *
                    (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e7358));
      local_28 = (double)(longlong)iVar10;
      FUN_8001dab8(*piVar11,iVar6,iVar1,iVar10,0xff);
      if ((*(byte *)(iVar8 + 0x29) & 0x20) != 0) {
        FUN_8001dd40(*piVar11,1);
      }
      if ((*(byte *)(iVar8 + 0x29) & 0x40) != 0) {
        if ((*(byte *)(iVar8 + 0x29) & 0x80) == 0) {
          iVar6 = (uint)*(byte *)(iVar8 + 0x1b) * 3;
          FUN_8001d730((double)(FLOAT_803e7370 * *(float *)(psVar5 + 4)),*piVar11,0,
                       (&DAT_8032bd50)[iVar6 + iVar9],(&DAT_8032bd51)[iVar6 + iVar9],
                       (&DAT_8032bd52)[iVar6 + iVar9],0x87);
        }
        else {
          iVar6 = (uint)*(byte *)(iVar8 + 0x1b) * 3;
          FUN_8001d730((double)(FLOAT_803e73b8 * *(float *)(psVar5 + 4)),*piVar11,0,
                       (&DAT_8032bd50)[iVar6 + iVar9],(&DAT_8032bd51)[iVar6 + iVar9],
                       (&DAT_8032bd52)[iVar6 + iVar9],0x87);
        }
        bVar4 = *(byte *)(iVar8 + 0x2c) & 3;
        if ((*(byte *)(iVar8 + 0x2c) & 3) == 0) {
          FUN_8001d714((double)FLOAT_803e73bc,*piVar11);
        }
        else if (bVar4 == 1) {
          FUN_8001d714((double)FLOAT_803e7384,*piVar11);
        }
        else if (bVar4 == 2) {
          FUN_8001d714((double)FLOAT_803e73c0,*piVar11);
        }
        else {
          FUN_8001d714((double)FLOAT_803e7360,*piVar11);
        }
      }
      if ((*(byte *)(iVar8 + 0x2a) & 4) == 0) {
        FUN_8001db54(*piVar11,1);
      }
      else {
        FUN_8001db54(*piVar11,0);
      }
    }
  }
  if (*(int *)(psVar5 + 0x2a) != 0) {
    *(byte *)((int)piVar11 + 0x27) = *(byte *)((int)piVar11 + 0x27) & 0x7f | 0x80;
    iVar6 = (int)(FLOAT_803e7374 *
                 *(float *)(iVar8 + 0x20) *
                 *(float *)(psVar5 + 4) *
                 *(float *)(&DAT_8032bd10 + (uint)*(byte *)(iVar8 + 0x1b) * 4));
    local_28 = (double)(longlong)iVar6;
    FUN_80035974(psVar5,iVar6);
    if ((*(byte *)(iVar8 + 0x29) & 4) == 0) {
      FUN_80035df4(psVar5,0,0,0);
    }
    else {
      FUN_80035df4(psVar5,0x1f,1,0);
      *(byte *)((int)piVar11 + 0x27) = *(byte *)((int)piVar11 + 0x27) & 0x7f;
    }
    if ((*(byte *)(iVar8 + 0x2a) & 0x40) == 0) {
      FUN_80035e8c(psVar5);
    }
    else {
      FUN_80035ea4(psVar5);
      *(byte *)((int)piVar11 + 0x27) = *(byte *)((int)piVar11 + 0x27) & 0x7f;
    }
    if ((*(byte *)(iVar8 + 0x2a) & 0x30) != 0) {
      *(byte *)((int)piVar11 + 0x27) = *(byte *)((int)piVar11 + 0x27) & 0x7f;
    }
    if (*(char *)((int)piVar11 + 0x27) < '\0') {
      FUN_80035f00(psVar5);
    }
  }
  uVar7 = FUN_800221a0(0,100);
  local_28 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  piVar11[4] = (int)(float)(local_28 - DOUBLE_803e73a0);
  piVar11[6] = (int)(FLOAT_803e7374 * *(float *)(iVar8 + 0x20));
  *(code **)(psVar5 + 0x5e) = FUN_80236aec;
  FUN_80286124();
  return;
}

