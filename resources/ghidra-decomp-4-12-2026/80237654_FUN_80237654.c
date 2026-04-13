// Function: FUN_80237654
// Entry: 80237654
// Size: 1500 bytes

void FUN_80237654(void)

{
  int iVar1;
  short sVar2;
  float fVar3;
  byte bVar4;
  short *psVar5;
  int *piVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar15;
  undefined auStack_58 [8];
  undefined8 local_50;
  undefined8 local_48;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  
  uVar15 = FUN_8028683c();
  psVar5 = (short *)((ulonglong)uVar15 >> 0x20);
  iVar8 = (int)uVar15;
  piVar12 = *(int **)(psVar5 + 0x5c);
  sVar2 = psVar5[0x23];
  psVar5[2] = (ushort)*(byte *)(iVar8 + 0x18) << 8;
  psVar5[1] = (ushort)*(byte *)(iVar8 + 0x19) << 8;
  *psVar5 = (ushort)*(byte *)(iVar8 + 0x1a) << 8;
  *(undefined *)((int)piVar12 + 0x25) = 1;
  *(undefined *)((int)piVar12 + 0x26) = 0xf;
  if (*(byte *)(iVar8 + 0x2b) == 0) {
    *(undefined2 *)(piVar12 + 8) = 600;
  }
  else {
    *(ushort *)(piVar12 + 8) = (ushort)*(byte *)(iVar8 + 0x2b) * 0x3c;
  }
  if ((*(byte *)(iVar8 + 0x29) & 1) != 0) {
    *(byte *)((int)piVar12 + 0x22) = *(byte *)((int)piVar12 + 0x22) | 2;
  }
  if ((*(byte *)(iVar8 + 0x2a) & 1) != 0) {
    *(byte *)((int)piVar12 + 0x22) = *(byte *)((int)piVar12 + 0x22) | 4;
  }
  if ((*(byte *)(iVar8 + 0x2a) & 0x80) != 0) {
    *(byte *)((int)piVar12 + 0x22) = *(byte *)((int)piVar12 + 0x22) | 8;
  }
  if ((*(byte *)(iVar8 + 0x29) & 0x10) != 0) {
    if (*piVar12 == 0) {
      piVar6 = FUN_8001f58c((int)psVar5,'\x01');
      *piVar12 = (int)piVar6;
    }
    if (*piVar12 != 0) {
      FUN_8001dbf0(*piVar12,2);
      if (psVar5[0x23] == 0x758) {
        dVar13 = (double)FLOAT_803e7ff8;
        FUN_8001de4c(dVar13,dVar13,dVar13,(int *)*piVar12);
      }
      else {
        FUN_8001de4c((double)FLOAT_803e7ff8,(double)FLOAT_803e8040,(double)FLOAT_803e7ff8,
                     (int *)*piVar12);
      }
      iVar10 = (uint)*(byte *)(iVar8 + 0x1b) * 3;
      iVar9 = (uint)(sVar2 == 0x758) * 0x30;
      FUN_8001dbb4(*piVar12,(&DAT_8032c9a8)[iVar10 + iVar9],(&DAT_8032c9a9)[iVar10 + iVar9],
                   (&DAT_8032c9aa)[iVar10 + iVar9],0xff);
      iVar10 = (uint)*(byte *)(iVar8 + 0x1b) * 3;
      FUN_8001dadc(*piVar12,(&DAT_8032c9a8)[iVar10 + iVar9],(&DAT_8032c9a9)[iVar10 + iVar9],
                   (&DAT_8032c9aa)[iVar10 + iVar9],0xff);
      fVar3 = FLOAT_803e8048;
      if ((*(byte *)(iVar8 + 0x2a) & 8) != 0) {
        fVar3 = FLOAT_803e8044;
      }
      local_50 = (double)(longlong)(int)(fVar3 * *(float *)(psVar5 + 4));
      uStack_3c = (int)(fVar3 * *(float *)(psVar5 + 4)) ^ 0x80000000;
      local_48 = (double)CONCAT44(0x43300000,uStack_3c);
      local_40 = 0x43300000;
      dVar13 = DOUBLE_803e8038;
      FUN_8001dcfc((double)(float)(local_48 - DOUBLE_803e8038),
                   (double)(FLOAT_803e804c +
                           (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e8038)),
                   *piVar12);
      if ((*(byte *)((int)piVar12 + 0x22) & 4) != 0) {
        iVar10 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_58);
        if (iVar10 == 0) {
          FUN_8001dc30((double)FLOAT_803e800c,*piVar12,'\0');
          *(undefined *)((int)piVar12 + 0x25) = 0;
        }
        else {
          FUN_8001dc30((double)FLOAT_803e800c,*piVar12,'\x01');
        }
      }
      FUN_8001d6e4(*piVar12,1,3);
      iVar11 = (uint)*(byte *)(iVar8 + 0x1b) * 3;
      dVar14 = (double)FLOAT_803e8000;
      uStack_3c = (uint)(byte)(&DAT_8032c9a8)[iVar11 + iVar9];
      local_40 = 0x43300000;
      iVar10 = (int)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uStack_3c) -
                                             DOUBLE_803e7ff0));
      local_48 = (double)(longlong)iVar10;
      local_50 = (double)CONCAT44(0x43300000,(uint)(byte)(&DAT_8032c9a9)[iVar11 + iVar9]);
      iVar1 = (int)(dVar14 * (double)(float)(local_50 - DOUBLE_803e7ff0));
      local_38 = (longlong)iVar1;
      uStack_2c = (uint)(byte)(&DAT_8032c9aa)[iVar11 + iVar9];
      local_30 = 0x43300000;
      iVar11 = (int)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uStack_2c) -
                                             DOUBLE_803e7ff0));
      local_28 = (double)(longlong)iVar11;
      FUN_8001db7c(*piVar12,(char)iVar10,(char)iVar1,(char)iVar11,0xff);
      if ((*(byte *)(iVar8 + 0x29) & 0x20) != 0) {
        FUN_8001de04(*piVar12,1);
      }
      if ((*(byte *)(iVar8 + 0x29) & 0x40) != 0) {
        if ((*(byte *)(iVar8 + 0x29) & 0x80) == 0) {
          iVar10 = (uint)*(byte *)(iVar8 + 0x1b) * 3;
          FUN_8001d7f4((double)(FLOAT_803e8008 * *(float *)(psVar5 + 4)),dVar14,dVar13,in_f4,in_f5,
                       in_f6,in_f7,in_f8,*piVar12,0,(uint)(byte)(&DAT_8032c9a8)[iVar10 + iVar9],
                       (uint)(byte)(&DAT_8032c9a9)[iVar10 + iVar9],
                       (uint)(byte)(&DAT_8032c9aa)[iVar10 + iVar9],0x87,in_r9,in_r10);
        }
        else {
          iVar10 = (uint)*(byte *)(iVar8 + 0x1b) * 3;
          FUN_8001d7f4((double)(FLOAT_803e8050 * *(float *)(psVar5 + 4)),dVar14,dVar13,in_f4,in_f5,
                       in_f6,in_f7,in_f8,*piVar12,0,(uint)(byte)(&DAT_8032c9a8)[iVar10 + iVar9],
                       (uint)(byte)(&DAT_8032c9a9)[iVar10 + iVar9],
                       (uint)(byte)(&DAT_8032c9aa)[iVar10 + iVar9],0x87,in_r9,in_r10);
        }
        bVar4 = *(byte *)(iVar8 + 0x2c) & 3;
        if ((*(byte *)(iVar8 + 0x2c) & 3) == 0) {
          FUN_8001d7d8((double)FLOAT_803e8054,*piVar12);
        }
        else if (bVar4 == 1) {
          FUN_8001d7d8((double)FLOAT_803e801c,*piVar12);
        }
        else if (bVar4 == 2) {
          FUN_8001d7d8((double)FLOAT_803e8058,*piVar12);
        }
        else {
          FUN_8001d7d8((double)FLOAT_803e7ff8,*piVar12);
        }
      }
      if ((*(byte *)(iVar8 + 0x2a) & 4) == 0) {
        FUN_8001dc18(*piVar12,1);
      }
      else {
        FUN_8001dc18(*piVar12,0);
      }
    }
  }
  if (*(int *)(psVar5 + 0x2a) != 0) {
    *(byte *)((int)piVar12 + 0x27) = *(byte *)((int)piVar12 + 0x27) & 0x7f | 0x80;
    iVar10 = (int)(FLOAT_803e800c *
                  *(float *)(iVar8 + 0x20) *
                  *(float *)(psVar5 + 4) *
                  *(float *)(&DAT_8032c968 + (uint)*(byte *)(iVar8 + 0x1b) * 4));
    local_28 = (double)(longlong)iVar10;
    FUN_80035a6c((int)psVar5,(short)iVar10);
    if ((*(byte *)(iVar8 + 0x29) & 4) == 0) {
      FUN_80035eec((int)psVar5,0,0,0);
    }
    else {
      FUN_80035eec((int)psVar5,0x1f,1,0);
      *(byte *)((int)piVar12 + 0x27) = *(byte *)((int)piVar12 + 0x27) & 0x7f;
    }
    if ((*(byte *)(iVar8 + 0x2a) & 0x40) == 0) {
      FUN_80035f84((int)psVar5);
    }
    else {
      FUN_80035f9c((int)psVar5);
      *(byte *)((int)piVar12 + 0x27) = *(byte *)((int)piVar12 + 0x27) & 0x7f;
    }
    if ((*(byte *)(iVar8 + 0x2a) & 0x30) != 0) {
      *(byte *)((int)piVar12 + 0x27) = *(byte *)((int)piVar12 + 0x27) & 0x7f;
    }
    if (*(char *)((int)piVar12 + 0x27) < '\0') {
      FUN_80035ff8((int)psVar5);
    }
  }
  uVar7 = FUN_80022264(0,100);
  local_28 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
  piVar12[4] = (int)(float)(local_28 - DOUBLE_803e8038);
  piVar12[6] = (int)(FLOAT_803e800c * *(float *)(iVar8 + 0x20));
  *(code **)(psVar5 + 0x5e) = FUN_802371b0;
  FUN_80286888();
  return;
}

