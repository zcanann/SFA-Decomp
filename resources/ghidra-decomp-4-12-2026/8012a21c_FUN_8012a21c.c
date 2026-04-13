// Function: FUN_8012a21c
// Entry: 8012a21c
// Size: 5604 bytes

/* WARNING: Removing unreachable block (ram,0x8012a644) */

void FUN_8012a21c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  byte bVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  ushort uVar11;
  int iVar8;
  char cVar12;
  byte bVar13;
  undefined4 uVar9;
  uint uVar10;
  undefined *extraout_r4;
  undefined *puVar14;
  short sVar15;
  byte bVar16;
  uint uVar17;
  short sVar18;
  int *piVar19;
  double dVar20;
  undefined8 extraout_f1;
  undefined8 uVar21;
  undefined uStack_48;
  char local_47 [3];
  char local_44 [20];
  undefined4 local_30;
  int iStack_2c;
  
  FUN_80286834();
  iVar5 = FUN_8002bac4();
  uVar17 = 0;
  bVar3 = false;
  FUN_80296328(iVar5);
  bVar16 = 1;
  bVar13 = 5;
  iVar6 = (**(code **)(*DAT_803dd72c + 0x8c))();
  dVar20 = FUN_80019c38();
  if (dVar20 == (double)FLOAT_803e2abc) {
    uVar17 = FUN_80014e9c(0);
    uVar17 = uVar17 & 0xffff;
    FUN_80014f14(0);
  }
  DAT_803de3f8 = DAT_803de3f8 - (ushort)DAT_803dc070;
  if (DAT_803de3f8 < 0) {
    DAT_803de3f8 = 0;
  }
  if ((iVar5 == 0) && (iVar5 = FUN_8022de2c(), iVar5 != 0)) {
    bVar3 = true;
  }
  uVar7 = FUN_8012b9f8();
  if ((uVar7 & 0xff) == 0) {
    bVar16 = 4;
  }
  if ((DAT_803dc084 == '\0') || (uVar11 = FUN_800ea540(), uVar11 < 3)) {
LAB_8012a334:
    bVar13 = 4;
  }
  else if (iVar5 != 0) {
    param_2 = (double)*(float *)(iVar5 + 0x14);
    iVar8 = FUN_8005b128();
    if ((iVar8 == 0) && (iVar8 = FUN_80297a08(iVar5), iVar8 != 0)) goto LAB_8012a334;
  }
  uVar11 = FUN_800ea484();
  DAT_803de456 = (byte)uVar11;
  if (iVar5 != 0) {
    if (*(int *)(iVar5 + 0x30) == 0) {
      param_2 = (double)*(float *)(iVar5 + 0x14);
      DAT_803de560 = FUN_8005b128();
    }
    else {
      DAT_803de560 = (uint)*(char *)(*(int *)(iVar5 + 0x30) + 0xac);
    }
    if (DAT_803de560 == 0x36) {
      cVar12 = (**(code **)(*DAT_803dd72c + 0x40))();
      if (cVar12 == '\x01') {
        param_11 = *DAT_803dd72c;
        cVar12 = (**(code **)(param_11 + 0x4c))(DAT_803de560,0);
        if (cVar12 == '\0') {
          param_11 = *DAT_803dd72c;
          cVar12 = (**(code **)(param_11 + 0x4c))(DAT_803de560,1);
          if (cVar12 == '\0') {
            param_11 = *DAT_803dd72c;
            cVar12 = (**(code **)(param_11 + 0x4c))(DAT_803de560,2);
            if (cVar12 != '\0') {
              DAT_803de560 = 0xc;
            }
          }
          else {
            DAT_803de560 = 6;
          }
        }
        else {
          DAT_803de560 = 5;
        }
      }
      else {
        cVar12 = (**(code **)(*DAT_803dd72c + 0x40))(DAT_803de560);
        if (cVar12 == '\x02') {
          param_11 = *DAT_803dd72c;
          cVar12 = (**(code **)(param_11 + 0x4c))(DAT_803de560,0);
          if (cVar12 == '\0') {
            param_11 = *DAT_803dd72c;
            cVar12 = (**(code **)(param_11 + 0x4c))(DAT_803de560,1);
            if (cVar12 == '\0') {
              param_11 = *DAT_803dd72c;
              cVar12 = (**(code **)(param_11 + 0x4c))(DAT_803de560,2);
              if (cVar12 == '\0') {
                param_11 = *DAT_803dd72c;
                cVar12 = (**(code **)(param_11 + 0x4c))(DAT_803de560,3);
                if (cVar12 == '\0') {
                  param_11 = *DAT_803dd72c;
                  cVar12 = (**(code **)(param_11 + 0x4c))(DAT_803de560,4);
                  if (cVar12 == '\0') {
                    param_11 = *DAT_803dd72c;
                    cVar12 = (**(code **)(param_11 + 0x4c))(DAT_803de560,5);
                    if (cVar12 != '\0') {
                      DAT_803de560 = 3;
                    }
                  }
                  else {
                    DAT_803de560 = 9;
                  }
                }
                else {
                  DAT_803de560 = 10;
                }
              }
              else {
                DAT_803de560 = 6;
              }
            }
            else {
              DAT_803de560 = 6;
            }
          }
          else {
            DAT_803de560 = 6;
          }
        }
      }
    }
    else {
      param_11 = 0;
      while (((param_11 & 0xff) < 0x2d &&
             (DAT_803de560 != (ushort)(&DAT_8031c3b4)[(param_11 & 0xff) * 2]))) {
        param_11 = param_11 + 1;
      }
      if ((param_11 & 0xff) != 0x2d) {
        DAT_803de560 = (uint)(ushort)(&DAT_8031c3b6)[(param_11 & 0xff) * 2];
        FUN_800201ac(DAT_803de560 + 0xf10,1);
      }
    }
  }
  dVar20 = (double)(**(code **)(*DAT_803dd6cc + 0x18))();
  if ((double)FLOAT_803e2abc == dVar20) {
    iVar8 = (int)DAT_803de408 - (uint)DAT_803dc070;
    if (iVar8 < 0) {
      iVar8 = 0;
    }
    DAT_803de408 = (char)iVar8;
  }
  if ((DAT_803de400 == 1) || ((DAT_803de400 != 0 && (2 < DAT_803de400)))) {
    iVar8 = (int)DAT_803de40c + (uint)DAT_803dc070 * 0x32;
    if (0x400 < iVar8) {
      iVar8 = 0x400;
    }
    DAT_803de40c = (short)iVar8;
  }
  switch(DAT_803de400) {
  case 0:
    iVar6 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    bVar2 = true;
    bVar1 = false;
    if (((iVar5 == 0) || ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0)) &&
       ((iVar8 = FUN_80080490(), iVar8 == 0 && (cVar12 = FUN_8000cfc0(), cVar12 == '\0')))) {
      bVar1 = true;
    }
    if ((!bVar1) && (iVar6 != 0x51)) {
      bVar2 = false;
    }
    if ((((((uVar17 & 0x1000) != 0) && (DAT_803de408 == '\0')) && (DAT_803de409 == '\0')) &&
        ((dVar20 = (double)(**(code **)(*DAT_803dd6cc + 0x18))(), (double)FLOAT_803e2abc == dVar20
         && (bVar2)))) && ((DAT_803de3db == '\0' && (iVar6 = FUN_80020800(), iVar6 == 0)))) {
      DAT_803de408 = '<';
      FUN_800207ac(1);
      FUN_800206ec(0xff);
      dVar20 = (double)FUN_80014b68(0,0x1000);
      uVar21 = FUN_8012c894(dVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      DAT_803dc6cc = 5;
      if (bVar3) {
        DAT_803de44c = 0;
      }
      if ((DAT_803de3f2 == 0) && (DAT_803de3f0 == 0)) {
        DAT_803de400 = 1;
        DAT_803de55c = FUN_80019c28();
        FUN_800199a8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
      }
      else {
        DAT_803de55c = FUN_80019c28();
        if (DAT_803de560 == DAT_803de456) {
          FUN_800ea4e8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
        DAT_803de400 = 4;
        if (DAT_803de560 == DAT_803de456) {
          FUN_800ea4e8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
        else {
          FUN_800199a8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
        }
        DAT_803de558 = 0xb;
        FLOAT_803de3e4 = FLOAT_803e2ae0;
      }
    }
    sVar18 = DAT_803de3f2;
    if ((((DAT_803de3f2 != 0) && (iVar5 != 0)) && ((*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0)) &&
       (uVar17 = FUN_8012b9f8(), (uVar17 & 0xff) != 0)) {
      DAT_803de3f2 = DAT_803de3f2 + (ushort)DAT_803dc070;
      if (DAT_803de3f2 < 0x1518) {
        if (((9 < DAT_803de3f2) && (sVar18 < 10)) || ((0x707 < DAT_803de3f2 && (sVar18 < 0x708)))) {
          DAT_803de3f0 = 1;
        }
      }
      else {
        DAT_803de3f2 = 0;
        DAT_803de3f0 = 1;
        FUN_8000bb38(0,0x38d);
      }
    }
    if (DAT_803de3f0 != 0) {
      FLOAT_803de45c = FLOAT_803de45c + FLOAT_803dc074;
      if ((DAT_803de3f0 == 1) || (FLOAT_803e2c1c <= FLOAT_803de45c)) {
        FLOAT_803de45c = FLOAT_803e2abc;
        FUN_8000bb38(0,0x38d);
      }
      DAT_803de3f0 = DAT_803de3f0 + (ushort)DAT_803dc070;
      if (0xff < DAT_803de3f0) {
        DAT_803de3f0 = 0;
      }
    }
    break;
  case 1:
    FUN_80014ba4(0,local_47,&uStack_48);
    uVar9 = 3;
    FUN_8012e114(0x2b1,DAT_803dc6cc,1,3);
    if (((DAT_803de401 != '\0') && (iVar5 = FUN_8000cfb8(), iVar5 == 0)) &&
       (cVar12 = FUN_8000cfc0(), cVar12 == '\0')) {
      FUN_8003042c((double)FLOAT_803e2abc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (&DAT_803aa070)[DAT_803de401],0,0,uVar9,param_13,param_14,param_15,param_16);
      DAT_803de401 = '\0';
    }
    if (((local_47[0] != '\0') || (DAT_803de40c == 0)) ||
       (((char)DAT_803dc6cc < (char)bVar16 || ((char)bVar13 < (char)DAT_803dc6cc)))) {
      iVar5 = (int)(char)DAT_803dc6cc;
      if (((iVar5 < 4) && (0 < iVar5)) && (0x90000000 < *(uint *)((&DAT_803aa070)[iVar5] + 0x4c))) {
        *(undefined4 *)((&DAT_803aa070)[iVar5] + 0x4c) = 0;
      }
      bVar4 = DAT_803dc6cc;
      DAT_803dc6cc = DAT_803dc6cc + local_47[0];
      if ((char)DAT_803dc6cc < (char)bVar16) {
        DAT_803dc6cc = bVar13;
      }
      if ((char)bVar13 < (char)DAT_803dc6cc) {
        DAT_803dc6cc = bVar16;
      }
      if ((int)(char)DAT_803dc6cc != (uint)bVar4) {
        FUN_8000bb38(0,0x37b);
      }
      iVar5 = (int)(char)DAT_803dc6cc;
      if (((iVar5 < 4) && (0 < iVar5)) && (0x90000000 < *(uint *)((&DAT_803aa070)[iVar5] + 0x4c))) {
        *(undefined4 *)((&DAT_803aa070)[iVar5] + 0x4c) = 0;
      }
    }
    if (DAT_803de406 < (short)(ushort)DAT_803dc70a) {
      DAT_803de406 = DAT_803de406 + (ushort)DAT_803dc070;
      if ((short)(ushort)DAT_803dc70a <= DAT_803de406) {
        FUN_8012e114(0x2b1,DAT_803dc6cc,1,3);
      }
    }
    else {
      DAT_803de404 = DAT_803de404 + (ushort)DAT_803dc070 * 0x28;
      if (0x400 < DAT_803de404) {
        DAT_803de404 = 0x400;
      }
    }
    if ((uVar17 & 0x100) != 0) {
      FUN_8000bb38(0,0x98);
      FUN_80014b68(0,0x100);
      FLOAT_803de43c = FLOAT_803e2abc;
      FLOAT_803de440 = FLOAT_803e2abc;
      FLOAT_803de3e4 = FLOAT_803e2ae0;
      DAT_803de458 = 0;
      FLOAT_803de3e8 = FLOAT_803e2abc;
      if (DAT_803dc6cc == 3) {
        uVar21 = FUN_8012e114(0x2b1,3,4,3);
        DAT_803de400 = 4;
        if (DAT_803de560 == DAT_803de456) {
          DAT_803de558 = FUN_800ea4e8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                     );
        }
        else {
          DAT_803de558 = FUN_80019c28();
        }
        FUN_80022264(0,1);
        FUN_8000d220(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      else if ((char)DAT_803dc6cc < '\x03') {
        if (DAT_803dc6cc == 1) {
          uVar21 = FUN_8012e114(0x2b1,1,2,3);
          DAT_803de400 = 5;
          DAT_803de444 = '\0';
          DAT_803de458 = 2;
          FUN_8000d220(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
        else if ('\0' < (char)DAT_803dc6cc) {
          uVar21 = FUN_8012e114(0x2b1,DAT_803dc6cc,2,3);
          DAT_803de400 = 3;
          DAT_803de444 = '\0';
          FUN_80022264(0,1);
          FUN_8000d220(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
      }
      else if (DAT_803dc6cc == 5) {
        DAT_803de400 = 7;
        DAT_803de458 = 1;
      }
      else if ((char)DAT_803dc6cc < '\x05') {
        DAT_803de400 = 6;
        DAT_803de458 = 1;
      }
      if (*(int *)(&DAT_8031cc40 + (uint)DAT_803de400 * 4) != 0) {
        iStack_2c = *(int *)(&DAT_803a95e0 + (uint)DAT_803de400 * 4) * 0x3c;
        local_30 = 0x43300000;
        FLOAT_803de4a0 = (float)((double)CONCAT44(0x43300000,iStack_2c) - DOUBLE_803e2b08);
        DAT_803de49c = 1;
      }
    }
    FUN_8012c33c();
    if (((uVar17 & 0x1200) != 0) && (DAT_803de408 == '\0')) {
      FUN_8000bb38(0,0x100);
      uVar21 = FUN_8000bb38(0,0x3f2);
      DAT_803de408 = '<';
      FUN_8005736c(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,'\x01');
      FUN_800207ac(0);
      FUN_80014b68(0,0x1200);
      DAT_803de400 = 2;
      FUN_8012e114(0x2b1,DAT_803dc6cc,2,3);
    }
    break;
  case 2:
    DAT_803de40c = DAT_803de40c + (ushort)DAT_803dc070 * -0x32;
    if (DAT_803de40c < 0) {
      DAT_803de40c = 0;
      if (bVar3) {
        DAT_803de44c = 1;
      }
      DAT_803de400 = 0;
      if ((iVar5 == 0) || (bVar13 = FUN_802973ac(iVar5), bVar13 == 0)) {
        dVar20 = (double)FUN_8000d03c();
      }
      iVar5 = 0;
      piVar19 = &DAT_803aa070;
      do {
        if (*piVar19 != 0) {
          *(undefined4 *)(*(int *)(*piVar19 + 100) + 4) = 0;
          *(undefined4 *)(*(int *)(*piVar19 + 100) + 8) = 0;
          if (0x90000000 < *(uint *)(*piVar19 + 0x4c)) {
            *(undefined4 *)(*piVar19 + 0x4c) = 0;
          }
          dVar20 = (double)FUN_8002cc9c(dVar20,param_2,param_3,param_4,param_5,param_6,param_7,
                                        param_8,*piVar19);
          *piVar19 = 0;
        }
        piVar19 = piVar19 + 1;
        iVar5 = iVar5 + 1;
      } while (iVar5 < 4);
      FUN_8000a538((int *)0x23,0);
      FUN_8012e114(0x2b1,DAT_803dc6cc,4,3);
    }
    else {
      FUN_8012c33c();
    }
    DAT_803de404 = DAT_803de404 + (ushort)DAT_803dc070 * -0x50;
    if (DAT_803de404 < 0) {
      DAT_803de404 = 0;
    }
    break;
  case 3:
    if ((DOUBLE_803e2df0 < (double)FLOAT_803de3e0) || (DOUBLE_803e2df0 < (double)FLOAT_803de3e4)) {
      dVar20 = DOUBLE_803e2df0;
      uVar17 = FUN_8012b800();
      if (DAT_803de444 == '\0') {
        DAT_803de4a4 = (undefined2 *)&DAT_8031c468;
        dVar20 = (double)FUN_800ea3f8((int)local_44);
        if (((uVar17 & 0xff) != 0) ||
           ((dVar20 = DOUBLE_803e2df0, DOUBLE_803e2df0 == (double)FLOAT_803de3e0 &&
            (DOUBLE_803e2df0 < (double)FLOAT_803de3e4)))) {
          DAT_803de458 = DAT_803de560;
        }
        for (bVar13 = 0; bVar13 < 0xd; bVar13 = bVar13 + 1) {
          uVar7 = (uint)bVar13;
          if (local_44[uVar7] == '\0') {
            DAT_803de4a4[uVar7 * 0x10] = 0x49;
          }
          else {
            DAT_803de4a4[uVar7 * 0x10] = 0x48;
          }
          *(undefined *)(DAT_803de4a4 + uVar7 * 0x10 + 4) = 0x10;
          *(undefined *)((int)DAT_803de4a4 + uVar7 * 0x20 + 9) = 0xc;
        }
        if (DAT_803de456 == DAT_803de560) {
          DAT_803de4a4[DAT_803de560 * 0x10] = 0x4c;
        }
        else {
          DAT_803de4a4[DAT_803de560 * 0x10] = 0x4b;
          DAT_803de4a4[(uint)DAT_803de456 * 0x10] = 0x4a;
          *(undefined *)(DAT_803de4a4 + (uint)DAT_803de456 * 0x10 + 4) = 0x14;
          *(undefined *)((int)DAT_803de4a4 + (uint)DAT_803de456 * 0x20 + 9) = 0x10;
        }
        *(undefined *)(DAT_803de4a4 + DAT_803de560 * 0x10 + 4) = 0x1a;
        *(undefined *)((int)DAT_803de4a4 + DAT_803de560 * 0x20 + 9) = 0x18;
      }
      else {
        DAT_803de4a4 = &DAT_8031c640;
        for (bVar13 = 0; bVar13 < 0xc; bVar13 = bVar13 + 1) {
          uVar7 = (uint)bVar13;
          uVar10 = FUN_80020078((int)(short)(&DAT_8031c628)[uVar7]);
          if (uVar10 == 0) {
            DAT_803de4a4[uVar7 * 0x10] = 0x25;
          }
          else {
            DAT_803de4a4[uVar7 * 0x10] = 0x26;
          }
        }
      }
      uVar21 = FUN_8012bcb4(dVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (char)uVar17);
      FUN_8012bab8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    else {
      if (DAT_803de448 != 0) {
        FUN_80054484();
        DAT_803de448 = 0;
      }
      FUN_8012e114(0x3a9,0,2,0);
      DAT_803de400 = 1;
      DAT_803de404 = 0;
    }
    break;
  case 4:
    if ((DOUBLE_803e2df0 < (double)FLOAT_803de3e0) || (DOUBLE_803e2df0 < (double)FLOAT_803de3e4)) {
      uVar17 = FUN_800ea540();
      DAT_803de3b0 = uVar17 & 0xffff;
      DAT_803de3f0 = 0;
      DAT_803de3f2 = 0;
      uVar21 = FUN_8012bab8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      if ((DAT_803de424 == (short *)0x0) || (*DAT_803de424 == -1)) {
        DAT_803de424 = (short *)FUN_800ea4bc(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,
                                             param_8);
      }
    }
    else {
      FUN_800199a8(DOUBLE_803e2df0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   DAT_803de558);
      DAT_803de400 = 1;
      DAT_803de404 = 0;
      if (DAT_803de424 != (short *)0x0) {
        DAT_803de424 = (short *)0x0;
      }
    }
    break;
  case 5:
    if ((DOUBLE_803e2df0 < (double)FLOAT_803de3e0) || (DOUBLE_803e2df0 < (double)FLOAT_803de3e4)) {
      dVar20 = DOUBLE_803e2df0;
      uVar9 = FUN_8012b800();
      if (DAT_803de444 == '\0') {
        DAT_803de4a4 = (undefined2 *)&DAT_8031c7e0;
      }
      else {
        DAT_803de4a4 = (undefined2 *)&DAT_8031c9e0;
      }
      uVar21 = FUN_8012bcb4(dVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (char)uVar9);
      uVar7 = 0;
      uVar17 = 0;
      puVar14 = extraout_r4;
      while( true ) {
        if ((int)(&DAT_8031c1b0)[uVar17 & 0xff] < 0) break;
        sVar18 = 0xbf0;
        uVar10 = FUN_80020078((&DAT_8031c1b0)[uVar17 & 0xff]);
        if (uVar10 != 0) {
          sVar18 = (&DAT_8031c1ce)[(uVar17 & 0xff) * 8];
        }
        uVar9 = FUN_80054ed0(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             (int)sVar18,puVar14,param_11,param_12,param_13,param_14,param_15,
                             param_16);
        param_11 = uVar7 & 0xff;
        puVar14 = &DAT_803a9450 + param_11 * 4;
        (&DAT_803a97f8)[param_11] = uVar9;
        (&DAT_803a97a8)[param_11] = sVar18;
        uVar7 = uVar7 + 1;
        uVar17 = uVar17 + 1;
      }
      uVar7 = 10;
      uVar17 = 0;
      while( true ) {
        if ((short)(&DAT_8031c130)[(uVar17 & 0xff) * 8] < 0) break;
        sVar18 = 0xbf0;
        uVar10 = FUN_80020078((int)(short)(&DAT_8031c130)[(uVar17 & 0xff) * 8]);
        if (uVar10 != 0) {
          sVar18 = (&DAT_8031c136)[(uVar17 & 0xff) * 8];
        }
        uVar9 = FUN_80054ed0(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             (int)sVar18,puVar14,param_11,param_12,param_13,param_14,param_15,
                             param_16);
        param_11 = uVar7 & 0xff;
        puVar14 = &DAT_803a9450 + param_11 * 4;
        (&DAT_803a97f8)[param_11] = uVar9;
        (&DAT_803a97a8)[param_11] = sVar18;
        uVar7 = uVar7 + 1;
        uVar17 = uVar17 + 1;
      }
      sVar18 = 0xbf0;
      uVar17 = FUN_80020078(0x1ee);
      if (uVar17 != 0) {
        sVar18 = 0xc8a;
      }
      DAT_803a9848 = FUN_80054ed0(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  (int)sVar18,puVar14,param_11,param_12,param_13,param_14,param_15,
                                  param_16);
      sVar15 = 0xbf0;
      DAT_803a97d0 = sVar18;
      uVar17 = FUN_80020078(0x13e);
      if (uVar17 != 0) {
        sVar15 = 0xc06;
      }
      DAT_803a984c = FUN_80054ed0(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  (int)sVar15,puVar14,param_11,param_12,param_13,param_14,param_15,
                                  param_16);
      sVar18 = 0xbf0;
      DAT_803a97d2 = sVar15;
      uVar17 = FUN_80020078(0xc64);
      if (uVar17 != 0) {
        sVar18 = 0xc05;
      }
      DAT_803a9850 = FUN_80054ed0(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  (int)sVar18,puVar14,param_11,param_12,param_13,param_14,param_15,
                                  param_16);
      DAT_803a97d4 = sVar18;
      FUN_8012bab8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    else {
      for (bVar13 = 0; bVar13 < 0x28; bVar13 = bVar13 + 1) {
        if ((&DAT_803a97f8)[bVar13] != 0) {
          FUN_80054484();
          (&DAT_803a97f8)[bVar13] = 0;
          (&DAT_803a97a8)[bVar13] = 0;
        }
      }
      FUN_8012e114(0x3a9,0,2,0);
      DAT_803de400 = 1;
      DAT_803de404 = 0;
    }
    break;
  case 6:
  case 7:
  case 8:
  case 9:
  case 10:
    if ((DOUBLE_803e2df0 < (double)FLOAT_803de3e0) || (DOUBLE_803e2df0 < (double)FLOAT_803de3e4)) {
      DAT_803de4a4 = (undefined2 *)&DAT_8031c980;
      uVar21 = FUN_8012bcb4(DOUBLE_803e2df0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            '\0');
      FUN_8012bab8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      if (((uVar17 & 0x100) != 0) && (DOUBLE_803e2df0 < (double)FLOAT_803de3e4)) {
        FUN_8000bb38(0,0x418);
        FUN_80014b68(0,0x100);
        FLOAT_803de3e4 = FLOAT_803e2df8;
      }
    }
    else if (DAT_803de458 == 1) {
      if (DAT_803de400 == 9) {
        DAT_803de400 = 10;
        FLOAT_803de3e4 = FLOAT_803e2ae0;
      }
      else {
        if (DAT_803de400 < 9) {
          if (7 < DAT_803de400) {
            if (DAT_803dc084 == '\0') {
              DAT_803de400 = 10;
            }
            else {
              DAT_803de400 = 9;
            }
            FLOAT_803de3e4 = FLOAT_803e2ae0;
            break;
          }
        }
        else if (DAT_803de400 < 0xb) {
          FUN_8000a538((int *)0x23,0);
          iVar5 = (**(code **)(*DAT_803dd72c + 0x30))();
          if (iVar5 == 0) {
            (**(code **)(*DAT_803dd72c + 0x20))();
          }
          else {
            (**(code **)(*DAT_803dd72c + 0x28))();
          }
          break;
        }
        DAT_803de400 = 1;
        DAT_803de404 = 0;
      }
    }
    else if (DAT_803de400 == 8) {
      *(char *)(iVar6 + 9) = *(char *)(iVar6 + 9) + -1;
      uVar21 = FUN_802973e4(iVar5);
      FUN_800199a8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803de55c);
      DAT_803de400 = 2;
      DAT_803de408 = '<';
      FUN_8012e114(0x2b1,DAT_803dc6cc,2,3);
    }
    else {
      if (DAT_803de400 < 8) {
        if (DAT_803de400 != 6) {
          if (5 < DAT_803de400) {
            FUN_800e8954(DOUBLE_803e2df0,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            DAT_803de3f8 = 0x80;
            DAT_803de400 = 1;
            DAT_803de404 = 0;
          }
          break;
        }
      }
      else if (DAT_803de400 != 10) {
        if (DAT_803de400 < 10) {
          uVar21 = FUN_800e9bcc();
          FUN_800e8954(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          DAT_803de3f8 = 0x80;
          DAT_803de400 = 10;
          DAT_803de458 = 1;
          FLOAT_803de3e4 = FLOAT_803e2ae0;
          DAT_803de404 = 0;
        }
        break;
      }
      DAT_803de55c = 0x15;
      FUN_800199a8(DOUBLE_803e2df0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x15);
      DAT_803de3fe = 0;
      DAT_803de3f4 = 0;
      DAT_803de3f6 = 0;
      DAT_803dc6c4 = 0xffffffff;
      FUN_8012e114(0x2b1,1,4,3);
      DAT_803de400 = 2;
      DAT_803de408 = '<';
      (**(code **)(*DAT_803dd6cc + 8))(0x14,1);
      DAT_803de414 = 1;
    }
    break;
  case 0xb:
    if ((DOUBLE_803e2df0 < (double)FLOAT_803de3e0) || (DOUBLE_803e2df0 < (double)FLOAT_803de3e4)) {
      dVar20 = DOUBLE_803e2df0;
      uVar7 = FUN_80020078(0x3f5);
      DAT_803de3d8 = '\0';
      if (iVar5 != 0) {
        dVar20 = (double)*(float *)(iVar5 + 0xc);
        param_2 = (double)*(float *)(iVar5 + 0x14);
        DAT_803de560 = FUN_8005b128();
        if (DAT_803de560 == 7) {
          DAT_803de3d6 = 0;
          while( true ) {
            if ((3 < DAT_803de3d6) ||
               (uVar10 = FUN_80020078((int)*(short *)(&DAT_8031bc80 + DAT_803de3d6 * 8)),
               uVar10 == 0)) goto LAB_8012b6e0;
            uVar10 = FUN_80020078((int)*(short *)(&DAT_8031bc82 + DAT_803de3d6 * 8));
            if (uVar10 == 0) break;
            DAT_803de3d6 = DAT_803de3d6 + 1;
          }
          if ((int)uVar7 < (int)(uint)(byte)(&DAT_8031bc84)[DAT_803de3d6 * 8]) {
            DAT_803de3d8 = '\x01';
          }
          else {
            DAT_803de3d8 = '\x02';
          }
        }
      }
LAB_8012b6e0:
      if ((((uVar17 & 0x100) == 0) || (dVar20 = (double)FLOAT_803de3e4, dVar20 <= DOUBLE_803e2df0))
         || (dVar20 = (double)FLOAT_803de3e0, dVar20 < DOUBLE_803e2be0)) {
        if ((((uVar17 & 0x200) != 0) && (dVar20 = (double)FLOAT_803de3e4, DOUBLE_803e2df0 < dVar20))
           && (dVar20 = (double)FLOAT_803de3e0, DOUBLE_803e2be0 <= dVar20)) {
          dVar20 = (double)FUN_80014b68(0,0x200);
          FLOAT_803de3e4 = FLOAT_803e2df8;
          DAT_803de3d9 = 0;
        }
      }
      else {
        if (DAT_803de3d8 == '\x02') {
          FUN_800201ac(0x3f5,uVar7 - (byte)(&DAT_8031bc84)[DAT_803de3d6 * 8]);
          FUN_800201ac((int)*(short *)(&DAT_8031bc82 + DAT_803de3d6 * 8),1);
        }
        DAT_803de3d9 = 1;
        dVar20 = (double)FUN_80014b68(0,0x100);
        FLOAT_803de3e4 = FLOAT_803e2df8;
      }
      FUN_8012bab8(dVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    else {
      uVar21 = FUN_800207ac(0);
      FUN_8005736c(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,'\x01');
      DAT_803de400 = 2;
      DAT_803de408 = '<';
    }
  }
  FUN_80286880();
  return;
}

