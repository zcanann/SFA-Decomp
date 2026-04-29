#include "ghidra_import.h"
#include "main/dll/DR/hightop.h"

extern undefined4 FUN_800066e0();
extern undefined8 FUN_80006728();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80017648();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern int FUN_8001769c();
extern undefined4 FUN_800178bc();
extern undefined4 FUN_80017a78();
extern undefined4 FUN_80017a7c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017af0();
extern int FUN_80017b00();
extern int ObjGroup_FindNearestObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80040da0();
extern undefined4 FUN_80041c10();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80043030();
extern int FUN_8005337c();
extern undefined4 FUN_80053754();
extern undefined4 FUN_80053b3c();
extern undefined4 FUN_80053b70();
extern int FUN_80056600();
extern undefined4 FUN_800569f4();
extern undefined4 FUN_80056a20();
extern undefined4 FUN_8005cff0();
extern undefined4 FUN_8005d0ac();
extern undefined4 FUN_8005d114();
extern undefined4 FUN_8005d17c();
extern undefined4 FUN_8006f498();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_80080f10();
extern undefined4 FUN_80080f28();
extern undefined4 FUN_80080f3c();
extern uint FUN_80080f40();
extern undefined4 FUN_80125b7c();
extern undefined4 FUN_80198e08();
extern int FUN_80198fa4();
extern undefined4 FUN_801991bc();
extern undefined4 FUN_80199440();
extern undefined4 FUN_8019959c();
extern undefined4 FUN_80199744();
extern int FUN_8020a6fc();
extern undefined4 FUN_8020a908();
extern undefined8 FUN_8028682c();
extern int FUN_8028683c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80294bd4();
extern int FUN_80294dbc();
extern uint countLeadingZeros();

extern uint DAT_803ad438;
extern undefined4 DAT_803ad43c;
extern undefined4 DAT_803ad43e;
extern undefined4 DAT_803ad4d8;
extern undefined4 DAT_803ad4dc;
extern undefined4 DAT_803ad4e0;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dca70;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd704;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de788;
extern undefined4 DAT_803de789;
extern undefined4 DAT_803de78c;
extern f64 DOUBLE_803e4d68;
extern f64 DOUBLE_803e4d88;
extern f32 FLOAT_803e4d70;
extern f32 FLOAT_803e4d90;
extern f32 FLOAT_803e4d94;
extern f32 FLOAT_803e4d98;
extern f32 FLOAT_803e4d9c;

/*
 * --INFO--
 *
 * Function: FUN_801993b0
 * EN v1.0 Address: 0x801993B0
 * EN v1.0 Size: 6644b
 * EN v1.1 Address: 0x8019992C
 * EN v1.1 Size: 3936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801993b0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,int param_12,
                 int param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  undefined2 uVar2;
  ushort uVar3;
  double dVar4;
  short sVar6;
  uint uVar5;
  short *psVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  byte bVar16;
  int *piVar11;
  short *psVar12;
  int iVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  int iVar17;
  byte bVar18;
  byte *pbVar19;
  char cVar20;
  byte *pbVar21;
  double extraout_f1;
  double extraout_f1_00;
  double extraout_f1_01;
  double dVar22;
  double extraout_f1_02;
  double extraout_f1_03;
  undefined8 uVar23;
  int local_38;
  int local_34 [13];
  
  uVar23 = FUN_8028682c();
  psVar7 = (short *)((ulonglong)uVar23 >> 0x20);
  iVar17 = (int)uVar23;
  pbVar19 = *(byte **)(psVar7 + 0x5c);
  pbVar21 = (byte *)(*(int *)(psVar7 + 0x26) + 0x18);
  bVar18 = 0;
  dVar22 = extraout_f1;
  do {
    dVar4 = DOUBLE_803e4d68;
    cVar20 = (char)param_11;
    if (7 < bVar18) {
      if (cVar20 < '\x01') {
        if (cVar20 < '\0') {
          *pbVar19 = *pbVar19 | 2;
        }
      }
      else {
        *pbVar19 = *pbVar19 | 1;
        FUN_80017698((int)*(short *)(pbVar19 + 0x80),1);
      }
      FUN_80286878();
      return;
    }
    if ((pbVar21[1] != 0) && ((bVar16 = *pbVar19, (bVar16 & 4) == 0 || ((*pbVar21 & 0x20) != 0)))) {
      bVar1 = *pbVar21;
      if ((bVar1 & 0x10) == 0) {
        if (cVar20 == '\x01') {
          if ((bVar1 & 1) != 0) {
            if ((bVar16 & 1) != 0) {
              bVar1 = bVar1 & 4;
joined_r0x80199a04:
              if (bVar1 == 0) goto switchD_80199a5c_caseD_0;
            }
            goto code_r0x80199a48;
          }
        }
        else if ((cVar20 == -1) && ((bVar1 & 2) != 0)) {
          if ((bVar16 & 2) != 0) {
            bVar1 = bVar1 & 8;
            goto joined_r0x80199a04;
          }
          goto code_r0x80199a48;
        }
      }
      else if ((bVar1 & 1) == 0) {
        if (((bVar1 & 2) == 0) || (cVar20 < '\x01')) goto code_r0x80199a48;
      }
      else if (-1 < cVar20) {
code_r0x80199a48:
        switch(pbVar21[1]) {
        case 1:
          bVar16 = pbVar21[2];
          if (bVar16 == 9) {
            iVar10 = FUN_80017a98();
            if (iVar10 != 0) {
              dVar22 = (double)FUN_80294bd4((double)FLOAT_803e4d70,iVar10,10);
            }
          }
          else if (bVar16 < 9) {
            if ((7 < bVar16) && (iVar10 = FUN_80017a98(), iVar10 != 0)) {
              dVar22 = (double)FUN_80294bd4((double)FLOAT_803e4d70,iVar10,1);
            }
          }
          else if (bVar16 == 0xb) {
            iVar10 = FUN_80017a98();
            if (iVar10 != 0) {
              dVar22 = (double)FUN_80294bd4((double)FLOAT_803e4d94,iVar10,1);
            }
          }
          else if ((bVar16 < 0xb) && (iVar10 = FUN_80017a98(), iVar10 != 0)) {
            dVar22 = (double)FUN_80294bd4((double)FLOAT_803e4d70,iVar10,0xb);
          }
          break;
        case 4:
          if (cVar20 < '\0') {
            dVar22 = (double)FUN_80006810((int)psVar7,*(short *)(pbVar21 + 2));
          }
          else {
            dVar22 = (double)FUN_80006824((uint)psVar7,*(ushort *)(pbVar21 + 2));
          }
          break;
        case 5:
          dVar22 = (double)*(float *)(pbVar19 + 4);
          break;
        case 6:
          dVar22 = (double)(**(code **)(*DAT_803dd6d0 + 0x24))(pbVar21[2],pbVar21[3],0);
          break;
        case 8:
          switch(pbVar21[2]) {
          case 0:
            if (1 < pbVar21[3]) {
              pbVar21[3] = 1;
            }
            dVar22 = (double)FUN_8005d17c((uint)pbVar21[3]);
            break;
          case 1:
            if (1 < pbVar21[3]) {
              pbVar21[3] = 1;
            }
            dVar22 = (double)FUN_8005d114((uint)pbVar21[3]);
            break;
          case 2:
            if (1 < pbVar21[3]) {
              pbVar21[3] = 1;
            }
            dVar22 = (double)FUN_8005d0ac((uint)pbVar21[3]);
            break;
          case 3:
            if (1 < pbVar21[3]) {
              pbVar21[3] = 1;
            }
            dVar22 = (double)(**(code **)(*DAT_803dd6e4 + 0x1c))(pbVar21[3]);
            break;
          case 4:
            dVar22 = (double)(**(code **)(*DAT_803dd704 + 0xc))(pbVar21[3]);
            break;
          case 5:
            dVar22 = (double)FUN_8006f498((uint)pbVar21[3]);
            break;
          case 6:
            if (pbVar21[3] == 0) {
              dVar22 = (double)FUN_80080f28(7,'\0');
            }
            else {
              dVar22 = (double)FUN_80080f28(7,'\x01');
            }
            break;
          case 7:
            if (pbVar21[3] == 0) {
              dVar22 = (double)FUN_8005cff0(0);
            }
            else {
              dVar22 = (double)FUN_8005cff0(1);
            }
            break;
          case 8:
            if (pbVar21[3] == 0) {
              dVar22 = (double)FUN_80053b3c();
            }
            else {
              dVar22 = (double)FUN_80053b70();
            }
            break;
          case 9:
            uVar5 = FUN_80080f40();
            local_34[2] = (int)pbVar21[3];
            local_34[1] = 0x43300000;
            dVar22 = (double)FUN_80080f3c((double)(float)((double)CONCAT44(0x43300000,local_34[2]) -
                                                         DOUBLE_803e4d88),uVar5 ^ 1);
            break;
          case 10:
            local_34[2] = (int)pbVar21[3];
            local_34[1] = 0x43300000;
            dVar22 = (double)FUN_80080f3c((double)(float)((double)CONCAT44(0x43300000,local_34[2]) -
                                                         DOUBLE_803e4d88),0);
            break;
          case 0xb:
            local_34[2] = (int)pbVar21[3];
            local_34[1] = 0x43300000;
            dVar22 = (double)FUN_80080f3c((double)(float)((double)CONCAT44(0x43300000,local_34[2]) -
                                                         DOUBLE_803e4d88),1);
          }
          break;
        case 10:
          FUN_80006728(dVar22,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar7,iVar17,
                       (uint)*(ushort *)(pbVar21 + 2),param_12,param_13,param_14,param_15,param_16);
          dVar22 = (double)FUN_800723a0();
          break;
        case 0xb:
          bVar16 = pbVar21[2];
          if (bVar16 == 2) {
            dVar22 = (double)(**(code **)(*DAT_803dd6d4 + 0xc))(pbVar21[3],0);
          }
          else if (bVar16 < 2) {
            if (bVar16 == 0) {
LAB_80199dec:
              iVar10 = ObjGroup_FindNearestObject(0xf,psVar7,(float *)0x0);
              dVar22 = extraout_f1_00;
              if (iVar10 != 0) {
                dVar22 = (double)(**(code **)(*DAT_803dd6d4 + 0x48))(pbVar21[3],iVar10,0xffffffff);
              }
            }
            else {
              dVar22 = (double)(**(code **)(*DAT_803dd6d4 + 0xc))(pbVar21[3],1);
            }
          }
          else if (bVar16 < 4) goto LAB_80199dec;
          break;
        case 0xc:
          uVar3 = *(ushort *)(pbVar21 + 2);
          iVar10 = FUN_80017b00(&local_38,local_34);
          for (; local_38 < local_34[0]; local_38 = local_38 + 1) {
            iVar13 = *(int *)(iVar10 + local_38 * 4);
            psVar12 = *(short **)(iVar13 + 0x4c);
            if (psVar12 == (short *)0x0) goto LAB_80199ef0;
            sVar6 = *psVar12;
            if (sVar6 == 0x54) {
LAB_80199ed4:
              if ((int)psVar12[0x1c] == (uint)uVar3) {
                dVar22 = (double)FUN_801993b0(dVar22,param_2,param_3,param_4,param_5,param_6,param_7
                                              ,param_8,iVar13,iVar17,param_11,param_12,param_13,
                                              param_14,param_15,param_16);
              }
            }
            else if (sVar6 < 0x54) {
              if ((sVar6 < 0x51) && (0x4a < sVar6)) goto LAB_80199ed4;
            }
            else if (sVar6 == 0x230) goto LAB_80199ed4;
LAB_80199ef0:
;
          }
          break;
        case 0xd:
          param_14 = 0;
          param_13 = param_12;
          FUN_800066e0(dVar22,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar7,iVar17,
                       (uint)*(ushort *)(pbVar21 + 2),param_11,param_12,0,param_15,param_16);
          break;
        case 0x10:
          iVar10 = FUN_80017a98();
          dVar22 = (double)FUN_80017a78(iVar10,(uint)pbVar21[2]);
          break;
        case 0x11:
          dVar22 = (double)FUN_80017698(0x4e3,(uint)*(ushort *)(pbVar21 + 2));
          break;
        case 0x12:
          bVar16 = pbVar21[2];
          uVar9 = (uint)bVar16 << 8 & 0x3f00 | (uint)pbVar21[3];
          uVar8 = FUN_80017690(uVar9);
          uVar5 = ((uint)bVar16 << 8) >> 0xe;
          if (uVar5 == 0) {
            uVar8 = 0;
          }
          else if (uVar5 == 1) {
            uVar8 = 0xffffffff;
          }
          else if (uVar5 == 2) {
            uVar8 = ~uVar8;
          }
          dVar22 = (double)FUN_80017698(uVar9,uVar8);
          break;
        case 0x13:
          dVar22 = (double)(**(code **)(*DAT_803dd72c + 0x50))
                                     ((int)*(char *)(psVar7 + 0x56),*(undefined2 *)(pbVar21 + 2),1);
          break;
        case 0x14:
          dVar22 = (double)(**(code **)(*DAT_803dd72c + 0x50))
                                     ((int)*(char *)(psVar7 + 0x56),*(undefined2 *)(pbVar21 + 2),0);
          break;
        case 0x15:
          piVar11 = (int *)FUN_80017af0(*(ushort *)(pbVar21 + 2) + 2);
          if (piVar11 != (int *)0x0) {
            for (; *piVar11 != -1; piVar11 = piVar11 + 1) {
              iVar10 = FUN_8005337c(*piVar11);
              if (iVar10 == 0) {
                param_13 = 0;
                param_14 = 0;
                param_15 = 0;
                param_16 = 0;
                dVar22 = (double)FUN_80017648();
              }
            }
          }
          break;
        case 0x16:
          piVar11 = (int *)FUN_80017af0(*(ushort *)(pbVar21 + 2) + 2);
          if (piVar11 != (int *)0x0) {
            for (; *piVar11 != -1; piVar11 = piVar11 + 1) {
              iVar10 = FUN_8005337c(*piVar11);
              if (iVar10 != 0) {
                dVar22 = (double)FUN_80053754();
              }
            }
          }
          break;
        case 0x18:
          dVar22 = (double)(**(code **)(*DAT_803dd72c + 0x44))
                                     ((int)*(char *)(psVar7 + 0x56),*(undefined2 *)(pbVar21 + 2));
          break;
        case 0x1a:
          dVar22 = (double)(**(code **)(*DAT_803dd72c + 0x50))(pbVar21[3],pbVar21[2],1);
          break;
        case 0x1b:
          dVar22 = (double)(**(code **)(*DAT_803dd72c + 0x50))(pbVar21[3],pbVar21[2],0);
          break;
        case 0x1c:
          bVar16 = pbVar21[2];
          if (bVar16 == 2) {
            uVar5 = countLeadingZeros((uint)pbVar21[3]);
            dVar22 = (double)FUN_80017698(0x3af,uVar5 >> 5);
          }
          else if (bVar16 < 2) {
            if (bVar16 == 0) {
              uVar5 = countLeadingZeros((uint)pbVar21[3]);
              dVar22 = (double)FUN_80017698(0x3ab,uVar5 >> 5);
            }
            else {
              uVar5 = countLeadingZeros((uint)pbVar21[3]);
              dVar22 = (double)FUN_80017698(0x3ac,uVar5 >> 5);
            }
          }
          else if (bVar16 < 4) {
            bVar16 = pbVar21[3];
            if (bVar16 == 1) {
              uVar23 = FUN_80017698(0x3b0,0);
              uVar14 = FUN_80017a98();
              uVar15 = FUN_80017a98();
              uVar23 = FUN_80006728(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    uVar15,uVar14,0x134,0,param_13,param_14,param_15,param_16);
              uVar14 = FUN_80017a98();
              uVar15 = FUN_80017a98();
              uVar23 = FUN_80006728(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    uVar15,uVar14,0x135,0,param_13,param_14,param_15,param_16);
              uVar14 = FUN_80017a98();
              uVar15 = FUN_80017a98();
              uVar23 = FUN_80006728(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    uVar15,uVar14,0x142,0,param_13,param_14,param_15,param_16);
              dVar22 = (double)FUN_80080f10(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,
                                            param_8);
            }
            else if (bVar16 == 0) {
              uVar23 = FUN_80017698(0x3b0,1);
              uVar14 = FUN_80017a98();
              uVar15 = FUN_80017a98();
              uVar23 = FUN_80006728(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    uVar15,uVar14,0x134,0,param_13,param_14,param_15,param_16);
              uVar14 = FUN_80017a98();
              uVar15 = FUN_80017a98();
              uVar23 = FUN_80006728(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    uVar15,uVar14,0x135,0,param_13,param_14,param_15,param_16);
              uVar14 = FUN_80017a98();
              uVar15 = FUN_80017a98();
              dVar22 = (double)FUN_80006728(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,
                                            param_8,uVar15,uVar14,0x142,0,param_13,param_14,param_15
                                            ,param_16);
            }
            else if (bVar16 < 3) {
              uVar23 = FUN_80017698(0x3b0,1);
              uVar14 = FUN_80017a98();
              uVar15 = FUN_80017a98();
              uVar23 = FUN_80006728(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    uVar15,uVar14,0x136,0,param_13,param_14,param_15,param_16);
              uVar14 = FUN_80017a98();
              uVar15 = FUN_80017a98();
              uVar23 = FUN_80006728(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    uVar15,uVar14,0x137,0,param_13,param_14,param_15,param_16);
              uVar14 = FUN_80017a98();
              uVar15 = FUN_80017a98();
              dVar22 = (double)FUN_80006728(uVar23,param_2,param_3,param_4,param_5,param_6,param_7,
                                            param_8,uVar15,uVar14,0x143,0,param_13,param_14,param_15
                                            ,param_16);
            }
          }
          break;
        case 0x1d:
          if (pbVar21[2] == 0) {
            FUN_80017698(0x966,1);
            FUN_80017698(0x967,1);
            dVar22 = (double)FUN_80017698(0x968,1);
          }
          else {
            FUN_80017698(0x966,0);
            FUN_80017698(0x967,0);
            dVar22 = (double)FUN_80017698(0x968,0);
          }
          break;
        case 0x1e:
          dVar22 = (double)(**(code **)(*DAT_803dd72c + 0x44))(pbVar21[3],pbVar21[2]);
          break;
        case 0x1f:
          psVar12 = (short *)FUN_80017a98();
          sVar6 = *psVar7 - *psVar12;
          if (0x8000 < sVar6) {
            sVar6 = sVar6 + 1;
          }
          if (sVar6 < -0x8000) {
            sVar6 = sVar6 + -1;
          }
          iVar10 = (int)sVar6;
          if (iVar10 < 0) {
            iVar10 = -iVar10;
          }
          if (iVar10 < 0x4001) {
            iVar10 = FUN_80056600();
            param_13 = *DAT_803dd72c;
            dVar22 = (double)(**(code **)(param_13 + 0x1c))
                                       (psVar7 + 6,(int)*psVar7,pbVar21[3],iVar10);
          }
          else {
            iVar10 = FUN_80056600();
            param_13 = *DAT_803dd72c;
            dVar22 = (double)(**(code **)(param_13 + 0x1c))
                                       (psVar7 + 6,(int)(short)(*psVar7 + -0x8000),pbVar21[3],iVar10
                                       );
          }
          break;
        case 0x20:
          if (pbVar21[2] == 0) {
            dVar22 = (double)FUN_80056a20();
          }
          else {
            dVar22 = (double)FUN_800569f4();
          }
          break;
        case 0x21:
          bVar16 = pbVar21[2];
          uVar5 = (uint)bVar16 << 8 & 0x1f00 | (uint)pbVar21[3];
          uVar9 = FUN_80017690(uVar5);
          dVar22 = (double)FUN_80017698(uVar5,uVar9 ^ 1 << (((uint)bVar16 << 8) >> 0xd));
          break;
        case 0x22:
          uVar2 = *(undefined2 *)(pbVar21 + 2);
          bVar16 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(psVar7 + 0x56),uVar2);
          dVar22 = (double)(**(code **)(*DAT_803dd72c + 0x50))
                                     ((int)*(char *)(psVar7 + 0x56),uVar2,bVar16 ^ 1);
          break;
        case 0x23:
          bVar16 = pbVar21[2];
          if (bVar16 == 2) {
            dVar22 = (double)(**(code **)(*DAT_803dd72c + 0x28))();
          }
          else if (bVar16 < 2) {
            if (bVar16 == 0) {
              iVar10 = FUN_80056600();
              param_13 = *DAT_803dd72c;
              dVar22 = (double)(**(code **)(param_13 + 0x24))(psVar7 + 6,(int)*psVar7,iVar10,0);
            }
            else {
              dVar22 = (double)(**(code **)(*DAT_803dd72c + 0x2c))();
            }
          }
          else if (bVar16 < 4) {
            iVar10 = FUN_80056600();
            param_13 = *DAT_803dd72c;
            dVar22 = (double)(**(code **)(param_13 + 0x24))(psVar7 + 6,(int)*psVar7,iVar10,1);
          }
          break;
        case 0x26:
          iVar10 = FUN_80017a90();
          if (iVar10 != 0) {
            bVar16 = pbVar21[2];
            if (bVar16 == 2) {
              iVar13 = ObjGroup_FindNearestObject(0x32,iVar10,(float *)0x0);
              dVar22 = extraout_f1_02;
              if (iVar13 == 0) {
                iVar13 = ObjGroup_FindNearestObject(0x31,iVar10,(float *)0x0);
                dVar22 = extraout_f1_03;
              }
              if (iVar13 != 0) {
                dVar22 = (double)(**(code **)(**(int **)(iVar10 + 0x68) + 0x38))(iVar10);
              }
            }
            else if (bVar16 < 2) {
              if (bVar16 == 0) {
                dVar22 = (double)(**(code **)(**(int **)(iVar10 + 0x68) + 0x3c))();
              }
              else {
                iVar10 = FUN_80017a90();
                dVar22 = (double)FUN_80017ac8(dVar22,param_2,param_3,param_4,param_5,param_6,param_7
                                              ,param_8,iVar10);
              }
            }
            else if (bVar16 == 4) {
              dVar22 = (double)FUN_80017698(0xd00,1);
            }
            else if (bVar16 < 4) {
              dVar22 = (double)FUN_80017698(0xd00,0);
            }
          }
          break;
        case 0x27:
          FUN_80041c10(dVar22,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (uint)*(ushort *)(pbVar21 + 2));
          FUN_800178bc();
          dVar22 = (double)FUN_800723a0();
          break;
        case 0x28:
          FUN_80043030(dVar22,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          dVar22 = (double)FUN_800723a0();
          break;
        case 0x2a:
          FUN_80042bec((uint)pbVar21[2],(uint)pbVar21[3]);
          dVar22 = (double)FUN_800723a0();
          break;
        case 0x2b:
          FUN_80042b9c((uint)pbVar21[2],(uint)pbVar21[3],0);
          dVar22 = (double)FUN_800723a0();
          break;
        case 0x2c:
          param_2 = (double)FLOAT_803e4d98;
          local_34[2] = *(ushort *)(pbVar21 + 2) ^ 0x80000000;
          local_34[1] = 0x43300000;
          **(float **)(iVar17 + 0xb8) =
               (float)(param_2 *
                      (double)(float)((double)CONCAT44(0x43300000,local_34[2]) - DOUBLE_803e4d68));
          dVar22 = dVar4;
          break;
        case 0x2d:
          iVar10 = FUN_80017a98();
          if (iVar10 == 0) {
            iVar10 = FUN_8020a6fc();
            if (iVar10 != 0) {
              dVar22 = (double)FUN_80125b7c(dVar22,param_2,param_3,param_4,param_5,param_6,param_7,
                                            param_8,(uint)*(ushort *)(pbVar21 + 2));
            }
          }
          else {
            param_13 = *DAT_803dd6e8;
            dVar22 = (double)(**(code **)(param_13 + 0x38))
                                       (*(undefined2 *)(pbVar21 + 2),0x14,0x8c,1);
          }
          break;
        case 0x2e:
          dVar22 = (double)FUN_80040da0();
          break;
        case 0x2f:
          iVar10 = ObjGroup_FindNearestObject(0x4c,psVar7,(float *)0x0);
          dVar22 = extraout_f1_01;
          if (iVar10 != 0) {
            dVar22 = (double)FUN_8020a908(iVar10,(uint)pbVar21[3] * 0x3c);
          }
        }
      }
    }
switchD_80199a5c_caseD_0:
    bVar18 = bVar18 + 1;
    pbVar21 = pbVar21 + 4;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_8019ada4
 * EN v1.0 Address: 0x8019ADA4
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x8019A88C
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019ada4(int param_1)
{
  byte *pbVar1;
  byte bVar2;
  
  pbVar1 = (byte *)(*(int *)(param_1 + 0x4c) + 0x18);
  for (bVar2 = 0; bVar2 < 8; bVar2 = bVar2 + 1) {
    if ((((*pbVar1 & 3) != 0) && (pbVar1[1] != 3)) && (pbVar1[1] == 4)) {
      FUN_80006810(param_1,*(short *)(pbVar1 + 2));
    }
    pbVar1 = pbVar1 + 4;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019ae30
 * EN v1.0 Address: 0x8019AE30
 * EN v1.0 Size: 2172b
 * EN v1.1 Address: 0x8019A92C
 * EN v1.1 Size: 1268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019ae30(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,float *param_11,undefined4 param_12,
                 int param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  byte *pbVar8;
  int unaff_r28;
  int iVar9;
  short *psVar10;
  byte *pbVar11;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 uVar12;
  float local_28 [10];
  
  iVar4 = FUN_8028683c();
  pbVar11 = *(byte **)(iVar4 + 0xb8);
  psVar10 = *(short **)(iVar4 + 0x4c);
  local_28[0] = FLOAT_803e4d9c;
  if ((psVar10[0x1c] < 1) || (*psVar10 == 0xf4)) {
    uVar12 = extraout_f1;
    iVar5 = FUN_80017a98();
    if (iVar5 == 0) {
      iVar5 = FUN_8020a6fc();
    }
    else {
      iVar6 = FUN_80294dbc(iVar5);
      if (iVar6 != 0) {
        iVar5 = iVar6;
      }
    }
    iVar6 = FUN_80017a90();
    if ((iVar5 != 0) || (iVar6 != 0)) {
      if ((*pbVar11 & 4) == 0) {
        bVar3 = true;
        uVar7 = (uint)*(byte *)((int)psVar10 + 0x43);
        if (uVar7 < 3) {
          if (uVar7 == 1) {
            if (iVar6 == 0) {
              bVar3 = false;
            }
          }
          else if (uVar7 == 0) {
            iVar6 = iVar5;
            if (iVar5 == 0) {
              bVar3 = false;
            }
          }
          else {
            iVar6 = unaff_r28;
            if (uVar7 < 3) {
              iVar6 = (**(code **)(*DAT_803dd6d0 + 0xc))();
              uVar12 = extraout_f1_01;
            }
          }
        }
        else {
          param_11 = local_28;
          iVar6 = ObjGroup_FindNearestObject(uVar7 - 1,iVar4,param_11);
          uVar12 = extraout_f1_00;
          if (iVar6 == 0) {
            bVar3 = false;
          }
        }
        if (bVar3) {
          if ((*pbVar11 & 0x40) == 0) {
            *(undefined4 *)(pbVar11 + 0x1c) = *(undefined4 *)(pbVar11 + 0x28);
            *(undefined4 *)(pbVar11 + 0x20) = *(undefined4 *)(pbVar11 + 0x2c);
            *(undefined4 *)(pbVar11 + 0x24) = *(undefined4 *)(pbVar11 + 0x30);
          }
          else {
            if (*(byte *)((int)psVar10 + 0x43) == 2) {
              *(undefined4 *)(pbVar11 + 0x1c) = *(undefined4 *)(iVar6 + 0x18);
              *(undefined4 *)(pbVar11 + 0x20) = *(undefined4 *)(iVar6 + 0x1c);
              *(undefined4 *)(pbVar11 + 0x24) = *(undefined4 *)(iVar6 + 0x20);
            }
            else if (*(byte *)((int)psVar10 + 0x43) < 2) {
              *(undefined4 *)(pbVar11 + 0x1c) = *(undefined4 *)(iVar6 + 0x8c);
              *(undefined4 *)(pbVar11 + 0x20) = *(undefined4 *)(iVar6 + 0x90);
              *(undefined4 *)(pbVar11 + 0x24) = *(undefined4 *)(iVar6 + 0x94);
            }
            else {
              *(undefined4 *)(pbVar11 + 0x1c) = *(undefined4 *)(iVar6 + 0x80);
              *(undefined4 *)(pbVar11 + 0x20) = *(undefined4 *)(iVar6 + 0x84);
              *(undefined4 *)(pbVar11 + 0x24) = *(undefined4 *)(iVar6 + 0x88);
            }
            *pbVar11 = *pbVar11 & 0xbf;
          }
          if (*(byte *)((int)psVar10 + 0x43) < 3) {
            *(undefined4 *)(pbVar11 + 0x28) = *(undefined4 *)(iVar6 + 0x18);
            *(undefined4 *)(pbVar11 + 0x2c) = *(undefined4 *)(iVar6 + 0x1c);
            *(undefined4 *)(pbVar11 + 0x30) = *(undefined4 *)(iVar6 + 0x20);
          }
          else {
            *(undefined4 *)(pbVar11 + 0x28) = *(undefined4 *)(iVar6 + 0xc);
            *(undefined4 *)(pbVar11 + 0x2c) = *(undefined4 *)(iVar6 + 0x10);
            *(undefined4 *)(pbVar11 + 0x30) = *(undefined4 *)(iVar6 + 0x14);
          }
        }
        sVar1 = *psVar10;
        if (sVar1 == 0x50) {
          uVar12 = FUN_801993b0(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4
                                ,iVar5,1,0,param_13,param_14,param_15,param_16);
          iVar5 = FUN_8001769c();
          if (iVar5 != 0) {
            FUN_80017ac8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
          }
        }
        else if (sVar1 < 0x50) {
          if (sVar1 == 0x4d) {
            if (bVar3) {
              iVar9 = *(int *)(iVar4 + 0xb8);
              iVar5 = FUN_80198fa4(iVar4,(float *)(iVar9 + 0x28));
              iVar9 = FUN_80198fa4(iVar4,(float *)(iVar9 + 0x1c));
              if (iVar5 == 0) {
                if (iVar9 == 0) {
                  FUN_801993b0(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                               iVar6,0xfffffffe,0,param_13,param_14,param_15,param_16);
                }
                else {
                  FUN_801993b0(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                               iVar6,0xffffffff,0,param_13,param_14,param_15,param_16);
                }
              }
              else if (iVar9 == 0) {
                FUN_801993b0(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                             iVar6,1,0,param_13,param_14,param_15,param_16);
              }
              else {
                FUN_801993b0(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                             iVar6,2,0,param_13,param_14,param_15,param_16);
              }
            }
          }
          else if (sVar1 < 0x4d) {
            if (sVar1 == 0x4b) {
              if (bVar3) {
                FUN_80199744(iVar4,iVar6,param_11,param_12,param_13,param_14,param_15,param_16);
              }
            }
            else if (0x4a < sVar1) {
              bVar2 = true;
              if (((int)*(short *)(pbVar11 + 0x82) != 0xffffffff) &&
                 (uVar7 = FUN_80017690((int)*(short *)(pbVar11 + 0x82)), uVar7 == 0)) {
                bVar2 = false;
              }
              if ((bVar2) && (bVar3)) {
                FUN_801991bc();
              }
            }
          }
          else if ((sVar1 < 0x4f) &&
                  (*(uint *)(pbVar11 + 8) = *(int *)(pbVar11 + 8) + (uint)DAT_803dc070,
                  (uint)(ushort)psVar10[0x23] <= *(uint *)(pbVar11 + 8))) {
            FUN_801993b0(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,0,1,0,
                         param_13,param_14,param_15,param_16);
          }
        }
        else if (sVar1 == 0xf4) {
          if (bVar3) {
            FUN_80198e08();
          }
        }
        else if (sVar1 < 0xf4) {
          if (sVar1 == 0x54) {
            bVar3 = true;
            iVar6 = 0;
            pbVar8 = pbVar11;
            while ((iVar6 < 4 && (bVar3))) {
              if (((int)*(short *)(pbVar8 + 0x82) != 0xffffffff) &&
                 (uVar7 = FUN_80017690((int)*(short *)(pbVar8 + 0x82)), uVar7 == 0)) {
                bVar3 = false;
              }
              pbVar8 = pbVar8 + 2;
              iVar6 = iVar6 + 1;
            }
            if ((bVar3) && (-1 < (char)pbVar11[0x8a])) {
              pbVar11[0x8a] = pbVar11[0x8a] & 0x7f | 0x80;
              FUN_801993b0(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                           iVar5,1,0,param_13,param_14,param_15,param_16);
            }
            if (!bVar3) {
              pbVar11[0x8a] = pbVar11[0x8a] & 0x7f;
            }
          }
        }
        else if ((sVar1 == 0x230) && (bVar3)) {
          FUN_8019959c(iVar4,iVar6,param_11,param_12,param_13,param_14,param_15,param_16);
        }
      }
      else {
        FUN_801993b0(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,iVar5,1,0,
                     param_13,param_14,param_15,param_16);
        *pbVar11 = *pbVar11 & 0xfb;
        *pbVar11 = *pbVar11 | 1;
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b6ac
 * EN v1.0 Address: 0x8019B6AC
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x8019AE20
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b6ac(ushort *param_1,short *param_2)
{
  float fVar1;
  short sVar2;
  uint uVar3;
  byte *pbVar4;
  
  FUN_80017a7c((int)param_1,'(');
  pbVar4 = *(byte **)(param_1 + 0x5c);
  sVar2 = *param_2;
  if (sVar2 == 0x54) {
    *(short *)(pbVar4 + 0x82) = param_2[0x24];
    *(short *)(pbVar4 + 0x84) = param_2[0x25];
    *(short *)(pbVar4 + 0x86) = param_2[0x26];
    *(short *)(pbVar4 + 0x88) = param_2[0x27];
    pbVar4[0x8a] = pbVar4[0x8a] & 0x7f;
  }
  else if (sVar2 < 0x54) {
    if (sVar2 == 0x4d) {
      *param_1 = (ushort)*(byte *)((int)param_2 + 0x3d) << 8;
      param_1[1] = (ushort)*(byte *)(param_2 + 0x1f) << 8;
      param_1[2] = 0;
    }
    else if (sVar2 < 0x4d) {
      if (sVar2 == 0x4b) {
        fVar1 = (float)((double)CONCAT44(0x43300000,
                                         (uint)*(byte *)(param_2 + 0x1d) << 1 ^ 0x80000000) -
                       DOUBLE_803e4d68);
        *(float *)(pbVar4 + 4) = fVar1 * fVar1;
        param_1[2] = 0;
        param_1[1] = 0;
        *param_1 = (ushort)*(byte *)((int)param_2 + 0x3d) << 8;
        *(float *)(param_1 + 4) = fVar1 / FLOAT_803e4d90;
      }
      else if (0x4a < sVar2) {
        *(short *)(pbVar4 + 0x82) = param_2[0x24];
        FUN_80199440(param_1,(int)param_2);
      }
    }
  }
  else if (sVar2 == 0x230) {
    *(float *)(pbVar4 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1d) << 1 ^ 0x80000000) -
                DOUBLE_803e4d68);
    *(float *)(pbVar4 + 4) = *(float *)(pbVar4 + 4) * *(float *)(pbVar4 + 4);
  }
  *(short *)(pbVar4 + 0x80) = param_2[0x22];
  uVar3 = FUN_80017690((int)*(short *)(pbVar4 + 0x80));
  if (uVar3 == 1) {
    *pbVar4 = *pbVar4 | 4;
  }
  *pbVar4 = *pbVar4 | 0x40;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b844
 * EN v1.0 Address: 0x8019B844
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019B00C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b844(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8019b86c
 * EN v1.0 Address: 0x8019B86C
 * EN v1.0 Size: 960b
 * EN v1.1 Address: 0x8019B040
 * EN v1.1 Size: 836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019b86c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  bool bVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  undefined4 *puVar5;
  int iVar6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar7;
  undefined8 extraout_f1;
  uint local_18;
  uint local_14;
  uint local_10 [2];
  
  local_18 = 0;
  if (DAT_803dca70 != '\0') {
    DAT_803de78c = (**(code **)(*DAT_803dd71c + 0x40))(8);
    DAT_803dca70 = '\0';
    param_1 = extraout_f1;
  }
  DAT_803de788 = '\0';
LAB_8019b350:
  do {
    while( true ) {
      iVar3 = ObjMsg_Pop(param_9,local_10,&local_14,&local_18);
      if (iVar3 == 0) {
        return;
      }
      if (local_10[0] == 0xf0008) break;
      if ((int)local_10[0] < 0xf0008) {
        if (local_10[0] == 0xf0004) {
          if (*(char *)(local_14 + 0xac) == *(char *)(param_9 + 0xac)) {
            bVar1 = false;
            puVar4 = &DAT_803ad438;
            iVar3 = (int)DAT_803de789;
            if (0 < iVar3) {
              do {
                if (*puVar4 == local_14) {
                  *(short *)(puVar4 + 1) = (short)local_18;
                  bVar1 = true;
                }
                puVar4 = puVar4 + 2;
                iVar3 = iVar3 + -1;
              } while (iVar3 != 0);
            }
            if (!bVar1) {
              iVar3 = (int)DAT_803de789;
              (&DAT_803ad438)[iVar3 * 2] = local_14;
              (&DAT_803ad43e)[iVar3 * 8] = 0;
              DAT_803de789 = DAT_803de789 + '\x01';
              (&DAT_803ad43c)[iVar3 * 4] = (short)local_18;
            }
            ObjMsg_SendToObject(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_14,
                         0xf0003,param_9,0,0xf0004,in_r8,in_r9,in_r10);
          }
        }
        else if ((int)local_10[0] < 0xf0004) goto LAB_8019b31c;
      }
      else {
LAB_8019b31c:
        iVar3 = DAT_803de788 * 0xc;
        *(uint *)(&DAT_803ad4dc + iVar3) = local_14;
        *(uint *)(&DAT_803ad4d8 + iVar3) = local_10[0];
        *(uint *)(&DAT_803ad4e0 + iVar3) = local_18;
        DAT_803de788 = DAT_803de788 + '\x01';
      }
    }
    iVar3 = 0;
    for (puVar4 = &DAT_803ad438; (iVar3 < DAT_803de789 && (*puVar4 != local_14));
        puVar4 = puVar4 + 2) {
      iVar3 = iVar3 + 1;
    }
    DAT_803de789 = DAT_803de789 + -1;
    iVar6 = (int)DAT_803de789;
    puVar5 = &DAT_803ad438 + iVar6 * 2;
    uVar2 = iVar6 - iVar3;
  } while (iVar6 <= iVar3);
  uVar7 = uVar2 >> 3;
  if (uVar7 != 0) {
    do {
      puVar5[-2] = *puVar5;
      *(undefined2 *)(puVar5 + -1) = *(undefined2 *)(puVar5 + 1);
      *(undefined *)((int)puVar5 + -2) = *(undefined *)((int)puVar5 + 6);
      puVar5[-4] = puVar5[-2];
      *(undefined2 *)(puVar5 + -3) = *(undefined2 *)(puVar5 + -1);
      *(undefined *)((int)puVar5 + -10) = *(undefined *)((int)puVar5 + -2);
      puVar5[-6] = puVar5[-4];
      *(undefined2 *)(puVar5 + -5) = *(undefined2 *)(puVar5 + -3);
      *(undefined *)((int)puVar5 + -0x12) = *(undefined *)((int)puVar5 + -10);
      puVar5[-8] = puVar5[-6];
      *(undefined2 *)(puVar5 + -7) = *(undefined2 *)(puVar5 + -5);
      *(undefined *)((int)puVar5 + -0x1a) = *(undefined *)((int)puVar5 + -0x12);
      puVar5[-10] = puVar5[-8];
      *(undefined2 *)(puVar5 + -9) = *(undefined2 *)(puVar5 + -7);
      *(undefined *)((int)puVar5 + -0x22) = *(undefined *)((int)puVar5 + -0x1a);
      puVar5[-0xc] = puVar5[-10];
      *(undefined2 *)(puVar5 + -0xb) = *(undefined2 *)(puVar5 + -9);
      *(undefined *)((int)puVar5 + -0x2a) = *(undefined *)((int)puVar5 + -0x22);
      puVar5[-0xe] = puVar5[-0xc];
      *(undefined2 *)(puVar5 + -0xd) = *(undefined2 *)(puVar5 + -0xb);
      *(undefined *)((int)puVar5 + -0x32) = *(undefined *)((int)puVar5 + -0x2a);
      puVar5[-0x10] = puVar5[-0xe];
      *(undefined2 *)(puVar5 + -0xf) = *(undefined2 *)(puVar5 + -0xd);
      *(undefined *)((int)puVar5 + -0x3a) = *(undefined *)((int)puVar5 + -0x32);
      puVar5 = puVar5 + -0x10;
      uVar7 = uVar7 - 1;
    } while (uVar7 != 0);
    uVar2 = uVar2 & 7;
    if (uVar2 == 0) goto LAB_8019b350;
  }
  do {
    puVar5[-2] = *puVar5;
    *(undefined2 *)(puVar5 + -1) = *(undefined2 *)(puVar5 + 1);
    *(undefined *)((int)puVar5 + -2) = *(undefined *)((int)puVar5 + 6);
    puVar5 = puVar5 + -2;
    uVar2 = uVar2 - 1;
  } while (uVar2 != 0);
  goto LAB_8019b350;
}

/*
 * --INFO--
 *
 * Function: FUN_8019bc2c
 * EN v1.0 Address: 0x8019BC2C
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8019B384
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019bc2c(int param_1)
{
  ObjMsg_AllocQueue(param_1,10);
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_8019A3AC(void) {}
void fn_8019A8A0(void) {}
void fn_8019AA74(void) {}
void fn_8019AA78(void) {}
void cloudprisoncontrol_free(void) {}
void cloudprisoncontrol_hitDetect(void) {}
void cloudprisoncontrol_release(void) {}
