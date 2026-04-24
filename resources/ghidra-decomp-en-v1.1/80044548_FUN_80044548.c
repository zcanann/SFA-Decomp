// Function: FUN_80044548
// Entry: 80044548
// Size: 8444 bytes

/* WARNING: Heritage AFTER dead removal. Example location: r0x803600cc : 0x800465c0 */
/* WARNING: Restarted to delay deadcode elimination for space: ram */

void FUN_80044548(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  char cVar9;
  undefined *puVar8;
  int in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar10;
  undefined2 uVar11;
  undefined8 extraout_f1;
  undefined8 uVar12;
  longlong lVar13;
  char acStack_68 [104];
  
  lVar13 = FUN_8028682c();
  iVar6 = (int)((ulonglong)lVar13 >> 0x20);
  iVar10 = (int)lVar13;
  bVar1 = DAT_803dd912 != 0;
  if (bVar1) {
    DAT_803dd912 = 0;
  }
  iVar3 = (int)*(short *)(&DAT_802cc9d4 + iVar6 * 2);
  uVar12 = extraout_f1;
  if (iVar3 != -1) {
    in_r6 = (int)DAT_803601f2;
    cVar9 = in_r6 != -1;
    if (DAT_80360236 != -1) {
      cVar9 = cVar9 + '\x01';
    }
    if (cVar9 == '\0') {
      iVar2 = 1;
      DAT_803dd912 = 1;
      if (in_r6 == iVar3) {
        iVar2 = 0;
      }
      else if (DAT_80360236 != iVar3) {
        iVar2 = -1;
      }
      if (iVar2 == -1) {
        uVar12 = FUN_80044548(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      bVar1 = true;
    }
  }
  iVar3 = DAT_803dd8f0;
  uVar11 = (undefined2)((ulonglong)lVar13 >> 0x20);
  switch(iVar10) {
  case 0xd:
  case 0x55:
    if (((DAT_8036007c == 0) || (DAT_803601c2 != iVar6)) &&
       ((DAT_8036019c == 0 || (DAT_80360252 != iVar6)))) {
      if (DAT_8035fbdc == iVar6) {
        iVar2 = 0xd;
        DAT_8035fbdc = -1;
      }
      else if (DAT_8035fcfc == iVar6) {
        iVar2 = 0x55;
        DAT_8035fcfc = -1;
      }
      else if (DAT_803601c2 == -1) {
        iVar2 = 0xd;
      }
      else {
        if (DAT_80360252 != -1) break;
        iVar2 = 0x55;
      }
      if ((&DAT_80360048)[iVar2] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar2]);
        (&DAT_80360048)[iVar2] = 0;
      }
      uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)acStack_68,s__s_animcurv_bin_802ccf30,
                            (&PTR_s_animtest_802cc784)[iVar6],in_r6,in_r7,in_r8,in_r9,in_r10);
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar4 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar4 != 0) {
        (&DAT_8035fd08)[iVar2] = piVar5[0xd];
        if ((&DAT_8035fd08)[iVar2] != 0) {
          iVar4 = FUN_80023d8c((&DAT_8035fd08)[iVar2],0x7d7d7d7d);
          (&DAT_80360048)[iVar2] = iVar4;
          FUN_802420b0((&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2]);
          iVar4 = (&DAT_80360048)[iVar2];
          if (iVar4 == 0) {
            if ((&DAT_8035fba8)[iVar10] == -1) {
              FUN_8005387c();
            }
            FUN_802493c8(piVar5);
            FUN_800241f8(DAT_803dd90c,piVar5);
            (&DAT_8035fd08)[iVar2] = 0;
            (&DAT_8035fba8)[iVar2] = iVar6;
          }
          else {
            if (bVar1 || iVar3 != 0) {
              FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                           iVar4,(&DAT_8035fd08)[iVar2],0,in_r7,in_r8,in_r9,in_r10);
              FUN_802493c8(piVar5);
              FUN_800241f8(DAT_803dd90c,piVar5);
              if (((DAT_803dd900 & 0x20000000) == 0) && ((DAT_803dd900 & 0x80000000) == 0)) {
                FUN_80043e64((uint *)&DAT_80346d30,0xe,0x56);
              }
            }
            else {
              if (iVar2 == 0xd) {
                DAT_803dd900 = DAT_803dd900 | 0x10000000;
              }
              else {
                DAT_803dd900 = DAT_803dd900 | 0x40000000;
              }
              FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                           iVar4,(&DAT_8035fd08)[iVar2],0,FUN_80042338,2,in_r9,in_r10);
              *(int **)(&DAT_80346bd0 + iVar2 * 4) = piVar5;
            }
            (&DAT_803601a8)[iVar2] = uVar11;
          }
        }
      }
    }
    break;
  case 0xe:
  case 0x56:
    if (((DAT_80360080 == 0) || (DAT_803601c4 != iVar6)) &&
       ((DAT_803601a0 == 0 || (DAT_80360254 != iVar6)))) {
      if (DAT_803601c4 == -1) {
        iVar10 = 0xe;
      }
      else {
        if (DAT_80360254 != -1) break;
        iVar10 = 0x56;
      }
      if ((&DAT_80360048)[iVar10] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar10]);
        (&DAT_80360048)[iVar10] = 0;
      }
      uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)acStack_68,s__s_animcurv_tab_802ccf40,
                            (&PTR_s_animtest_802cc784)[iVar6],in_r6,in_r7,in_r8,in_r9,in_r10);
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar6 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar6 != 0) {
        (&DAT_8035fd08)[iVar10] = piVar5[0xd];
        if ((&DAT_8035fd08)[iVar10] != 0) {
          iVar6 = FUN_80023d8c((&DAT_8035fd08)[iVar10],0x7d7d7d7d);
          (&DAT_80360048)[iVar10] = iVar6;
          FUN_802420b0((&DAT_80360048)[iVar10],(&DAT_8035fd08)[iVar10]);
          if (bVar1 || iVar3 != 0) {
            FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                         (&DAT_80360048)[iVar10],(&DAT_8035fd08)[iVar10],0,in_r7,in_r8,in_r9,in_r10)
            ;
            FUN_802493c8(piVar5);
            FUN_800241f8(DAT_803dd90c,piVar5);
            if (((DAT_803dd900 & 0x20000000) == 0) && ((DAT_803dd900 & 0x80000000) == 0)) {
              FUN_80043e64((uint *)&DAT_80346d30,0xe,0x56);
            }
          }
          else {
            if (iVar10 == 0xe) {
              DAT_803dd900 = DAT_803dd900 | 0x20000000;
            }
            else {
              DAT_803dd900 = DAT_803dd900 | 0x80000000;
            }
            FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                         (&DAT_80360048)[iVar10],(&DAT_8035fd08)[iVar10],0,FUN_800423f0,2,in_r9,
                         in_r10);
            *(int **)(&DAT_80346bd0 + iVar10 * 4) = piVar5;
          }
          (&DAT_803601a8)[iVar10] = uVar11;
        }
      }
    }
    break;
  default:
    break;
  case 0x1a:
  case 0x53:
    if (((DAT_803600b0 == 0) || (DAT_803601dc != iVar6)) &&
       ((DAT_80360194 == 0 || (DAT_8036024e != iVar6)))) {
      if (DAT_803601dc == -1) {
        iVar10 = 0x1a;
      }
      else {
        if (DAT_8036024e != -1) break;
        iVar10 = 0x53;
      }
      if ((&DAT_80360048)[iVar10] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar10]);
        (&DAT_80360048)[iVar10] = 0;
      }
      uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)acStack_68,s__s_voxmap_tab_802ccf74,
                            (&PTR_s_animtest_802cc784)[iVar6],in_r6,in_r7,in_r8,in_r9,in_r10);
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar6 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar6 != 0) {
        (&DAT_8035fd08)[iVar10] = piVar5[0xd];
        if ((&DAT_8035fd08)[iVar10] == 0) {
          FUN_800241f8(DAT_803dd90c,piVar5);
        }
        else {
          iVar6 = FUN_80023d8c((&DAT_8035fd08)[iVar10],0x7d7d7d7d);
          (&DAT_80360048)[iVar10] = iVar6;
          FUN_802420b0((&DAT_80360048)[iVar10],(&DAT_8035fd08)[iVar10]);
          if (bVar1 || iVar3 != 0) {
            FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                         (&DAT_80360048)[iVar10],(&DAT_8035fd08)[iVar10],0,in_r7,in_r8,in_r9,in_r10)
            ;
            FUN_802493c8(piVar5);
            FUN_800241f8(DAT_803dd90c,piVar5);
            if (((DAT_803dd900 & 0x2000000) == 0) && ((DAT_803dd900 & 0x8000000) == 0)) {
              FUN_80043e64((uint *)&DAT_8034ec70,0x1a,0x53);
            }
          }
          else {
            if (iVar10 == 0x1a) {
              DAT_803dd900 = DAT_803dd900 | 0x2000000;
            }
            else {
              DAT_803dd900 = DAT_803dd900 | 0x8000000;
            }
            *(int **)(&DAT_80346bd0 + iVar10 * 4) = piVar5;
            FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                         (&DAT_80360048)[iVar10],(&DAT_8035fd08)[iVar10],0,FUN_80042560,2,in_r9,
                         in_r10);
          }
          (&DAT_803601a8)[iVar10] = uVar11;
        }
      }
    }
    break;
  case 0x1b:
  case 0x54:
    if (((DAT_803600b4 == 0) || (DAT_803601de != iVar6)) &&
       ((DAT_80360198 == 0 || (DAT_80360250 != iVar6)))) {
      if (DAT_803601de == -1) {
        iVar10 = 0x1b;
      }
      else {
        if (DAT_80360250 != -1) break;
        iVar10 = 0x54;
      }
      if ((&DAT_80360048)[iVar10] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar10]);
        (&DAT_80360048)[iVar10] = 0;
      }
      puVar8 = (&PTR_s_animtest_802cc784)[iVar6];
      uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)acStack_68,s__s_voxmap_bin_802ccf50,puVar8,in_r6,in_r7,in_r8,in_r9,
                            in_r10);
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar6 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar6 == 0) {
        uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              (int)acStack_68,s_warlock_voxmap_bin_802ccf60,puVar8,in_r6,in_r7,in_r8
                              ,in_r9,in_r10);
        iVar6 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             acStack_68,(int)piVar5);
        if (iVar6 == 0) break;
      }
      (&DAT_8035fd08)[iVar10] = piVar5[0xd];
      if ((&DAT_8035fd08)[iVar10] == 0) {
        uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              (int)acStack_68,s_warlock_voxmap_bin_802ccf60,puVar8,in_r6,in_r7,in_r8
                              ,in_r9,in_r10);
        iVar6 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             acStack_68,(int)piVar5);
        if (iVar6 == 0) break;
        (&DAT_8035fd08)[iVar10] = piVar5[0xd];
      }
      iVar6 = FUN_80023d8c((&DAT_8035fd08)[iVar10],0x7d7d7d7d);
      (&DAT_80360048)[iVar10] = iVar6;
      FUN_802420b0((&DAT_80360048)[iVar10],(&DAT_8035fd08)[iVar10]);
      if (bVar1 || iVar3 != 0) {
        FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                     (&DAT_80360048)[iVar10],(&DAT_8035fd08)[iVar10],0,in_r7,in_r8,in_r9,in_r10);
        FUN_802493c8(piVar5);
        FUN_800241f8(DAT_803dd90c,piVar5);
        if (((DAT_803dd900 & 0x2000000) == 0) && ((DAT_803dd900 & 0x8000000) == 0)) {
          FUN_80043e64((uint *)&DAT_8034ec70,0x1a,0x53);
        }
      }
      else {
        if (iVar10 == 0x1b) {
          DAT_803dd900 = DAT_803dd900 | 0x1000000;
        }
        else {
          DAT_803dd900 = DAT_803dd900 | 0x4000000;
        }
        *(int **)(&DAT_80346bd0 + iVar10 * 4) = piVar5;
        FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                     (&DAT_80360048)[iVar10],(&DAT_8035fd08)[iVar10],0,FUN_800424a8,2,in_r9,in_r10);
      }
      (&DAT_803601a8)[iVar10] = uVar11;
    }
    break;
  case 0x20:
  case 0x4b:
    if (((DAT_803600c8 == 0) || (DAT_803601e8 != iVar6)) &&
       ((DAT_80360174 == 0 || (DAT_8036023e != iVar6)))) {
      if (DAT_8035fc28 == iVar6) {
        iVar2 = 0x20;
        DAT_8035fc28 = -1;
      }
      else if (DAT_8035fcd4 == iVar6) {
        iVar2 = 0x4b;
        DAT_8035fcd4 = -1;
      }
      else if (DAT_803601e8 == -1) {
        iVar2 = 0x20;
      }
      else {
        if (DAT_8036023e != -1) break;
        iVar2 = 0x4b;
      }
      if ((&DAT_80360048)[iVar2] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar2]);
        (&DAT_80360048)[iVar2] = 0;
      }
      uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)acStack_68,&DAT_803dc218,(&PTR_s_animtest_802cc784)[iVar6],
                            (&PTR_s_AUDIO_tab_802cbecc)[iVar10],in_r7,in_r8,in_r9,in_r10);
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar4 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar4 != 0) {
        (&DAT_8035fd08)[iVar2] = piVar5[0xd];
        iVar4 = FUN_80023d8c((&DAT_8035fd08)[iVar2] + 0x20,0x7d7d7d7d);
        (&DAT_80360048)[iVar2] = iVar4;
        FUN_802420b0((&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2]);
        iVar4 = (&DAT_80360048)[iVar2];
        if (iVar4 == 0) {
          if ((&DAT_8035fba8)[iVar10] == -1) {
            FUN_8005387c();
          }
          FUN_802493c8(piVar5);
          FUN_800241f8(DAT_803dd90c,piVar5);
          (&DAT_8035fd08)[iVar2] = 0;
          (&DAT_8035fba8)[iVar2] = iVar6;
        }
        else {
          if (bVar1 || iVar3 != 0) {
            FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,iVar4
                         ,(&DAT_8035fd08)[iVar2],0,in_r7,in_r8,in_r9,in_r10);
            FUN_802493c8(piVar5);
            FUN_800241f8(DAT_803dd90c,piVar5);
            if (((DAT_803dd900 & 0x4000) == 0) && ((DAT_803dd900 & 0x8000) == 0)) {
              FUN_80043e64((uint *)&DAT_80352c70,0x21,0x4c);
            }
          }
          else {
            if (iVar2 == 0x20) {
              DAT_803dd900 = DAT_803dd900 | 0x1000;
            }
            else {
              DAT_803dd900 = DAT_803dd900 | 0x2000;
            }
            *(int **)(&DAT_80346bd0 + iVar2 * 4) = piVar5;
            FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,iVar4
                         ,(&DAT_8035fd08)[iVar2],0,FUN_80042984,2,in_r9,in_r10);
          }
          (&DAT_803601a8)[iVar2] = uVar11;
        }
      }
    }
    break;
  case 0x21:
  case 0x4c:
    if (((DAT_803600cc == 0) || (DAT_803601ea != iVar6)) &&
       ((DAT_80360178 == 0 || (DAT_80360240 != iVar6)))) {
      if (DAT_803601ea == -1) {
        iVar2 = 0x21;
      }
      else {
        if (DAT_80360240 != -1) break;
        iVar2 = 0x4c;
      }
      if ((&DAT_80360048)[iVar2] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar2]);
        (&DAT_80360048)[iVar2] = 0;
      }
      uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)acStack_68,&DAT_803dc218,(&PTR_s_animtest_802cc784)[iVar6],
                            (&PTR_s_AUDIO_tab_802cbecc)[iVar10],in_r7,in_r8,in_r9,in_r10);
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar6 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar6 != 0) {
        (&DAT_8035fd08)[iVar2] = piVar5[0xd];
        iVar6 = FUN_80023d8c((&DAT_8035fd08)[iVar2],0x7d7d7d7d);
        (&DAT_80360048)[iVar2] = iVar6;
        FUN_802420b0((&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2]);
        if (bVar1 || iVar3 != 0) {
          FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                       (&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2],0,in_r7,in_r8,in_r9,in_r10);
          FUN_802493c8(piVar5);
          FUN_800241f8(DAT_803dd90c,piVar5);
          if (((DAT_803dd900 & 0x4000) == 0) && ((DAT_803dd900 & 0x8000) == 0)) {
            FUN_80043e64((uint *)&DAT_80352c70,0x21,0x4c);
          }
        }
        else {
          *(int **)(&DAT_80346bd0 + iVar2 * 4) = piVar5;
          if (iVar2 == 0x21) {
            DAT_803dd900 = DAT_803dd900 | 0x4000;
            FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                         DAT_803600cc,DAT_8035fd8c,0,FUN_800428b8,2,in_r9,in_r10);
          }
          else {
            DAT_803dd900 = DAT_803dd900 | 0x8000;
            FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                         (&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2],0,FUN_800427ec,2,in_r9,in_r10
                        );
          }
        }
        (&DAT_803601a8)[iVar2] = uVar11;
      }
    }
    break;
  case 0x23:
  case 0x4d:
    if (((DAT_803600d4 == 0) || (DAT_803601ee != iVar6)) &&
       ((DAT_8036017c == 0 || (DAT_80360242 != iVar6)))) {
      if (DAT_8035fc34 == iVar6) {
        iVar2 = 0x23;
        DAT_8035fc34 = -1;
      }
      else if (DAT_8035fcdc == iVar6) {
        iVar2 = 0x4d;
        DAT_8035fcdc = -1;
      }
      else if (DAT_803601ee == -1) {
        iVar2 = 0x23;
      }
      else {
        if (DAT_80360242 != -1) break;
        iVar2 = 0x4d;
      }
      if ((&DAT_80360048)[iVar2] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar2]);
        (&DAT_80360048)[iVar2] = 0;
      }
      uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)acStack_68,&DAT_803dc218,(&PTR_s_animtest_802cc784)[iVar6],
                            (&PTR_s_AUDIO_tab_802cbecc)[iVar10],in_r7,in_r8,in_r9,in_r10);
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar4 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar4 != 0) {
        (&DAT_8035fd08)[iVar2] = piVar5[0xd];
        iVar4 = FUN_80023d8c((&DAT_8035fd08)[iVar2] + 0x20,0x7d7d7d7d);
        (&DAT_80360048)[iVar2] = iVar4;
        FUN_802420b0((&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2]);
        iVar4 = (&DAT_80360048)[iVar2];
        if (iVar4 == 0) {
          if ((&DAT_8035fba8)[iVar10] == -1) {
            FUN_8005387c();
          }
          FUN_802493c8(piVar5);
          FUN_800241f8(DAT_803dd90c,piVar5);
          (&DAT_8035fd08)[iVar2] = 0;
          (&DAT_8035fba8)[iVar2] = iVar6;
        }
        else {
          if (bVar1 || iVar3 != 0) {
            FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,iVar4
                         ,(&DAT_8035fd08)[iVar2],0,in_r7,in_r8,in_r9,in_r10);
            FUN_802493c8(piVar5);
            FUN_800241f8(DAT_803dd90c,piVar5);
            if (((DAT_803dd900 & 0x400) == 0) && ((DAT_803dd900 & 0x800) == 0)) {
              FUN_80043e64((uint *)&DAT_80356c70,0x24,0x4e);
            }
          }
          else {
            if (iVar2 == 0x23) {
              DAT_803dd900 = DAT_803dd900 | 0x100;
            }
            else {
              DAT_803dd900 = DAT_803dd900 | 0x200;
            }
            *(int **)(&DAT_80346bd0 + iVar2 * 4) = piVar5;
            FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,iVar4
                         ,(&DAT_8035fd08)[iVar2],0,FUN_80042bd4,2,in_r9,in_r10);
          }
          (&DAT_803601a8)[iVar2] = uVar11;
        }
      }
    }
    break;
  case 0x24:
  case 0x4e:
    if (((DAT_803600d8 == 0) || (DAT_803601f0 != iVar6)) &&
       ((DAT_80360180 == 0 || (DAT_80360244 != iVar6)))) {
      if (DAT_803601f0 == -1) {
        iVar2 = 0x24;
      }
      else {
        if (DAT_80360244 != -1) break;
        iVar2 = 0x4e;
      }
      if ((&DAT_80360048)[iVar2] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar2]);
        (&DAT_80360048)[iVar2] = 0;
      }
      uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)acStack_68,&DAT_803dc218,(&PTR_s_animtest_802cc784)[iVar6],
                            (&PTR_s_AUDIO_tab_802cbecc)[iVar10],in_r7,in_r8,in_r9,in_r10);
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar6 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar6 != 0) {
        (&DAT_8035fd08)[iVar2] = piVar5[0xd];
        iVar6 = FUN_80023d8c((&DAT_8035fd08)[iVar2] + 0x20,0x7d7d7d7d);
        (&DAT_80360048)[iVar2] = iVar6;
        FUN_802420b0((&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2]);
        if (bVar1 || iVar3 != 0) {
          FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                       (&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2],0,in_r7,in_r8,in_r9,in_r10);
          FUN_802493c8(piVar5);
          FUN_800241f8(DAT_803dd90c,piVar5);
          if (((DAT_803dd900 & 0x400) == 0) && ((DAT_803dd900 & 0x800) == 0)) {
            FUN_80043e64((uint *)&DAT_80356c70,0x24,0x4e);
          }
        }
        else if (iVar2 == 0x24) {
          DAT_803dd900 = DAT_803dd900 | 0x400;
          *(int **)(&DAT_80346bd0 + iVar2 * 4) = piVar5;
          FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                       DAT_803600d8,DAT_8035fd98,0,FUN_80042b08,2,in_r9,in_r10);
        }
        else {
          DAT_803dd900 = DAT_803dd900 | 0x800;
          *(int **)(&DAT_80346bd0 + iVar2 * 4) = piVar5;
          FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                       (&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2],0,FUN_80042a3c,2,in_r9,in_r10);
        }
        (&DAT_803601a8)[iVar2] = uVar11;
      }
    }
    break;
  case 0x25:
  case 0x47:
    if (((DAT_803600dc == 0) || (DAT_803601f2 != iVar6)) &&
       ((DAT_80360164 == 0 || (DAT_80360236 != iVar6)))) {
      if (DAT_8035fc3c == iVar6) {
        iVar2 = 0x25;
        DAT_8035fc3c = -1;
      }
      else if (DAT_8035fcc4 == iVar6) {
        iVar2 = 0x47;
        DAT_8035fcc4 = -1;
      }
      else if (DAT_803601f2 == -1) {
        iVar2 = 0x25;
      }
      else {
        if (DAT_80360236 != -1) break;
        iVar2 = 0x47;
      }
      if ((&DAT_80360048)[iVar2] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar2]);
        (&DAT_80360048)[iVar2] = 0;
      }
      if (lVar13 < 0x500000000) {
        uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              (int)acStack_68,s__s_mod_d_zlb_bin_802ccf84,
                              (&PTR_s_animtest_802cc784)[iVar6],iVar6,in_r7,in_r8,in_r9,in_r10);
      }
      else {
        uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              (int)acStack_68,s__s_mod_d_zlb_bin_802ccf84,
                              (&PTR_s_animtest_802cc784)[iVar6],iVar6 + 1,in_r7,in_r8,in_r9,in_r10);
      }
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar4 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar4 != 0) {
        (&DAT_8035fd08)[iVar2] = piVar5[0xd];
        iVar4 = FUN_80023d8c((&DAT_8035fd08)[iVar2],0x7d7d7d7d);
        (&DAT_80360048)[iVar2] = iVar4;
        FUN_802420b0((&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2]);
        iVar4 = (&DAT_80360048)[iVar2];
        if (iVar4 == 0) {
          if ((&DAT_8035fba8)[iVar10] == -1) {
            FUN_8005387c();
          }
          FUN_802493c8(piVar5);
          FUN_800241f8(DAT_803dd90c,piVar5);
          (&DAT_8035fd08)[iVar2] = 0;
          (&DAT_8035fba8)[iVar2] = iVar6;
        }
        else {
          if (bVar1 || iVar3 != 0) {
            FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,iVar4
                         ,(&DAT_8035fd08)[iVar2],0,in_r7,in_r8,in_r9,in_r10);
            FUN_802493c8(piVar5);
            FUN_800241f8(DAT_803dd90c,piVar5);
            if (((DAT_803dd900 & 0x20000) == 0) && ((DAT_803dd900 & 0x80000) == 0)) {
              FUN_80043e64((uint *)&DAT_80350c70,0x26,0x48);
            }
          }
          else {
            if (iVar2 == 0x25) {
              DAT_803dd900 = DAT_803dd900 | 0x10000;
            }
            else {
              DAT_803dd900 = DAT_803dd900 | 0x40000;
            }
            *(int **)(&DAT_80346bd0 + iVar2 * 4) = piVar5;
            FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,iVar4
                         ,(&DAT_8035fd08)[iVar2],0,FUN_80042734,2,in_r9,in_r10);
          }
          (&DAT_803601a8)[iVar2] = uVar11;
        }
      }
    }
    break;
  case 0x26:
  case 0x48:
    if (((DAT_803600e0 == 0) || (DAT_803601f4 != iVar6)) &&
       ((DAT_80360168 == 0 || (DAT_80360238 != iVar6)))) {
      if (DAT_803601f4 == -1) {
        iVar10 = 0x26;
      }
      else {
        if (DAT_80360238 != -1) break;
        iVar10 = 0x48;
      }
      if ((&DAT_80360048)[iVar10] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar10]);
        (&DAT_80360048)[iVar10] = 0;
      }
      iVar2 = 0;
      piVar5 = &DAT_802cc8a8;
      iVar4 = 0xf;
      do {
        iVar7 = iVar2;
        if ((((iVar6 == *piVar5) || (iVar7 = iVar2 + 1, iVar6 == piVar5[1])) ||
            (iVar7 = iVar2 + 2, iVar6 == piVar5[2])) ||
           ((iVar7 = iVar2 + 3, iVar6 == piVar5[3] || (iVar7 = iVar2 + 4, iVar6 == piVar5[4]))))
        break;
        piVar5 = piVar5 + 5;
        iVar2 = iVar2 + 5;
        iVar4 = iVar4 + -1;
        iVar7 = iVar2;
      } while (iVar4 != 0);
      uVar12 = FUN_800484a4(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,iVar7,0
                            ,in_r6,in_r7,in_r8,in_r9,in_r10);
      if (lVar13 < 0x500000000) {
        uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              (int)acStack_68,s__s_mod_d_tab_802ccf98,
                              (&PTR_s_animtest_802cc784)[iVar6],iVar6,in_r7,in_r8,in_r9,in_r10);
      }
      else {
        uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              (int)acStack_68,s__s_mod_d_tab_802ccf98,
                              (&PTR_s_animtest_802cc784)[iVar6],iVar6 + 1,in_r7,in_r8,in_r9,in_r10);
      }
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar6 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar6 != 0) {
        (&DAT_8035fd08)[iVar10] = piVar5[0xd];
        iVar6 = FUN_80023d8c((&DAT_8035fd08)[iVar10],0x7d7d7d7d);
        (&DAT_80360048)[iVar10] = iVar6;
        FUN_802420b0((&DAT_80360048)[iVar10],(&DAT_8035fd08)[iVar10]);
        if (bVar1 || iVar3 != 0) {
          FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                       (&DAT_80360048)[iVar10],(&DAT_8035fd08)[iVar10],0,in_r7,in_r8,in_r9,in_r10);
          FUN_802493c8(piVar5);
          FUN_800241f8(DAT_803dd90c,piVar5);
          if (((DAT_803dd900 & 0x20000) == 0) && ((DAT_803dd900 & 0x80000) == 0)) {
            FUN_80043e64((uint *)&DAT_80350c70,0x26,0x48);
          }
        }
        else {
          if (iVar10 == 0x26) {
            DAT_803dd900 = DAT_803dd900 | 0x20000;
          }
          else {
            DAT_803dd900 = DAT_803dd900 | 0x80000;
          }
          *(int **)(&DAT_80346bd0 + iVar10 * 4) = piVar5;
          FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                       (&DAT_80360048)[iVar10],(&DAT_8035fd08)[iVar10],0,FUN_80042618,2,in_r9,in_r10
                      );
        }
        (&DAT_803601a8)[iVar10] = uVar11;
      }
    }
    break;
  case 0x2a:
  case 0x45:
    if (((DAT_803600f0 == 0) || (DAT_803601fc != iVar6)) &&
       ((DAT_8036015c == 0 || (DAT_80360232 != iVar6)))) {
      if (DAT_803601fc == -1) {
        iVar2 = 0x2a;
      }
      else {
        if (DAT_80360232 != -1) break;
        iVar2 = 0x45;
      }
      if ((&DAT_80360048)[iVar2] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar2]);
        (&DAT_80360048)[iVar2] = 0;
      }
      uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)acStack_68,&DAT_803dc218,(&PTR_s_animtest_802cc784)[iVar6],
                            (&PTR_s_AUDIO_tab_802cbecc)[iVar10],in_r7,in_r8,in_r9,in_r10);
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar6 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar6 != 0) {
        (&DAT_8035fd08)[iVar2] = piVar5[0xd];
        iVar6 = FUN_80023d8c((&DAT_8035fd08)[iVar2],0x7d7d7d7d);
        (&DAT_80360048)[iVar2] = iVar6;
        FUN_802420b0((&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2]);
        if (bVar1 || iVar3 != 0) {
          FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                       (&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2],0,in_r7,in_r8,in_r9,in_r10);
          FUN_802493c8(piVar5);
          FUN_800241f8(DAT_803dd90c,piVar5);
          if (((DAT_803dd900 & 4) == 0) && ((DAT_803dd900 & 8) == 0)) {
            FUN_80043e64((uint *)&DAT_8035db50,0x2a,0x45);
          }
        }
        else {
          if (iVar2 == 0x2a) {
            DAT_803dd900 = DAT_803dd900 | 4;
          }
          else {
            DAT_803dd900 = DAT_803dd900 | 8;
          }
          *(int **)(&DAT_80346bd0 + iVar2 * 4) = piVar5;
          FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                       (&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2],0,FUN_80042eb4,2,in_r9,in_r10);
        }
        (&DAT_803601a8)[iVar2] = uVar11;
      }
    }
    break;
  case 0x2b:
  case 0x46:
    if (((DAT_803600f4 == 0) || (DAT_803601fe != iVar6)) &&
       ((DAT_80360160 == 0 || (DAT_80360234 != iVar6)))) {
      if (DAT_8035fc54 == iVar6) {
        iVar2 = 0x2b;
        DAT_8035fc54 = -1;
      }
      else if (DAT_8035fcc0 == iVar6) {
        iVar2 = 0x46;
        DAT_8035fcc0 = -1;
      }
      else if (DAT_803601fe == -1) {
        iVar2 = 0x2b;
      }
      else {
        if (DAT_80360234 != -1) break;
        iVar2 = 0x46;
      }
      if ((&DAT_80360048)[iVar2] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar2]);
        (&DAT_80360048)[iVar2] = 0;
      }
      uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)acStack_68,&DAT_803dc218,(&PTR_s_animtest_802cc784)[iVar6],
                            (&PTR_s_AUDIO_tab_802cbecc)[iVar10],in_r7,in_r8,in_r9,in_r10);
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar4 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar4 != 0) {
        (&DAT_8035fd08)[iVar2] = piVar5[0xd];
        iVar4 = FUN_80023d8c((&DAT_8035fd08)[iVar2],0x7d7d7d7d);
        (&DAT_80360048)[iVar2] = iVar4;
        FUN_802420b0((&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2]);
        iVar4 = (&DAT_80360048)[iVar2];
        if (iVar4 == 0) {
          if ((&DAT_8035fba8)[iVar10] == -1) {
            FUN_8005387c();
          }
          FUN_802493c8(piVar5);
          FUN_800241f8(DAT_803dd90c,piVar5);
          (&DAT_8035fd08)[iVar2] = 0;
          (&DAT_8035fba8)[iVar2] = iVar6;
        }
        else {
          if (bVar1 || iVar3 != 0) {
            FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,iVar4
                         ,(&DAT_8035fd08)[iVar2],0,in_r7,in_r8,in_r9,in_r10);
            FUN_802493c8(piVar5);
            FUN_800241f8(DAT_803dd90c,piVar5);
            if (((DAT_803dd900 & 4) == 0) && ((DAT_803dd900 & 8) == 0)) {
              FUN_80043e64((uint *)&DAT_8035db50,0x2a,0x45);
            }
            DAT_803dd8fc = DAT_803dd8fc + 1;
          }
          else {
            DAT_803dd8fc = DAT_803dd8fc + 1;
            if (iVar2 == 0x2b) {
              DAT_803dd900 = DAT_803dd900 | 1;
            }
            else {
              DAT_803dd900 = DAT_803dd900 | 2;
            }
            *(int **)(&DAT_80346bd0 + iVar2 * 4) = piVar5;
            FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,iVar4
                         ,(&DAT_8035fd08)[iVar2],0,FUN_80042d44,2,in_r9,in_r10);
          }
          (&DAT_803601a8)[iVar2] = uVar11;
        }
      }
    }
    break;
  case 0x2f:
  case 0x49:
    if (((DAT_80360104 == 0) || (DAT_80360206 != iVar6)) &&
       ((DAT_8036016c == 0 || (DAT_8036023a != iVar6)))) {
      if (DAT_80360206 == -1) {
        iVar2 = 0x2f;
      }
      else {
        if (DAT_8036023a != -1) break;
        iVar2 = 0x49;
      }
      if ((&DAT_80360048)[iVar2] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar2]);
        (&DAT_80360048)[iVar2] = 0;
      }
      uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)acStack_68,&DAT_803dc218,(&PTR_s_animtest_802cc784)[iVar6],
                            (&PTR_s_AUDIO_tab_802cbecc)[iVar10],in_r7,in_r8,in_r9,in_r10);
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar6 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar6 != 0) {
        (&DAT_8035fd08)[iVar2] = piVar5[0xd];
        iVar6 = FUN_80023d8c((&DAT_8035fd08)[iVar2],0x7d7d7d7d);
        (&DAT_80360048)[iVar2] = iVar6;
        FUN_802420b0((&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2]);
        if (bVar1 || iVar3 != 0) {
          FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                       (&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2],0,in_r7,in_r8,in_r9,in_r10);
          FUN_802493c8(piVar5);
          FUN_800241f8(DAT_803dd90c,piVar5);
          if (((DAT_803dd900 & 0x40) == 0) && ((DAT_803dd900 & 0x80) == 0)) {
            FUN_80043e64((uint *)&DAT_8035ac70,0x2f,0x49);
          }
        }
        else {
          if (iVar2 == 0x2f) {
            DAT_803dd900 = DAT_803dd900 | 0x40;
          }
          else {
            DAT_803dd900 = DAT_803dd900 | 0x80;
          }
          *(int **)(&DAT_80346bd0 + iVar2 * 4) = piVar5;
          FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,
                       (&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2],0,FUN_80042dfc,2,in_r9,in_r10);
        }
        (&DAT_803601a8)[iVar2] = uVar11;
      }
    }
    break;
  case 0x30:
  case 0x4a:
    if (((DAT_80360108 == 0) || (DAT_80360208 != iVar6)) &&
       ((DAT_80360170 == 0 || (DAT_8036023c != iVar6)))) {
      if (DAT_8035fc68 == iVar6) {
        iVar2 = 0x30;
        DAT_8035fc68 = -1;
      }
      else if (DAT_8035fcd0 == iVar6) {
        iVar2 = 0x4a;
        DAT_8035fcd0 = -1;
      }
      else if (DAT_80360208 == -1) {
        iVar2 = 0x30;
      }
      else {
        if (DAT_8036023c != -1) break;
        iVar2 = 0x4a;
      }
      if ((&DAT_80360048)[iVar2] != 0) {
        uVar12 = FUN_800238c4((&DAT_80360048)[iVar2]);
        (&DAT_80360048)[iVar2] = 0;
      }
      uVar12 = FUN_8028fde8(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)acStack_68,&DAT_803dc218,(&PTR_s_animtest_802cc784)[iVar6],
                            (&PTR_s_AUDIO_tab_802cbecc)[iVar10],in_r7,in_r8,in_r9,in_r10);
      piVar5 = FUN_8002419c(DAT_803dd90c);
      iVar4 = FUN_80249300(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_68
                           ,(int)piVar5);
      if (iVar4 != 0) {
        (&DAT_8035fd08)[iVar2] = piVar5[0xd];
        iVar4 = FUN_80023d8c((&DAT_8035fd08)[iVar2],0x7d7d7d7d);
        (&DAT_80360048)[iVar2] = iVar4;
        FUN_802420b0((&DAT_80360048)[iVar2],(&DAT_8035fd08)[iVar2]);
        iVar4 = (&DAT_80360048)[iVar2];
        if (iVar4 == 0) {
          if ((&DAT_8035fba8)[iVar10] == -1) {
            FUN_8005387c();
          }
          FUN_802493c8(piVar5);
          FUN_800241f8(DAT_803dd90c,piVar5);
          (&DAT_8035fd08)[iVar2] = 0;
          (&DAT_8035fba8)[iVar2] = iVar6;
        }
        else {
          if (bVar1 || iVar3 != 0) {
            FUN_80015888(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,iVar4
                         ,(&DAT_8035fd08)[iVar2],0,in_r7,in_r8,in_r9,in_r10);
            FUN_802493c8(piVar5);
            FUN_800241f8(DAT_803dd90c,piVar5);
            if (((DAT_803dd900 & 0x40) == 0) && ((DAT_803dd900 & 0x80) == 0)) {
              FUN_80043e64((uint *)&DAT_8035ac70,0x2f,0x49);
            }
          }
          else {
            if (iVar2 == 0x30) {
              DAT_803dd900 = DAT_803dd900 | 0x10;
            }
            else {
              DAT_803dd900 = DAT_803dd900 | 0x20;
            }
            *(int **)(&DAT_80346bd0 + iVar2 * 4) = piVar5;
            FUN_80249610(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar5,iVar4
                         ,(&DAT_8035fd08)[iVar2],0,FUN_80042c8c,2,in_r9,in_r10);
          }
          (&DAT_803601a8)[iVar2] = uVar11;
        }
      }
    }
  }
  FUN_80286878();
  return;
}

