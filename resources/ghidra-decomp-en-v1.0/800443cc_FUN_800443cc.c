// Function: FUN_800443cc
// Entry: 800443cc
// Size: 8444 bytes

void FUN_800443cc(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  int *piVar7;
  char cVar8;
  int iVar9;
  uint uVar10;
  undefined2 uVar11;
  longlong lVar12;
  undefined auStack104 [104];
  
  lVar12 = FUN_802860c8();
  iVar5 = (int)((ulonglong)lVar12 >> 0x20);
  iVar9 = (int)lVar12;
  bVar1 = DAT_803dcc92 != 0;
  if (bVar1) {
    DAT_803dcc92 = 0;
  }
  uVar10 = (uint)bVar1;
  iVar3 = (int)*(short *)(&DAT_802cbdfc + iVar5 * 2);
  if (iVar3 != -1) {
    cVar8 = DAT_8035f592 != -1;
    if (DAT_8035f5d6 != -1) {
      cVar8 = cVar8 + '\x01';
    }
    if (cVar8 == '\0') {
      iVar2 = 1;
      DAT_803dcc92 = 1;
      if (DAT_8035f592 == iVar3) {
        iVar2 = 0;
      }
      else if (DAT_8035f5d6 != iVar3) {
        iVar2 = -1;
      }
      if (iVar2 == -1) {
        FUN_800443cc(iVar3,iVar9);
      }
      uVar10 = 1;
    }
  }
  uVar10 = uVar10 | DAT_803dcc70;
  uVar11 = (undefined2)((ulonglong)lVar12 >> 0x20);
  switch(iVar9) {
  case 0xd:
  case 0x55:
    if (((DAT_8035f41c == 0) || (iVar3 = DAT_8035f41c, DAT_8035f562 != iVar5)) &&
       ((DAT_8035f53c == 0 || (iVar3 = DAT_8035f53c, DAT_8035f5f2 != iVar5)))) {
      if (DAT_8035ef7c == iVar5) {
        iVar3 = 0xd;
        DAT_8035ef7c = -1;
      }
      else if (DAT_8035f09c == iVar5) {
        iVar3 = 0x55;
        DAT_8035f09c = -1;
      }
      else if (DAT_8035f562 == -1) {
        iVar3 = 0xd;
      }
      else {
        if (DAT_8035f5f2 != -1) {
          iVar3 = 0;
          break;
        }
        iVar3 = 0x55;
      }
      if ((&DAT_8035f3e8)[iVar3] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar3] = 0;
      }
      FUN_8028f688(auStack104,s__s_animcurv_bin_802cc378,(&PTR_s_animtest_802cbbac)[iVar5]);
      iVar2 = FUN_800240d8(DAT_803dcc8c);
      iVar4 = FUN_80248b9c(auStack104,iVar2);
      if (iVar4 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar3] = *(undefined4 *)(iVar2 + 0x34);
        if ((&DAT_8035f0a8)[iVar3] == 0) {
          iVar3 = 0;
        }
        else {
          uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar3],0x7d7d7d7d,0);
          (&DAT_8035f3e8)[iVar3] = uVar6;
          FUN_802419b8((&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3]);
          iVar4 = (&DAT_8035f3e8)[iVar3];
          if (iVar4 == 0) {
            if ((&DAT_8035ef48)[iVar9] == -1) {
              FUN_80053700(1);
            }
            FUN_80248c64(iVar2);
            FUN_80024134(DAT_803dcc8c,iVar2);
            (&DAT_8035f0a8)[iVar3] = 0;
            (&DAT_8035ef48)[iVar3] = iVar5;
            iVar3 = 0;
          }
          else {
            if (uVar10 == 0) {
              if (iVar3 == 0xd) {
                DAT_803dcc80 = DAT_803dcc80 | 0x10000000;
              }
              else {
                DAT_803dcc80 = DAT_803dcc80 | 0x40000000;
              }
              FUN_80248eac(iVar2,iVar4,(&DAT_8035f0a8)[iVar3],0,FUN_80042240,2);
              *(int *)(&DAT_80345f70 + iVar3 * 4) = iVar2;
            }
            else {
              FUN_80015850(iVar2,iVar4,(&DAT_8035f0a8)[iVar3],0);
              FUN_80248c64(iVar2);
              FUN_80024134(DAT_803dcc8c,iVar2);
              if (((DAT_803dcc80 & 0x20000000) == 0) && ((DAT_803dcc80 & 0x80000000) == 0)) {
                FUN_80043ce8(&DAT_803460d0,0xe,0x56,0x1fd0);
              }
            }
            (&DAT_8035f548)[iVar3] = uVar11;
            iVar3 = (&DAT_8035f3e8)[iVar3];
          }
        }
      }
    }
    break;
  case 0xe:
  case 0x56:
    if (((DAT_8035f420 == 0) || (iVar3 = DAT_8035f420, DAT_8035f564 != iVar5)) &&
       ((DAT_8035f540 == 0 || (iVar3 = DAT_8035f540, DAT_8035f5f4 != iVar5)))) {
      if (DAT_8035f564 == -1) {
        iVar9 = 0xe;
      }
      else {
        if (DAT_8035f5f4 != -1) {
          iVar3 = 0;
          break;
        }
        iVar9 = 0x56;
      }
      if ((&DAT_8035f3e8)[iVar9] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar9] = 0;
      }
      FUN_8028f688(auStack104,s__s_animcurv_tab_802cc388,(&PTR_s_animtest_802cbbac)[iVar5]);
      iVar5 = FUN_800240d8(DAT_803dcc8c);
      iVar3 = FUN_80248b9c(auStack104,iVar5);
      if (iVar3 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar9] = *(undefined4 *)(iVar5 + 0x34);
        if ((&DAT_8035f0a8)[iVar9] == 0) {
          iVar3 = 0;
        }
        else {
          uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar9],0x7d7d7d7d,0);
          (&DAT_8035f3e8)[iVar9] = uVar6;
          FUN_802419b8((&DAT_8035f3e8)[iVar9],(&DAT_8035f0a8)[iVar9]);
          if (uVar10 == 0) {
            if (iVar9 == 0xe) {
              DAT_803dcc80 = DAT_803dcc80 | 0x20000000;
            }
            else {
              DAT_803dcc80 = DAT_803dcc80 | 0x80000000;
            }
            FUN_80248eac(iVar5,(&DAT_8035f3e8)[iVar9],(&DAT_8035f0a8)[iVar9],0,FUN_800422f8,2);
            *(int *)(&DAT_80345f70 + iVar9 * 4) = iVar5;
          }
          else {
            FUN_80015850(iVar5,(&DAT_8035f3e8)[iVar9],(&DAT_8035f0a8)[iVar9],0);
            FUN_80248c64(iVar5);
            FUN_80024134(DAT_803dcc8c,iVar5);
            if (((DAT_803dcc80 & 0x20000000) == 0) && ((DAT_803dcc80 & 0x80000000) == 0)) {
              FUN_80043ce8(&DAT_803460d0,0xe,0x56,0x1fd0);
            }
          }
          (&DAT_8035f548)[iVar9] = uVar11;
          iVar3 = (&DAT_8035f3e8)[iVar9];
        }
      }
    }
    break;
  default:
    iVar3 = 0;
    break;
  case 0x1a:
  case 0x53:
    if (((DAT_8035f450 == 0) || (iVar3 = DAT_8035f450, DAT_8035f57c != iVar5)) &&
       ((DAT_8035f534 == 0 || (iVar3 = DAT_8035f534, DAT_8035f5ee != iVar5)))) {
      if (DAT_8035f57c == -1) {
        iVar9 = 0x1a;
      }
      else {
        if (DAT_8035f5ee != -1) {
          iVar3 = 0;
          break;
        }
        iVar9 = 0x53;
      }
      if ((&DAT_8035f3e8)[iVar9] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar9] = 0;
      }
      FUN_8028f688(auStack104,s__s_voxmap_tab_802cc3bc,(&PTR_s_animtest_802cbbac)[iVar5]);
      iVar5 = FUN_800240d8(DAT_803dcc8c);
      iVar3 = FUN_80248b9c(auStack104,iVar5);
      if (iVar3 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar9] = *(undefined4 *)(iVar5 + 0x34);
        if ((&DAT_8035f0a8)[iVar9] == 0) {
          FUN_80024134(DAT_803dcc8c,iVar5);
          iVar3 = 0;
        }
        else {
          uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar9],0x7d7d7d7d,0);
          (&DAT_8035f3e8)[iVar9] = uVar6;
          FUN_802419b8((&DAT_8035f3e8)[iVar9],(&DAT_8035f0a8)[iVar9]);
          if (uVar10 == 0) {
            if (iVar9 == 0x1a) {
              DAT_803dcc80 = DAT_803dcc80 | 0x2000000;
            }
            else {
              DAT_803dcc80 = DAT_803dcc80 | 0x8000000;
            }
            *(int *)(&DAT_80345f70 + iVar9 * 4) = iVar5;
            FUN_80248eac(iVar5,(&DAT_8035f3e8)[iVar9],(&DAT_8035f0a8)[iVar9],0,FUN_80042468,2);
          }
          else {
            FUN_80015850(iVar5,(&DAT_8035f3e8)[iVar9],(&DAT_8035f0a8)[iVar9],0);
            FUN_80248c64(iVar5);
            FUN_80024134(DAT_803dcc8c,iVar5);
            if (((DAT_803dcc80 & 0x2000000) == 0) && ((DAT_803dcc80 & 0x8000000) == 0)) {
              FUN_80043ce8(&DAT_8034e010,0x1a,0x53,0x800);
            }
          }
          (&DAT_8035f548)[iVar9] = uVar11;
          iVar3 = (&DAT_8035f3e8)[iVar9];
        }
      }
    }
    break;
  case 0x1b:
  case 0x54:
    if (((DAT_8035f454 == 0) || (iVar3 = DAT_8035f454, DAT_8035f57e != iVar5)) &&
       ((DAT_8035f538 == 0 || (iVar3 = DAT_8035f538, DAT_8035f5f0 != iVar5)))) {
      if (DAT_8035f57e == -1) {
        iVar9 = 0x1b;
      }
      else {
        if (DAT_8035f5f0 != -1) {
          iVar3 = 0;
          break;
        }
        iVar9 = 0x54;
      }
      if ((&DAT_8035f3e8)[iVar9] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar9] = 0;
      }
      FUN_8028f688(auStack104,s__s_voxmap_bin_802cc398,(&PTR_s_animtest_802cbbac)[iVar5]);
      iVar5 = FUN_800240d8(DAT_803dcc8c);
      iVar3 = FUN_80248b9c(auStack104,iVar5);
      if (iVar3 == 0) {
        FUN_8028f688(auStack104,s_warlock_voxmap_bin_802cc3a8);
        iVar3 = FUN_80248b9c(auStack104,iVar5);
        if (iVar3 == 0) {
          iVar3 = 0;
          break;
        }
      }
      (&DAT_8035f0a8)[iVar9] = *(undefined4 *)(iVar5 + 0x34);
      if ((&DAT_8035f0a8)[iVar9] == 0) {
        FUN_8028f688(auStack104,s_warlock_voxmap_bin_802cc3a8);
        iVar3 = FUN_80248b9c(auStack104,iVar5);
        if (iVar3 == 0) {
          iVar3 = 0;
          break;
        }
        (&DAT_8035f0a8)[iVar9] = *(undefined4 *)(iVar5 + 0x34);
      }
      uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar9],0x7d7d7d7d,0);
      (&DAT_8035f3e8)[iVar9] = uVar6;
      FUN_802419b8((&DAT_8035f3e8)[iVar9],(&DAT_8035f0a8)[iVar9]);
      if (uVar10 == 0) {
        if (iVar9 == 0x1b) {
          DAT_803dcc80 = DAT_803dcc80 | 0x1000000;
        }
        else {
          DAT_803dcc80 = DAT_803dcc80 | 0x4000000;
        }
        *(int *)(&DAT_80345f70 + iVar9 * 4) = iVar5;
        FUN_80248eac(iVar5,(&DAT_8035f3e8)[iVar9],(&DAT_8035f0a8)[iVar9],0,FUN_800423b0,2);
      }
      else {
        FUN_80015850(iVar5,(&DAT_8035f3e8)[iVar9],(&DAT_8035f0a8)[iVar9],0);
        FUN_80248c64(iVar5);
        FUN_80024134(DAT_803dcc8c,iVar5);
        if (((DAT_803dcc80 & 0x2000000) == 0) && ((DAT_803dcc80 & 0x8000000) == 0)) {
          FUN_80043ce8(&DAT_8034e010,0x1a,0x53,0x800);
        }
      }
      (&DAT_8035f548)[iVar9] = uVar11;
      iVar3 = (&DAT_8035f3e8)[iVar9];
    }
    break;
  case 0x20:
  case 0x4b:
    if (((DAT_8035f468 == 0) || (iVar3 = DAT_8035f468, DAT_8035f588 != iVar5)) &&
       ((DAT_8035f514 == 0 || (iVar3 = DAT_8035f514, DAT_8035f5de != iVar5)))) {
      if (DAT_8035efc8 == iVar5) {
        iVar3 = 0x20;
        DAT_8035efc8 = -1;
      }
      else if (DAT_8035f074 == iVar5) {
        iVar3 = 0x4b;
        DAT_8035f074 = -1;
      }
      else if (DAT_8035f588 == -1) {
        iVar3 = 0x20;
      }
      else {
        if (DAT_8035f5de != -1) {
          iVar3 = 0;
          break;
        }
        iVar3 = 0x4b;
      }
      if ((&DAT_8035f3e8)[iVar3] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar3] = 0;
      }
      FUN_8028f688(auStack104,&DAT_803db5b8,(&PTR_s_animtest_802cbbac)[iVar5],
                   (&PTR_s_AUDIO_tab_802cb2f4)[iVar9]);
      iVar2 = FUN_800240d8(DAT_803dcc8c);
      iVar4 = FUN_80248b9c(auStack104,iVar2);
      if (iVar4 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar3] = *(undefined4 *)(iVar2 + 0x34);
        uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar3] + 0x20,0x7d7d7d7d,0);
        (&DAT_8035f3e8)[iVar3] = uVar6;
        FUN_802419b8((&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3]);
        iVar4 = (&DAT_8035f3e8)[iVar3];
        if (iVar4 == 0) {
          if ((&DAT_8035ef48)[iVar9] == -1) {
            FUN_80053700(1);
          }
          FUN_80248c64(iVar2);
          FUN_80024134(DAT_803dcc8c,iVar2);
          (&DAT_8035f0a8)[iVar3] = 0;
          (&DAT_8035ef48)[iVar3] = iVar5;
          iVar3 = 0;
        }
        else {
          if (uVar10 == 0) {
            if (iVar3 == 0x20) {
              DAT_803dcc80 = DAT_803dcc80 | 0x1000;
            }
            else {
              DAT_803dcc80 = DAT_803dcc80 | 0x2000;
            }
            *(int *)(&DAT_80345f70 + iVar3 * 4) = iVar2;
            FUN_80248eac(iVar2,iVar4,(&DAT_8035f0a8)[iVar3],0,FUN_8004288c,2);
          }
          else {
            FUN_80015850(iVar2,iVar4,(&DAT_8035f0a8)[iVar3],0);
            FUN_80248c64(iVar2);
            FUN_80024134(DAT_803dcc8c,iVar2);
            if (((DAT_803dcc80 & 0x4000) == 0) && ((DAT_803dcc80 & 0x8000) == 0)) {
              FUN_80043ce8(&DAT_80352010,0x21,0x4c,0x1000);
            }
          }
          (&DAT_8035f548)[iVar3] = uVar11;
          iVar3 = (&DAT_8035f3e8)[iVar3];
        }
      }
    }
    break;
  case 0x21:
  case 0x4c:
    if (((DAT_8035f46c == 0) || (iVar3 = DAT_8035f46c, DAT_8035f58a != iVar5)) &&
       ((DAT_8035f518 == 0 || (iVar3 = DAT_8035f518, DAT_8035f5e0 != iVar5)))) {
      if (DAT_8035f58a == -1) {
        iVar3 = 0x21;
      }
      else {
        if (DAT_8035f5e0 != -1) {
          iVar3 = 0;
          break;
        }
        iVar3 = 0x4c;
      }
      if ((&DAT_8035f3e8)[iVar3] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar3] = 0;
      }
      FUN_8028f688(auStack104,&DAT_803db5b8,(&PTR_s_animtest_802cbbac)[iVar5],
                   (&PTR_s_AUDIO_tab_802cb2f4)[iVar9]);
      iVar5 = FUN_800240d8(DAT_803dcc8c);
      iVar9 = FUN_80248b9c(auStack104,iVar5);
      if (iVar9 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar3] = *(undefined4 *)(iVar5 + 0x34);
        uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar3],0x7d7d7d7d,0);
        (&DAT_8035f3e8)[iVar3] = uVar6;
        FUN_802419b8((&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3]);
        if (uVar10 == 0) {
          *(int *)(&DAT_80345f70 + iVar3 * 4) = iVar5;
          if (iVar3 == 0x21) {
            DAT_803dcc80 = DAT_803dcc80 | 0x4000;
            FUN_80248eac(iVar5,(&DAT_8035f3e8)[0x21],(&DAT_8035f0a8)[0x21],0,FUN_800427c0,2);
          }
          else {
            DAT_803dcc80 = DAT_803dcc80 | 0x8000;
            FUN_80248eac(iVar5,(&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3],0,FUN_800426f4,2);
          }
        }
        else {
          FUN_80015850(iVar5,(&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3],0);
          FUN_80248c64(iVar5);
          FUN_80024134(DAT_803dcc8c,iVar5);
          if (((DAT_803dcc80 & 0x4000) == 0) && ((DAT_803dcc80 & 0x8000) == 0)) {
            FUN_80043ce8(&DAT_80352010,0x21,0x4c,0x1000);
          }
        }
        (&DAT_8035f548)[iVar3] = uVar11;
        iVar3 = (&DAT_8035f3e8)[iVar3];
      }
    }
    break;
  case 0x23:
  case 0x4d:
    if (((DAT_8035f474 == 0) || (iVar3 = DAT_8035f474, DAT_8035f58e != iVar5)) &&
       ((DAT_8035f51c == 0 || (iVar3 = DAT_8035f51c, DAT_8035f5e2 != iVar5)))) {
      if (DAT_8035efd4 == iVar5) {
        iVar3 = 0x23;
        DAT_8035efd4 = -1;
      }
      else if (DAT_8035f07c == iVar5) {
        iVar3 = 0x4d;
        DAT_8035f07c = -1;
      }
      else if (DAT_8035f58e == -1) {
        iVar3 = 0x23;
      }
      else {
        if (DAT_8035f5e2 != -1) {
          iVar3 = 0;
          break;
        }
        iVar3 = 0x4d;
      }
      if ((&DAT_8035f3e8)[iVar3] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar3] = 0;
      }
      FUN_8028f688(auStack104,&DAT_803db5b8,(&PTR_s_animtest_802cbbac)[iVar5],
                   (&PTR_s_AUDIO_tab_802cb2f4)[iVar9]);
      iVar2 = FUN_800240d8(DAT_803dcc8c);
      iVar4 = FUN_80248b9c(auStack104,iVar2);
      if (iVar4 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar3] = *(undefined4 *)(iVar2 + 0x34);
        uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar3] + 0x20,0x7d7d7d7d,0);
        (&DAT_8035f3e8)[iVar3] = uVar6;
        FUN_802419b8((&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3]);
        iVar4 = (&DAT_8035f3e8)[iVar3];
        if (iVar4 == 0) {
          if ((&DAT_8035ef48)[iVar9] == -1) {
            FUN_80053700(1);
          }
          FUN_80248c64(iVar2);
          FUN_80024134(DAT_803dcc8c,iVar2);
          (&DAT_8035f0a8)[iVar3] = 0;
          (&DAT_8035ef48)[iVar3] = iVar5;
          iVar3 = 0;
        }
        else {
          if (uVar10 == 0) {
            if (iVar3 == 0x23) {
              DAT_803dcc80 = DAT_803dcc80 | 0x100;
            }
            else {
              DAT_803dcc80 = DAT_803dcc80 | 0x200;
            }
            *(int *)(&DAT_80345f70 + iVar3 * 4) = iVar2;
            FUN_80248eac(iVar2,iVar4,(&DAT_8035f0a8)[iVar3],0,FUN_80042adc,2);
          }
          else {
            FUN_80015850(iVar2,iVar4,(&DAT_8035f0a8)[iVar3],0);
            FUN_80248c64(iVar2);
            FUN_80024134(DAT_803dcc8c,iVar2);
            if (((DAT_803dcc80 & 0x400) == 0) && ((DAT_803dcc80 & 0x800) == 0)) {
              FUN_80043ce8(&DAT_80356010,0x24,0x4e,0x1000);
            }
          }
          (&DAT_8035f548)[iVar3] = uVar11;
          iVar3 = (&DAT_8035f3e8)[iVar3];
        }
      }
    }
    break;
  case 0x24:
  case 0x4e:
    if (((DAT_8035f478 == 0) || (iVar3 = DAT_8035f478, DAT_8035f590 != iVar5)) &&
       ((DAT_8035f520 == 0 || (iVar3 = DAT_8035f520, DAT_8035f5e4 != iVar5)))) {
      if (DAT_8035f590 == -1) {
        iVar3 = 0x24;
      }
      else {
        if (DAT_8035f5e4 != -1) {
          iVar3 = 0;
          break;
        }
        iVar3 = 0x4e;
      }
      if ((&DAT_8035f3e8)[iVar3] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar3] = 0;
      }
      FUN_8028f688(auStack104,&DAT_803db5b8,(&PTR_s_animtest_802cbbac)[iVar5],
                   (&PTR_s_AUDIO_tab_802cb2f4)[iVar9]);
      iVar5 = FUN_800240d8(DAT_803dcc8c);
      iVar9 = FUN_80248b9c(auStack104,iVar5);
      if (iVar9 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar3] = *(undefined4 *)(iVar5 + 0x34);
        uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar3] + 0x20,0x7d7d7d7d,0);
        (&DAT_8035f3e8)[iVar3] = uVar6;
        FUN_802419b8((&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3]);
        if (uVar10 == 0) {
          if (iVar3 == 0x24) {
            DAT_803dcc80 = DAT_803dcc80 | 0x400;
            *(int *)(&DAT_80345f70 + iVar3 * 4) = iVar5;
            FUN_80248eac(iVar5,(&DAT_8035f3e8)[0x24],(&DAT_8035f0a8)[0x24],0,FUN_80042a10,2);
          }
          else {
            DAT_803dcc80 = DAT_803dcc80 | 0x800;
            *(int *)(&DAT_80345f70 + iVar3 * 4) = iVar5;
            FUN_80248eac(iVar5,(&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3],0,FUN_80042944,2);
          }
        }
        else {
          FUN_80015850(iVar5,(&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3],0);
          FUN_80248c64(iVar5);
          FUN_80024134(DAT_803dcc8c,iVar5);
          if (((DAT_803dcc80 & 0x400) == 0) && ((DAT_803dcc80 & 0x800) == 0)) {
            FUN_80043ce8(&DAT_80356010,0x24,0x4e,0x1000);
          }
        }
        (&DAT_8035f548)[iVar3] = uVar11;
        iVar3 = (&DAT_8035f3e8)[iVar3];
      }
    }
    break;
  case 0x25:
  case 0x47:
    if (((DAT_8035f47c == 0) || (iVar3 = DAT_8035f47c, DAT_8035f592 != iVar5)) &&
       ((DAT_8035f504 == 0 || (iVar3 = DAT_8035f504, DAT_8035f5d6 != iVar5)))) {
      if (DAT_8035efdc == iVar5) {
        iVar3 = 0x25;
        DAT_8035efdc = -1;
      }
      else if (DAT_8035f064 == iVar5) {
        iVar3 = 0x47;
        DAT_8035f064 = -1;
      }
      else if (DAT_8035f592 == -1) {
        iVar3 = 0x25;
      }
      else {
        if (DAT_8035f5d6 != -1) {
          iVar3 = 0;
          break;
        }
        iVar3 = 0x47;
      }
      if ((&DAT_8035f3e8)[iVar3] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar3] = 0;
      }
      if (lVar12 < 0x500000000) {
        FUN_8028f688(auStack104,s__s_mod_d_zlb_bin_802cc3cc,(&PTR_s_animtest_802cbbac)[iVar5],iVar5)
        ;
      }
      else {
        FUN_8028f688(auStack104,s__s_mod_d_zlb_bin_802cc3cc,(&PTR_s_animtest_802cbbac)[iVar5],
                     iVar5 + 1);
      }
      iVar2 = FUN_800240d8(DAT_803dcc8c);
      iVar4 = FUN_80248b9c(auStack104,iVar2);
      if (iVar4 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar3] = *(undefined4 *)(iVar2 + 0x34);
        uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar3],0x7d7d7d7d,0);
        (&DAT_8035f3e8)[iVar3] = uVar6;
        FUN_802419b8((&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3]);
        iVar4 = (&DAT_8035f3e8)[iVar3];
        if (iVar4 == 0) {
          if ((&DAT_8035ef48)[iVar9] == -1) {
            FUN_80053700(1);
          }
          FUN_80248c64(iVar2);
          FUN_80024134(DAT_803dcc8c,iVar2);
          (&DAT_8035f0a8)[iVar3] = 0;
          (&DAT_8035ef48)[iVar3] = iVar5;
          iVar3 = 0;
        }
        else {
          if (uVar10 == 0) {
            if (iVar3 == 0x25) {
              DAT_803dcc80 = DAT_803dcc80 | 0x10000;
            }
            else {
              DAT_803dcc80 = DAT_803dcc80 | 0x40000;
            }
            *(int *)(&DAT_80345f70 + iVar3 * 4) = iVar2;
            FUN_80248eac(iVar2,iVar4,(&DAT_8035f0a8)[iVar3],0,FUN_8004263c,2);
          }
          else {
            FUN_80015850(iVar2,iVar4,(&DAT_8035f0a8)[iVar3],0);
            FUN_80248c64(iVar2);
            FUN_80024134(DAT_803dcc8c,iVar2);
            if (((DAT_803dcc80 & 0x20000) == 0) && ((DAT_803dcc80 & 0x80000) == 0)) {
              FUN_80043ce8(&DAT_80350010,0x26,0x48,0x800);
            }
          }
          (&DAT_8035f548)[iVar3] = uVar11;
          iVar3 = (&DAT_8035f3e8)[iVar3];
        }
      }
    }
    break;
  case 0x26:
  case 0x48:
    if (((DAT_8035f480 == 0) || (iVar3 = DAT_8035f480, DAT_8035f594 != iVar5)) &&
       ((DAT_8035f508 == 0 || (iVar3 = DAT_8035f508, DAT_8035f5d8 != iVar5)))) {
      if (DAT_8035f594 == -1) {
        iVar9 = 0x26;
      }
      else {
        if (DAT_8035f5d8 != -1) {
          iVar3 = 0;
          break;
        }
        iVar9 = 0x48;
      }
      if ((&DAT_8035f3e8)[iVar9] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar9] = 0;
      }
      iVar3 = 0;
      piVar7 = &DAT_802cbcd0;
      iVar2 = 0xf;
      do {
        iVar4 = iVar3;
        if ((((iVar5 == *piVar7) || (iVar4 = iVar3 + 1, iVar5 == piVar7[1])) ||
            (iVar4 = iVar3 + 2, iVar5 == piVar7[2])) ||
           ((iVar4 = iVar3 + 3, iVar5 == piVar7[3] || (iVar4 = iVar3 + 4, iVar5 == piVar7[4]))))
        break;
        piVar7 = piVar7 + 5;
        iVar3 = iVar3 + 5;
        iVar2 = iVar2 + -1;
        iVar4 = iVar3;
      } while (iVar2 != 0);
      FUN_80048328(0,iVar4,0);
      if (lVar12 < 0x500000000) {
        FUN_8028f688(auStack104,s__s_mod_d_tab_802cc3e0,(&PTR_s_animtest_802cbbac)[iVar5],iVar5);
      }
      else {
        FUN_8028f688(auStack104,s__s_mod_d_tab_802cc3e0,(&PTR_s_animtest_802cbbac)[iVar5],iVar5 + 1)
        ;
      }
      iVar5 = FUN_800240d8(DAT_803dcc8c);
      iVar3 = FUN_80248b9c(auStack104,iVar5);
      if (iVar3 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar9] = *(undefined4 *)(iVar5 + 0x34);
        uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar9],0x7d7d7d7d,0);
        (&DAT_8035f3e8)[iVar9] = uVar6;
        FUN_802419b8((&DAT_8035f3e8)[iVar9],(&DAT_8035f0a8)[iVar9]);
        if (uVar10 == 0) {
          if (iVar9 == 0x26) {
            DAT_803dcc80 = DAT_803dcc80 | 0x20000;
          }
          else {
            DAT_803dcc80 = DAT_803dcc80 | 0x80000;
          }
          *(int *)(&DAT_80345f70 + iVar9 * 4) = iVar5;
          FUN_80248eac(iVar5,(&DAT_8035f3e8)[iVar9],(&DAT_8035f0a8)[iVar9],0,FUN_80042520,2);
        }
        else {
          FUN_80015850(iVar5,(&DAT_8035f3e8)[iVar9],(&DAT_8035f0a8)[iVar9],0);
          FUN_80248c64(iVar5);
          FUN_80024134(DAT_803dcc8c,iVar5);
          if (((DAT_803dcc80 & 0x20000) == 0) && ((DAT_803dcc80 & 0x80000) == 0)) {
            FUN_80043ce8(&DAT_80350010,0x26,0x48,0x800);
          }
        }
        (&DAT_8035f548)[iVar9] = uVar11;
        iVar3 = (&DAT_8035f3e8)[iVar9];
      }
    }
    break;
  case 0x2a:
  case 0x45:
    if (((DAT_8035f490 == 0) || (iVar3 = DAT_8035f490, DAT_8035f59c != iVar5)) &&
       ((DAT_8035f4fc == 0 || (iVar3 = DAT_8035f4fc, DAT_8035f5d2 != iVar5)))) {
      if (DAT_8035f59c == -1) {
        iVar3 = 0x2a;
      }
      else {
        if (DAT_8035f5d2 != -1) {
          iVar3 = 0;
          break;
        }
        iVar3 = 0x45;
      }
      if ((&DAT_8035f3e8)[iVar3] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar3] = 0;
      }
      FUN_8028f688(auStack104,&DAT_803db5b8,(&PTR_s_animtest_802cbbac)[iVar5],
                   (&PTR_s_AUDIO_tab_802cb2f4)[iVar9]);
      iVar5 = FUN_800240d8(DAT_803dcc8c);
      iVar9 = FUN_80248b9c(auStack104,iVar5);
      if (iVar9 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar3] = *(undefined4 *)(iVar5 + 0x34);
        uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar3],0x7d7d7d7d,0);
        (&DAT_8035f3e8)[iVar3] = uVar6;
        FUN_802419b8((&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3]);
        if (uVar10 == 0) {
          if (iVar3 == 0x2a) {
            DAT_803dcc80 = DAT_803dcc80 | 4;
          }
          else {
            DAT_803dcc80 = DAT_803dcc80 | 8;
          }
          *(int *)(&DAT_80345f70 + iVar3 * 4) = iVar5;
          FUN_80248eac(iVar5,(&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3],0,FUN_80042dbc,2);
        }
        else {
          FUN_80015850(iVar5,(&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3],0);
          FUN_80248c64(iVar5);
          FUN_80024134(DAT_803dcc8c,iVar5);
          if (((DAT_803dcc80 & 4) == 0) && ((DAT_803dcc80 & 8) == 0)) {
            FUN_80043ce8(&DAT_8035cef0,0x2a,0x45,0x800);
          }
        }
        (&DAT_8035f548)[iVar3] = uVar11;
        iVar3 = (&DAT_8035f3e8)[iVar3];
      }
    }
    break;
  case 0x2b:
  case 0x46:
    if (((DAT_8035f494 == 0) || (iVar3 = DAT_8035f494, DAT_8035f59e != iVar5)) &&
       ((DAT_8035f500 == 0 || (iVar3 = DAT_8035f500, DAT_8035f5d4 != iVar5)))) {
      if (DAT_8035eff4 == iVar5) {
        iVar3 = 0x2b;
        DAT_8035eff4 = -1;
      }
      else if (DAT_8035f060 == iVar5) {
        iVar3 = 0x46;
        DAT_8035f060 = -1;
      }
      else if (DAT_8035f59e == -1) {
        iVar3 = 0x2b;
      }
      else {
        if (DAT_8035f5d4 != -1) {
          iVar3 = 0;
          break;
        }
        iVar3 = 0x46;
      }
      if ((&DAT_8035f3e8)[iVar3] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar3] = 0;
      }
      FUN_8028f688(auStack104,&DAT_803db5b8,(&PTR_s_animtest_802cbbac)[iVar5],
                   (&PTR_s_AUDIO_tab_802cb2f4)[iVar9]);
      iVar2 = FUN_800240d8(DAT_803dcc8c);
      iVar4 = FUN_80248b9c(auStack104,iVar2);
      if (iVar4 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar3] = *(undefined4 *)(iVar2 + 0x34);
        uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar3],0x7d7d7d7d,0);
        (&DAT_8035f3e8)[iVar3] = uVar6;
        FUN_802419b8((&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3]);
        iVar4 = (&DAT_8035f3e8)[iVar3];
        if (iVar4 == 0) {
          if ((&DAT_8035ef48)[iVar9] == -1) {
            FUN_80053700(1);
          }
          FUN_80248c64(iVar2);
          FUN_80024134(DAT_803dcc8c,iVar2);
          (&DAT_8035f0a8)[iVar3] = 0;
          (&DAT_8035ef48)[iVar3] = iVar5;
          iVar3 = 0;
        }
        else {
          if (uVar10 == 0) {
            DAT_803dcc7c = DAT_803dcc7c + 1;
            if (iVar3 == 0x2b) {
              DAT_803dcc80 = DAT_803dcc80 | 1;
            }
            else {
              DAT_803dcc80 = DAT_803dcc80 | 2;
            }
            *(int *)(&DAT_80345f70 + iVar3 * 4) = iVar2;
            FUN_80248eac(iVar2,iVar4,(&DAT_8035f0a8)[iVar3],0,FUN_80042c4c,2);
          }
          else {
            FUN_80015850(iVar2,iVar4,(&DAT_8035f0a8)[iVar3],0);
            FUN_80248c64(iVar2);
            FUN_80024134(DAT_803dcc8c,iVar2);
            if (((DAT_803dcc80 & 4) == 0) && ((DAT_803dcc80 & 8) == 0)) {
              FUN_80043ce8(&DAT_8035cef0,0x2a,0x45,0x800);
            }
            DAT_803dcc7c = DAT_803dcc7c + 1;
          }
          (&DAT_8035f548)[iVar3] = uVar11;
          iVar3 = (&DAT_8035f3e8)[iVar3];
        }
      }
    }
    break;
  case 0x2f:
  case 0x49:
    if (((DAT_8035f4a4 == 0) || (iVar3 = DAT_8035f4a4, DAT_8035f5a6 != iVar5)) &&
       ((DAT_8035f50c == 0 || (iVar3 = DAT_8035f50c, DAT_8035f5da != iVar5)))) {
      if (DAT_8035f5a6 == -1) {
        iVar3 = 0x2f;
      }
      else {
        if (DAT_8035f5da != -1) {
          iVar3 = 0;
          break;
        }
        iVar3 = 0x49;
      }
      if ((&DAT_8035f3e8)[iVar3] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar3] = 0;
      }
      FUN_8028f688(auStack104,&DAT_803db5b8,(&PTR_s_animtest_802cbbac)[iVar5],
                   (&PTR_s_AUDIO_tab_802cb2f4)[iVar9]);
      iVar5 = FUN_800240d8(DAT_803dcc8c);
      iVar9 = FUN_80248b9c(auStack104,iVar5);
      if (iVar9 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar3] = *(undefined4 *)(iVar5 + 0x34);
        uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar3],0x7d7d7d7d,0);
        (&DAT_8035f3e8)[iVar3] = uVar6;
        FUN_802419b8((&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3]);
        if (uVar10 == 0) {
          if (iVar3 == 0x2f) {
            DAT_803dcc80 = DAT_803dcc80 | 0x40;
          }
          else {
            DAT_803dcc80 = DAT_803dcc80 | 0x80;
          }
          *(int *)(&DAT_80345f70 + iVar3 * 4) = iVar5;
          FUN_80248eac(iVar5,(&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3],0,FUN_80042d04,2);
        }
        else {
          FUN_80015850(iVar5,(&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3],0);
          FUN_80248c64(iVar5);
          FUN_80024134(DAT_803dcc8c,iVar5);
          if (((DAT_803dcc80 & 0x40) == 0) && ((DAT_803dcc80 & 0x80) == 0)) {
            FUN_80043ce8(&DAT_8035a010,0x2f,0x49,3000);
          }
        }
        (&DAT_8035f548)[iVar3] = uVar11;
        iVar3 = (&DAT_8035f3e8)[iVar3];
      }
    }
    break;
  case 0x30:
  case 0x4a:
    if (((DAT_8035f4a8 == 0) || (iVar3 = DAT_8035f4a8, DAT_8035f5a8 != iVar5)) &&
       ((DAT_8035f510 == 0 || (iVar3 = DAT_8035f510, DAT_8035f5dc != iVar5)))) {
      if (DAT_8035f008 == iVar5) {
        iVar3 = 0x30;
        DAT_8035f008 = -1;
      }
      else if (DAT_8035f070 == iVar5) {
        iVar3 = 0x4a;
        DAT_8035f070 = -1;
      }
      else if (DAT_8035f5a8 == -1) {
        iVar3 = 0x30;
      }
      else {
        if (DAT_8035f5dc != -1) {
          iVar3 = 0;
          break;
        }
        iVar3 = 0x4a;
      }
      if ((&DAT_8035f3e8)[iVar3] != 0) {
        FUN_80023800();
        (&DAT_8035f3e8)[iVar3] = 0;
      }
      FUN_8028f688(auStack104,&DAT_803db5b8,(&PTR_s_animtest_802cbbac)[iVar5],
                   (&PTR_s_AUDIO_tab_802cb2f4)[iVar9]);
      iVar2 = FUN_800240d8(DAT_803dcc8c);
      iVar4 = FUN_80248b9c(auStack104,iVar2);
      if (iVar4 == 0) {
        iVar3 = 0;
      }
      else {
        (&DAT_8035f0a8)[iVar3] = *(undefined4 *)(iVar2 + 0x34);
        uVar6 = FUN_80023cc8((&DAT_8035f0a8)[iVar3],0x7d7d7d7d,0);
        (&DAT_8035f3e8)[iVar3] = uVar6;
        FUN_802419b8((&DAT_8035f3e8)[iVar3],(&DAT_8035f0a8)[iVar3]);
        iVar4 = (&DAT_8035f3e8)[iVar3];
        if (iVar4 == 0) {
          if ((&DAT_8035ef48)[iVar9] == -1) {
            FUN_80053700(1);
          }
          FUN_80248c64(iVar2);
          FUN_80024134(DAT_803dcc8c,iVar2);
          (&DAT_8035f0a8)[iVar3] = 0;
          (&DAT_8035ef48)[iVar3] = iVar5;
          iVar3 = 0;
        }
        else {
          if (uVar10 == 0) {
            if (iVar3 == 0x30) {
              DAT_803dcc80 = DAT_803dcc80 | 0x10;
            }
            else {
              DAT_803dcc80 = DAT_803dcc80 | 0x20;
            }
            *(int *)(&DAT_80345f70 + iVar3 * 4) = iVar2;
            FUN_80248eac(iVar2,iVar4,(&DAT_8035f0a8)[iVar3],0,FUN_80042b94,2);
          }
          else {
            FUN_80015850(iVar2,iVar4,(&DAT_8035f0a8)[iVar3],0);
            FUN_80248c64(iVar2);
            FUN_80024134(DAT_803dcc8c,iVar2);
            if (((DAT_803dcc80 & 0x40) == 0) && ((DAT_803dcc80 & 0x80) == 0)) {
              FUN_80043ce8(&DAT_8035a010,0x2f,0x49,3000);
            }
          }
          (&DAT_8035f548)[iVar3] = uVar11;
          iVar3 = (&DAT_8035f3e8)[iVar3];
        }
      }
    }
  }
  FUN_80286114(iVar3);
  return;
}

