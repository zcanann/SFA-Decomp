// Function: FUN_8026e0e4
// Entry: 8026e0e4
// Size: 1920 bytes

/* WARNING: Removing unreachable block (ram,0x8026e388) */
/* WARNING: Removing unreachable block (ram,0x8026e120) */

undefined4 FUN_8026e0e4(int param_1,undefined4 param_2,uint *param_3)

{
  bool bVar1;
  byte bVar2;
  byte bVar3;
  short sVar4;
  uint uVar5;
  int *piVar6;
  int iVar7;
  undefined4 uVar8;
  uint uVar9;
  short sVar10;
  int iVar11;
  int iVar12;
  undefined4 *puVar13;
  undefined4 *puVar14;
  uint uVar15;
  ushort local_2c;
  ushort local_2a;
  ushort local_28;
  ushort local_26 [3];
  
  iVar12 = DAT_803de218;
  bVar2 = *(byte *)(param_1 + 0x14);
  if (bVar2 == 2) {
    iVar12 = *(int *)(param_1 + 0x10);
    *(short *)(iVar12 + 0x14) = *(short *)(iVar12 + 0x14) + *(short *)(iVar12 + 0x16);
    if (*(int *)(iVar12 + 0x10) == 0) {
      *(undefined4 *)(iVar12 + 0x18) = 0x7fffffff;
    }
    else {
      iVar7 = FUN_8026ddb4(*(int *)(iVar12 + 0x10),&local_2a,iVar12 + 0x16);
      *(int *)(iVar12 + 0x10) = iVar7;
      if (iVar7 == 0) {
        *(undefined4 *)(iVar12 + 0x18) = 0x7fffffff;
      }
      else {
        *(uint *)(iVar12 + 0x18) = *(int *)(iVar12 + 0x18) + (uint)local_2a;
      }
    }
    FUN_80281908(0x80,*(undefined *)(iVar12 + 0x28),DAT_803de220 & 0xff,
                 *(undefined2 *)(iVar12 + 0x14));
  }
  else if (bVar2 < 2) {
    if (bVar2 == 0) {
      iVar7 = *(int *)(param_1 + 0xc);
      bVar2 = *(byte *)(iVar7 + 2);
      bVar3 = *(byte *)(iVar7 + 3);
      uVar9 = (uint)bVar3;
      uVar15 = (uint)*(byte *)(*(int *)(param_1 + 0x10) + 0x28);
      if ((bVar2 & 0x80) == 0) {
        if ((*(uint *)(DAT_803de218 + ((int)(uint)*(byte *)(param_1 + 0x15) >> 5) * 4 + 0x11c) &
            1 << (*(byte *)(param_1 + 0x15) & 0x1f)) != 0) {
          sVar4 = *(short *)(DAT_803de218 + uVar15 * 4 + 0xe70);
          if (sVar4 != -1) {
            iVar12 = *(int *)(*(int *)(param_1 + 0x10) + 0xc);
            uVar5 = (uint)bVar2 + (int)*(char *)(iVar12 + 10);
            if ((int)uVar5 < 0x80) {
              if ((int)uVar5 < 0) {
                uVar5 = 0;
              }
            }
            else {
              uVar5 = 0x7f;
            }
            uVar9 = uVar9 + (int)*(char *)(iVar12 + 0xb);
            if ((int)uVar9 < 0x80) {
              if ((int)uVar9 < 0) {
                uVar9 = 0;
              }
            }
            else {
              uVar9 = 0x7f;
            }
            piVar6 = (int *)FUN_8026c030(*(int *)(param_1 + 8) + (uint)*(ushort *)(iVar7 + 4),
                                         param_2);
            if (piVar6 != (int *)0x0) {
              if (DAT_803de224 == '\0') {
                sVar10 = 0;
              }
              else {
                sVar10 = -1;
              }
              iVar12 = DAT_803de218 + uVar15 * 4;
              iVar12 = FUN_8026feec(sVar4,*(undefined *)(iVar12 + 0xe72),
                                    *(undefined *)(iVar12 + 0xe73),uVar5 & 0xff,uVar9 & 0xff,0x40,
                                    uVar15,DAT_803de220 & 0xff,param_2,0,
                                    (uint)*(byte *)(param_1 + 0x15),
                                    *(undefined *)
                                     (DAT_803de218 + (uint)*(byte *)(param_1 + 0x15) + 0x324),
                                    (int)sVar10,(uint)*(byte *)(DAT_803de218 + 0xee1),
                                    (&DAT_803bda24)[(uint)*(byte *)(DAT_803de218 + 0xee1) * 2]);
              piVar6[2] = iVar12;
              if (iVar12 == -1) {
                if (*piVar6 != 0) {
                  *(int *)(*piVar6 + 4) = piVar6[1];
                }
                if ((int *)piVar6[1] == (int *)0x0) {
                  *(int *)(DAT_803de218 + (uint)*(byte *)((int)piVar6 + 0x11) * 4 + 0xe64) = *piVar6
                  ;
                }
                else {
                  *(int *)piVar6[1] = *piVar6;
                }
                bVar1 = DAT_803de21c != (int *)0x0;
                *piVar6 = (int)DAT_803de21c;
                if (bVar1) {
                  *(int **)((int)DAT_803de21c + 4) = piVar6;
                }
                piVar6[1] = 0;
                DAT_803de21c = piVar6;
              }
            }
          }
        }
      }
      else if (uVar9 == 1) {
        FUN_80281338(0x82,uVar15,DAT_803de220 & 0xff,bVar2 & 0x7f);
      }
      else if (uVar9 == 0) {
        (&DAT_803bcc90)[uVar15 + DAT_803de220 * 0x10] = 0xffff;
        if (uVar15 == 9) {
          uVar9 = (uint)*(byte *)(iVar12 + (bVar2 & 0x7f) + 0x98);
          if (uVar9 != 0xff) {
            iVar7 = uVar9 * 6;
            *(undefined2 *)(iVar12 + 0xe94) = *(undefined2 *)(*(int *)(iVar12 + 0x94) + iVar7);
            *(undefined *)(iVar12 + 0xe96) = *(undefined *)(*(int *)(iVar12 + 0x94) + iVar7 + 2);
            *(undefined *)(iVar12 + 0xe97) = *(undefined *)(*(int *)(iVar12 + 0x94) + iVar7 + 3);
          }
        }
        else {
          uVar9 = (uint)*(byte *)(iVar12 + (bVar2 & 0x7f) + 0x14);
          if (uVar9 != 0xff) {
            iVar11 = uVar9 * 6;
            iVar7 = iVar12 + uVar15 * 4;
            *(undefined2 *)(iVar7 + 0xe70) = *(undefined2 *)(*(int *)(iVar12 + 0x10) + iVar11);
            *(undefined *)(iVar7 + 0xe72) = *(undefined *)(*(int *)(iVar12 + 0x10) + iVar11 + 2);
            *(undefined *)(iVar7 + 0xe73) = *(undefined *)(*(int *)(iVar12 + 0x10) + iVar11 + 3);
          }
        }
      }
      else if ((bVar3 & 0x80) == 0x80) {
        switch(bVar3 & 0x7f) {
        case 0x68:
          if (*(char *)(DAT_803de218 + 0xee0) != '\0') {
            FUN_8026d880(DAT_803de218 + 0xeb4,*(undefined4 *)(DAT_803de218 + 0xedc),1);
            *(undefined *)(DAT_803de218 + 0xee0) = 0;
          }
          break;
        case 0x69:
          (&DAT_803bcc90)[uVar15 + DAT_803de220 * 0x10] = bVar2 & 0x7f;
          break;
        case 0x6a:
          (&DAT_803bcc90)[uVar15 + DAT_803de220 * 0x10] = (bVar2 & 0x7f) + 0x80;
          break;
        default:
          FUN_80281338(bVar3 & 0x7f,uVar15,DAT_803de220 & 0xff,bVar2 & 0x7f);
          break;
        case 0x79:
          FUN_80281a30(uVar15,DAT_803de220 & 0xff,0);
          break;
        case 0x7b:
          FUN_8026c250();
        }
      }
    }
    else {
      iVar12 = *(int *)(param_1 + 0x10);
      *(short *)(iVar12 + 0x20) = *(short *)(iVar12 + 0x20) + *(short *)(iVar12 + 0x22);
      if (*(int *)(iVar12 + 0x1c) == 0) {
        *(undefined4 *)(iVar12 + 0x24) = 0x7fffffff;
      }
      else {
        iVar7 = FUN_8026ddb4(*(int *)(iVar12 + 0x1c),&local_2c,iVar12 + 0x22);
        *(int *)(iVar12 + 0x1c) = iVar7;
        if (iVar7 == 0) {
          *(undefined4 *)(iVar12 + 0x24) = 0x7fffffff;
        }
        else {
          *(uint *)(iVar12 + 0x24) = *(int *)(iVar12 + 0x24) + (uint)local_2c;
        }
      }
      FUN_80281908(1,*(undefined *)(iVar12 + 0x28),DAT_803de220 & 0xff,
                   *(undefined2 *)(iVar12 + 0x20));
    }
  }
  else if (bVar2 == 4) {
    puVar13 = *(undefined4 **)(param_1 + 0xc);
    iVar12 = *(int *)(DAT_803de218 + 0x118);
    iVar12 = iVar12 + *(int *)(*(int *)(iVar12 + 4) + iVar12 + (uint)*(ushort *)(puVar13 + 2) * 4);
    puVar14 = (undefined4 *)(DAT_803de218 + (uint)*(byte *)(param_1 + 0x15) * 0x2c + 0x364);
    puVar14[2] = iVar12 + 0xc;
    *puVar14 = 0;
    puVar14[1] = *puVar13;
    puVar14[3] = puVar13;
    if (*(int *)(iVar12 + 4) == 0) {
      puVar14[6] = 0x7fffffff;
    }
    else {
      iVar7 = FUN_8026ddb4(*(int *)(iVar12 + 4) + *(int *)(DAT_803de218 + 0x118),local_26,
                           (int)puVar14 + 0x16);
      puVar14[4] = iVar7;
      if (iVar7 == 0) {
        puVar14[6] = 0x7fffffff;
      }
      else {
        puVar14[6] = (uint)local_26[0];
      }
    }
    *(undefined2 *)(puVar14 + 5) = 0x2000;
    if (*(int *)(iVar12 + 8) == 0) {
      puVar14[9] = 0x7fffffff;
    }
    else {
      iVar12 = FUN_8026ddb4(*(int *)(iVar12 + 8) + *(int *)(DAT_803de218 + 0x118),&local_28,
                            (int)puVar14 + 0x22);
      puVar14[7] = iVar12;
      if (iVar12 == 0) {
        puVar14[9] = 0x7fffffff;
      }
      else {
        puVar14[9] = (uint)local_28;
      }
    }
    *(undefined2 *)(puVar14 + 8) = 0;
    *(undefined *)(puVar14 + 10) =
         *(undefined *)
          (*(int *)(*(int *)(DAT_803de218 + 0x118) + 8) +
          *(int *)(DAT_803de218 + 0x118) + (uint)*(byte *)(param_1 + 0x15));
    iVar12 = DAT_803de218;
    uVar9 = (uint)*(byte *)(puVar13 + 1);
    if (uVar9 != 0xff) {
      uVar15 = (uint)*(byte *)(puVar14 + 10);
      (&DAT_803bcc90)[uVar15 + DAT_803de220 * 0x10] = 0xffff;
      if (uVar15 == 9) {
        uVar9 = (uint)*(byte *)(iVar12 + uVar9 + 0x98);
        if (uVar9 != 0xff) {
          iVar7 = uVar9 * 6;
          *(undefined2 *)(iVar12 + 0xe94) = *(undefined2 *)(*(int *)(iVar12 + 0x94) + iVar7);
          *(undefined *)(iVar12 + 0xe96) = *(undefined *)(*(int *)(iVar12 + 0x94) + iVar7 + 2);
          *(undefined *)(iVar12 + 0xe97) = *(undefined *)(*(int *)(iVar12 + 0x94) + iVar7 + 3);
        }
      }
      else {
        uVar9 = (uint)*(byte *)(iVar12 + uVar9 + 0x14);
        if (uVar9 != 0xff) {
          iVar11 = uVar9 * 6;
          iVar7 = iVar12 + uVar15 * 4;
          *(undefined2 *)(iVar7 + 0xe70) = *(undefined2 *)(*(int *)(iVar12 + 0x10) + iVar11);
          *(undefined *)(iVar7 + 0xe72) = *(undefined *)(*(int *)(iVar12 + 0x10) + iVar11 + 2);
          *(undefined *)(iVar7 + 0xe73) = *(undefined *)(*(int *)(iVar12 + 0x10) + iVar11 + 3);
        }
      }
    }
    if (*(char *)((int)puVar13 + 5) != -1) {
      FUN_80281338(7,*(undefined *)(puVar14 + 10),DAT_803de220 & 0xff);
    }
  }
  else if (bVar2 < 4) {
    *param_3 = *param_3 | 1;
    return 0;
  }
  uVar8 = FUN_8026de58(*(undefined *)(param_1 + 0x15));
  return uVar8;
}

