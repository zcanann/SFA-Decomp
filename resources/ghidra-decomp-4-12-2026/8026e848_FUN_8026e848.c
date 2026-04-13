// Function: FUN_8026e848
// Entry: 8026e848
// Size: 1920 bytes

/* WARNING: Removing unreachable block (ram,0x8026eaec) */
/* WARNING: Removing unreachable block (ram,0x8026e884) */

int FUN_8026e848(int param_1,byte param_2,uint *param_3)

{
  bool bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  byte *pbVar8;
  int iVar9;
  uint uVar10;
  short sVar11;
  int iVar12;
  undefined4 *puVar13;
  uint uVar14;
  undefined4 *puVar15;
  uint uVar16;
  ushort local_2c;
  ushort local_2a;
  ushort local_28;
  ushort local_26 [3];
  
  iVar9 = DAT_803dee98;
  bVar2 = *(byte *)(param_1 + 0x14);
  if (bVar2 == 2) {
    iVar9 = *(int *)(param_1 + 0x10);
    *(short *)(iVar9 + 0x14) = *(short *)(iVar9 + 0x14) + *(short *)(iVar9 + 0x16);
    if (*(byte **)(iVar9 + 0x10) == (byte *)0x0) {
      *(undefined4 *)(iVar9 + 0x18) = 0x7fffffff;
    }
    else {
      pbVar8 = FUN_8026e518(*(byte **)(iVar9 + 0x10),&local_2a,(short *)(iVar9 + 0x16));
      *(byte **)(iVar9 + 0x10) = pbVar8;
      if (pbVar8 == (byte *)0x0) {
        *(undefined4 *)(iVar9 + 0x18) = 0x7fffffff;
      }
      else {
        *(uint *)(iVar9 + 0x18) = *(int *)(iVar9 + 0x18) + (uint)local_2a;
      }
    }
    FUN_8028206c(0x80,*(byte *)(iVar9 + 0x28),(byte)DAT_803deea0,(uint)*(ushort *)(iVar9 + 0x14));
  }
  else if (bVar2 < 2) {
    if (bVar2 == 0) {
      iVar6 = *(int *)(param_1 + 0xc);
      bVar2 = *(byte *)(iVar6 + 2);
      bVar3 = *(byte *)(iVar6 + 3);
      uVar10 = (uint)bVar3;
      bVar4 = *(byte *)(*(int *)(param_1 + 0x10) + 0x28);
      uVar16 = (uint)bVar4;
      if ((bVar2 & 0x80) == 0) {
        if ((*(uint *)(DAT_803dee98 + ((int)(uint)*(byte *)(param_1 + 0x15) >> 5) * 4 + 0x11c) &
            1 << (*(byte *)(param_1 + 0x15) & 0x1f)) != 0) {
          uVar14 = (uint)*(ushort *)(DAT_803dee98 + uVar16 * 4 + 0xe70);
          if (uVar14 != 0xffff) {
            iVar9 = *(int *)(*(int *)(param_1 + 0x10) + 0xc);
            uVar5 = (uint)bVar2 + (int)*(char *)(iVar9 + 10);
            if ((int)uVar5 < 0x80) {
              if ((int)uVar5 < 0) {
                uVar5 = 0;
              }
            }
            else {
              uVar5 = 0x7f;
            }
            iVar9 = uVar10 + (int)*(char *)(iVar9 + 0xb);
            if (iVar9 < 0x80) {
              if (iVar9 < 0) {
                iVar9 = 0;
              }
            }
            else {
              iVar9 = 0x7f;
            }
            piVar7 = FUN_8026c794(*(int *)(param_1 + 8) + (uint)*(ushort *)(iVar6 + 4),param_2);
            if (piVar7 != (int *)0x0) {
              if (DAT_803deea4 == '\0') {
                sVar11 = 0;
              }
              else {
                sVar11 = -1;
              }
              iVar6 = DAT_803dee98 + uVar16 * 4;
              iVar9 = FUN_80270650(uVar14,(uint)*(byte *)(iVar6 + 0xe72),
                                   (uint)*(byte *)(iVar6 + 0xe73),uVar5 & 0xff,(byte)iVar9,0x40,
                                   uVar16,DAT_803deea0 & 0xff,param_2,0,
                                   (ushort)*(byte *)(param_1 + 0x15),
                                   *(undefined *)
                                    (DAT_803dee98 + (uint)*(byte *)(param_1 + 0x15) + 0x324),sVar11,
                                   *(byte *)(DAT_803dee98 + 0xee1),
                                   (uint)(byte)(&DAT_803be684)
                                               [(uint)*(byte *)(DAT_803dee98 + 0xee1) * 2]);
              piVar7[2] = iVar9;
              if (iVar9 == -1) {
                if (*piVar7 != 0) {
                  *(int *)(*piVar7 + 4) = piVar7[1];
                }
                if ((int *)piVar7[1] == (int *)0x0) {
                  *(int *)(DAT_803dee98 + (uint)*(byte *)((int)piVar7 + 0x11) * 4 + 0xe64) = *piVar7
                  ;
                }
                else {
                  *(int *)piVar7[1] = *piVar7;
                }
                bVar1 = DAT_803dee9c != (int *)0x0;
                *piVar7 = (int)DAT_803dee9c;
                if (bVar1) {
                  DAT_803dee9c[1] = (int)piVar7;
                }
                piVar7[1] = 0;
                DAT_803dee9c = piVar7;
              }
            }
          }
        }
      }
      else if (uVar10 == 1) {
        FUN_80281a9c(0x82,bVar4,(byte)DAT_803deea0,bVar2 & 0x7f);
      }
      else if (uVar10 == 0) {
        (&DAT_803bd8f0)[uVar16 + DAT_803deea0 * 0x10] = 0xffff;
        if (uVar16 == 9) {
          uVar10 = (uint)*(byte *)(iVar9 + (bVar2 & 0x7f) + 0x98);
          if (uVar10 != 0xff) {
            iVar6 = uVar10 * 6;
            *(undefined2 *)(iVar9 + 0xe94) = *(undefined2 *)(*(int *)(iVar9 + 0x94) + iVar6);
            *(undefined *)(iVar9 + 0xe96) = *(undefined *)(*(int *)(iVar9 + 0x94) + iVar6 + 2);
            *(undefined *)(iVar9 + 0xe97) = *(undefined *)(*(int *)(iVar9 + 0x94) + iVar6 + 3);
          }
        }
        else {
          uVar10 = (uint)*(byte *)(iVar9 + (bVar2 & 0x7f) + 0x14);
          if (uVar10 != 0xff) {
            iVar12 = uVar10 * 6;
            iVar6 = iVar9 + uVar16 * 4;
            *(undefined2 *)(iVar6 + 0xe70) = *(undefined2 *)(*(int *)(iVar9 + 0x10) + iVar12);
            *(undefined *)(iVar6 + 0xe72) = *(undefined *)(*(int *)(iVar9 + 0x10) + iVar12 + 2);
            *(undefined *)(iVar6 + 0xe73) = *(undefined *)(*(int *)(iVar9 + 0x10) + iVar12 + 3);
          }
        }
      }
      else if ((bVar3 & 0x80) == 0x80) {
        switch(bVar3 & 0x7f) {
        case 0x68:
          if (*(char *)(DAT_803dee98 + 0xee0) != '\0') {
            FUN_8026dfe4((uint *)(DAT_803dee98 + 0xeb4),*(uint **)(DAT_803dee98 + 0xedc),'\x01');
            *(undefined *)(DAT_803dee98 + 0xee0) = 0;
          }
          break;
        case 0x69:
          (&DAT_803bd8f0)[uVar16 + DAT_803deea0 * 0x10] = bVar2 & 0x7f;
          break;
        case 0x6a:
          (&DAT_803bd8f0)[uVar16 + DAT_803deea0 * 0x10] = (bVar2 & 0x7f) + 0x80;
          break;
        default:
          FUN_80281a9c(bVar3 & 0x7f,bVar4,(byte)DAT_803deea0,bVar2 & 0x7f);
          break;
        case 0x79:
          FUN_80282194(uVar16,DAT_803deea0 & 0xff,0);
          break;
        case 0x7b:
          FUN_8026c9b4();
        }
      }
    }
    else {
      iVar9 = *(int *)(param_1 + 0x10);
      *(short *)(iVar9 + 0x20) = *(short *)(iVar9 + 0x20) + *(short *)(iVar9 + 0x22);
      if (*(byte **)(iVar9 + 0x1c) == (byte *)0x0) {
        *(undefined4 *)(iVar9 + 0x24) = 0x7fffffff;
      }
      else {
        pbVar8 = FUN_8026e518(*(byte **)(iVar9 + 0x1c),&local_2c,(short *)(iVar9 + 0x22));
        *(byte **)(iVar9 + 0x1c) = pbVar8;
        if (pbVar8 == (byte *)0x0) {
          *(undefined4 *)(iVar9 + 0x24) = 0x7fffffff;
        }
        else {
          *(uint *)(iVar9 + 0x24) = *(int *)(iVar9 + 0x24) + (uint)local_2c;
        }
      }
      FUN_8028206c(1,*(byte *)(iVar9 + 0x28),(byte)DAT_803deea0,(uint)*(ushort *)(iVar9 + 0x20));
    }
  }
  else if (bVar2 == 4) {
    puVar13 = *(undefined4 **)(param_1 + 0xc);
    iVar9 = *(int *)(DAT_803dee98 + 0x118);
    iVar9 = iVar9 + *(int *)(*(int *)(iVar9 + 4) + iVar9 + (uint)*(ushort *)(puVar13 + 2) * 4);
    puVar15 = (undefined4 *)(DAT_803dee98 + (uint)*(byte *)(param_1 + 0x15) * 0x2c + 0x364);
    puVar15[2] = iVar9 + 0xc;
    *puVar15 = 0;
    puVar15[1] = *puVar13;
    puVar15[3] = puVar13;
    if (*(int *)(iVar9 + 4) == 0) {
      puVar15[6] = 0x7fffffff;
    }
    else {
      pbVar8 = FUN_8026e518((byte *)(*(int *)(iVar9 + 4) + *(int *)(DAT_803dee98 + 0x118)),local_26,
                            (short *)((int)puVar15 + 0x16));
      puVar15[4] = pbVar8;
      if (pbVar8 == (byte *)0x0) {
        puVar15[6] = 0x7fffffff;
      }
      else {
        puVar15[6] = (uint)local_26[0];
      }
    }
    *(undefined2 *)(puVar15 + 5) = 0x2000;
    if (*(int *)(iVar9 + 8) == 0) {
      puVar15[9] = 0x7fffffff;
    }
    else {
      pbVar8 = FUN_8026e518((byte *)(*(int *)(iVar9 + 8) + *(int *)(DAT_803dee98 + 0x118)),&local_28
                            ,(short *)((int)puVar15 + 0x22));
      puVar15[7] = pbVar8;
      if (pbVar8 == (byte *)0x0) {
        puVar15[9] = 0x7fffffff;
      }
      else {
        puVar15[9] = (uint)local_28;
      }
    }
    *(undefined2 *)(puVar15 + 8) = 0;
    *(undefined *)(puVar15 + 10) =
         *(undefined *)
          (*(int *)(*(int *)(DAT_803dee98 + 0x118) + 8) +
          *(int *)(DAT_803dee98 + 0x118) + (uint)*(byte *)(param_1 + 0x15));
    iVar9 = DAT_803dee98;
    uVar10 = (uint)*(byte *)(puVar13 + 1);
    if (uVar10 != 0xff) {
      uVar16 = (uint)*(byte *)(puVar15 + 10);
      (&DAT_803bd8f0)[uVar16 + DAT_803deea0 * 0x10] = 0xffff;
      if (uVar16 == 9) {
        uVar10 = (uint)*(byte *)(iVar9 + uVar10 + 0x98);
        if (uVar10 != 0xff) {
          iVar6 = uVar10 * 6;
          *(undefined2 *)(iVar9 + 0xe94) = *(undefined2 *)(*(int *)(iVar9 + 0x94) + iVar6);
          *(undefined *)(iVar9 + 0xe96) = *(undefined *)(*(int *)(iVar9 + 0x94) + iVar6 + 2);
          *(undefined *)(iVar9 + 0xe97) = *(undefined *)(*(int *)(iVar9 + 0x94) + iVar6 + 3);
        }
      }
      else {
        uVar10 = (uint)*(byte *)(iVar9 + uVar10 + 0x14);
        if (uVar10 != 0xff) {
          iVar12 = uVar10 * 6;
          iVar6 = iVar9 + uVar16 * 4;
          *(undefined2 *)(iVar6 + 0xe70) = *(undefined2 *)(*(int *)(iVar9 + 0x10) + iVar12);
          *(undefined *)(iVar6 + 0xe72) = *(undefined *)(*(int *)(iVar9 + 0x10) + iVar12 + 2);
          *(undefined *)(iVar6 + 0xe73) = *(undefined *)(*(int *)(iVar9 + 0x10) + iVar12 + 3);
        }
      }
    }
    if (*(byte *)((int)puVar13 + 5) != 0xff) {
      FUN_80281a9c(7,*(byte *)(puVar15 + 10),(byte)DAT_803deea0,*(byte *)((int)puVar13 + 5));
    }
  }
  else if (bVar2 < 4) {
    *param_3 = *param_3 | 1;
    return 0;
  }
  iVar9 = FUN_8026e5bc(*(byte *)(param_1 + 0x15));
  return iVar9;
}

