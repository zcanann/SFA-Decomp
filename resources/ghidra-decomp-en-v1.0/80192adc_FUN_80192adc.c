// Function: FUN_80192adc
// Entry: 80192adc
// Size: 1548 bytes

/* WARNING: Removing unreachable block (ram,0x80192d4c) */

void FUN_80192adc(void)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined uVar7;
  byte bVar8;
  int *piVar9;
  int iVar10;
  
  iVar4 = FUN_802860dc();
  iVar10 = *(int *)(iVar4 + 0x4c);
  piVar9 = *(int **)(iVar4 + 0xb8);
  bVar1 = *(byte *)(iVar10 + 0x20);
  bVar8 = bVar1 & 3;
  FUN_8005b2fc((double)*(float *)(iVar4 + 0xc),(double)*(float *)(iVar4 + 0x10),
               (double)*(float *)(iVar4 + 0x14));
  iVar5 = FUN_8005aeec();
  if (iVar5 == 0) {
    *(undefined *)(piVar9 + 6) = 0;
  }
  else if ((*(ushort *)(iVar5 + 4) & 8) != 0) {
    if (*piVar9 == 0) {
      *(undefined *)((int)piVar9 + 0x16) = *(undefined *)(iVar10 + 0x1e);
      if (*piVar9 == 0) {
        *(undefined *)((int)piVar9 + 0x16) = 0;
      }
      fVar2 = FLOAT_803e3f7c;
      if (*(char *)((int)piVar9 + 0x16) == '\0') goto LAB_801930d0;
      piVar9[1] = (int)FLOAT_803e3f7c;
      piVar9[2] = (int)fVar2;
      piVar9[3] = (int)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar10 + 0x22)) -
                              DOUBLE_803e3f88);
      if (*(short *)(iVar10 + 0x18) == -1) {
        *(undefined *)((int)piVar9 + 0x17) = 1;
      }
      else {
        uVar7 = FUN_8001ffb4();
        *(undefined *)((int)piVar9 + 0x17) = uVar7;
      }
      *(ushort *)(piVar9 + 5) = (ushort)*(byte *)(iVar10 + 0x1c);
      if ((*(short *)(iVar10 + 0x1a) != -1) && (iVar6 = FUN_8001ffb4(), iVar6 != 0)) {
        *(ushort *)(piVar9 + 5) = (ushort)*(byte *)(iVar10 + 0x1d);
        piVar9[1] = (int)(FLOAT_803e3f78 + (float)piVar9[3]);
        *(undefined *)((int)piVar9 + 0x17) = 1;
      }
      if (bVar8 == 3) {
        iVar6 = FUN_80023cc8(*piVar9 << 2,5,0);
        piVar9[4] = iVar6;
      }
      *(ushort *)(iVar5 + 4) = *(ushort *)(iVar5 + 4) ^ 1;
      *(ushort *)(iVar5 + 4) = *(ushort *)(iVar5 + 4) ^ 1;
    }
    if (*(char *)((int)piVar9 + 0x16) != '\0') {
      if (bVar8 == 2) {
        uVar7 = FUN_8001ffb4((int)*(short *)(iVar10 + 0x18));
        *(undefined *)((int)piVar9 + 0x17) = uVar7;
        if (('\x02' < *(char *)(piVar9 + 6)) &&
           (*(char *)((int)piVar9 + 0x17) != *(char *)((int)piVar9 + 0x19))) {
          if ((int)(uint)*(byte *)(iVar10 + 0x20) >> 2 != 0) {
            FUN_8000bb18(iVar4,*(undefined2 *)(iVar10 + 0x24));
          }
          *(undefined *)(piVar9 + 6) = 0;
          *(undefined *)((int)piVar9 + 0x19) = *(undefined *)((int)piVar9 + 0x17);
        }
        if ('\x02' < *(char *)(piVar9 + 6)) goto LAB_801930d0;
      }
      else {
        if ('\x02' < *(char *)(piVar9 + 6)) goto LAB_801930d0;
        if (*(char *)((int)piVar9 + 0x17) == '\0') {
          uVar7 = FUN_8001ffb4((int)*(short *)(iVar10 + 0x18));
          *(undefined *)((int)piVar9 + 0x17) = uVar7;
          if (*(char *)((int)piVar9 + 0x17) == '\0') goto LAB_801930d0;
          if ((int)(uint)*(byte *)(iVar10 + 0x20) >> 2 != 0) {
            FUN_8000bb18(iVar4,*(undefined2 *)(iVar10 + 0x24));
          }
        }
      }
      if (bVar8 == 2) {
        if (*(char *)((int)piVar9 + 0x17) == '\0') {
          if (*(byte *)(iVar10 + 0x1d) < *(byte *)(iVar10 + 0x1c)) {
            *(ushort *)(piVar9 + 5) =
                 *(short *)(piVar9 + 5) + (short)*(char *)(iVar10 + 0x1f) * (ushort)DAT_803db410;
            if ((short)(ushort)*(byte *)(iVar10 + 0x1c) <= *(short *)(piVar9 + 5)) {
              *(ushort *)(piVar9 + 5) = (ushort)*(byte *)(iVar10 + 0x1c);
              if (*(short *)(iVar10 + 0x1a) != -1) {
                FUN_800200e8((int)*(short *)(iVar10 + 0x1a),0);
              }
              *(char *)(piVar9 + 6) = *(char *)(piVar9 + 6) + '\x01';
            }
          }
          else {
            *(ushort *)(piVar9 + 5) =
                 *(short *)(piVar9 + 5) - (short)*(char *)(iVar10 + 0x1f) * (ushort)DAT_803db410;
            if (*(short *)(piVar9 + 5) <= (short)(ushort)*(byte *)(iVar10 + 0x1c)) {
              *(ushort *)(piVar9 + 5) = (ushort)*(byte *)(iVar10 + 0x1c);
              if (*(short *)(iVar10 + 0x1a) != -1) {
                FUN_800200e8((int)*(short *)(iVar10 + 0x1a),0);
              }
              *(char *)(piVar9 + 6) = *(char *)(piVar9 + 6) + '\x01';
            }
          }
        }
        else if (*(byte *)(iVar10 + 0x1d) < *(byte *)(iVar10 + 0x1c)) {
          *(ushort *)(piVar9 + 5) =
               *(short *)(piVar9 + 5) - (short)*(char *)(iVar10 + 0x1f) * (ushort)DAT_803db410;
          if (*(short *)(piVar9 + 5) <= (short)(ushort)*(byte *)(iVar10 + 0x1d)) {
            *(ushort *)(piVar9 + 5) = (ushort)*(byte *)(iVar10 + 0x1d);
            if (*(short *)(iVar10 + 0x1a) != -1) {
              FUN_800200e8((int)*(short *)(iVar10 + 0x1a),1);
            }
            *(char *)(piVar9 + 6) = *(char *)(piVar9 + 6) + '\x01';
          }
        }
        else {
          *(ushort *)(piVar9 + 5) =
               *(short *)(piVar9 + 5) + (short)*(char *)(iVar10 + 0x1f) * (ushort)DAT_803db410;
          if ((short)(ushort)*(byte *)(iVar10 + 0x1d) <= *(short *)(piVar9 + 5)) {
            *(ushort *)(piVar9 + 5) = (ushort)*(byte *)(iVar10 + 0x1d);
            if (*(short *)(iVar10 + 0x1a) != -1) {
              FUN_800200e8((int)*(short *)(iVar10 + 0x1a),1);
            }
            *(char *)(piVar9 + 6) = *(char *)(piVar9 + 6) + '\x01';
          }
        }
      }
      else if (bVar8 < 2) {
        if ((bVar1 & 3) == 0) {
          if (*(byte *)(iVar10 + 0x1d) < *(byte *)(iVar10 + 0x1c)) {
            *(ushort *)(piVar9 + 5) =
                 *(short *)(piVar9 + 5) - (short)*(char *)(iVar10 + 0x1f) * (ushort)DAT_803db410;
            if (*(short *)(piVar9 + 5) <= (short)(ushort)*(byte *)(iVar10 + 0x1d)) {
              *(ushort *)(piVar9 + 5) = (ushort)*(byte *)(iVar10 + 0x1d);
              if (*(short *)(iVar10 + 0x1a) != -1) {
                FUN_800200e8((int)*(short *)(iVar10 + 0x1a),1);
              }
              *(char *)(piVar9 + 6) = *(char *)(piVar9 + 6) + '\x01';
            }
          }
          else {
            *(ushort *)(piVar9 + 5) =
                 *(short *)(piVar9 + 5) + (short)*(char *)(iVar10 + 0x1f) * (ushort)DAT_803db410;
            if ((short)(ushort)*(byte *)(iVar10 + 0x1d) <= *(short *)(piVar9 + 5)) {
              *(ushort *)(piVar9 + 5) = (ushort)*(byte *)(iVar10 + 0x1d);
              if (*(short *)(iVar10 + 0x1a) != -1) {
                FUN_800200e8((int)*(short *)(iVar10 + 0x1a),1);
              }
              *(char *)(piVar9 + 6) = *(char *)(piVar9 + 6) + '\x01';
            }
          }
        }
        else if (*(byte *)(iVar10 + 0x1d) < *(byte *)(iVar10 + 0x1c)) {
          *(ushort *)(piVar9 + 5) =
               *(short *)(piVar9 + 5) - (short)*(char *)(iVar10 + 0x1f) * (ushort)DAT_803db410;
          if (*(short *)(piVar9 + 5) < (short)(ushort)*(byte *)(iVar10 + 0x1d)) {
            *(ushort *)(piVar9 + 5) =
                 (ushort)*(byte *)(iVar10 + 0x1c) -
                 ((ushort)*(byte *)(iVar10 + 0x1d) - *(short *)(piVar9 + 5));
          }
        }
        else {
          *(ushort *)(piVar9 + 5) =
               *(short *)(piVar9 + 5) + (short)*(char *)(iVar10 + 0x1f) * (ushort)DAT_803db410;
          if ((short)(ushort)*(byte *)(iVar10 + 0x1c) < *(short *)(piVar9 + 5)) {
            *(ushort *)(piVar9 + 5) =
                 (ushort)*(byte *)(iVar10 + 0x1d) +
                 (*(short *)(piVar9 + 5) - (ushort)*(byte *)(iVar10 + 0x1d));
          }
        }
      }
      else if (bVar8 < 4) {
        uVar3 = (uint)*(char *)(iVar10 + 0x1f);
        if ((int)uVar3 < 0) {
          uVar3 = -uVar3;
        }
        piVar9[1] = (int)(((float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e3f90
                                  ) / FLOAT_803e3f80) * FLOAT_803db414 + (float)piVar9[1]);
        if ((float)piVar9[3] < (float)piVar9[1]) {
          piVar9[1] = piVar9[3];
          FUN_800200e8((int)*(short *)(iVar10 + 0x1a),1);
          *(char *)(piVar9 + 6) = *(char *)(piVar9 + 6) + '\x01';
        }
        piVar9[2] = (int)((float)piVar9[1] - FLOAT_803e3f84);
      }
    }
  }
LAB_801930d0:
  FUN_80286128();
  return;
}

