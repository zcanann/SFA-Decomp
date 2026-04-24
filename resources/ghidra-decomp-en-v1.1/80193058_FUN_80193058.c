// Function: FUN_80193058
// Entry: 80193058
// Size: 1548 bytes

/* WARNING: Removing unreachable block (ram,0x801932c8) */

void FUN_80193058(void)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  byte bVar7;
  int *piVar8;
  int iVar9;
  
  uVar3 = FUN_80286840();
  iVar9 = *(int *)(uVar3 + 0x4c);
  piVar8 = *(int **)(uVar3 + 0xb8);
  bVar1 = *(byte *)(iVar9 + 0x20);
  bVar7 = bVar1 & 3;
  iVar4 = FUN_8005b478((double)*(float *)(uVar3 + 0xc),(double)*(float *)(uVar3 + 0x10));
  iVar4 = FUN_8005b068(iVar4);
  if (iVar4 == 0) {
    *(undefined *)(piVar8 + 6) = 0;
  }
  else if ((*(ushort *)(iVar4 + 4) & 8) != 0) {
    if (*piVar8 == 0) {
      *(undefined *)((int)piVar8 + 0x16) = *(undefined *)(iVar9 + 0x1e);
      if (*piVar8 == 0) {
        *(undefined *)((int)piVar8 + 0x16) = 0;
      }
      fVar2 = FLOAT_803e4c14;
      if (*(char *)((int)piVar8 + 0x16) == '\0') goto LAB_8019364c;
      piVar8[1] = (int)FLOAT_803e4c14;
      piVar8[2] = (int)fVar2;
      piVar8[3] = (int)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar9 + 0x22)) -
                              DOUBLE_803e4c20);
      if ((int)*(short *)(iVar9 + 0x18) == 0xffffffff) {
        *(undefined *)((int)piVar8 + 0x17) = 1;
      }
      else {
        uVar5 = FUN_80020078((int)*(short *)(iVar9 + 0x18));
        *(char *)((int)piVar8 + 0x17) = (char)uVar5;
      }
      *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1c);
      if (((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) &&
         (uVar5 = FUN_80020078((int)*(short *)(iVar9 + 0x1a)), uVar5 != 0)) {
        *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
        piVar8[1] = (int)(FLOAT_803e4c10 + (float)piVar8[3]);
        *(undefined *)((int)piVar8 + 0x17) = 1;
      }
      if (bVar7 == 3) {
        iVar6 = FUN_80023d8c(*piVar8 << 2,5);
        piVar8[4] = iVar6;
      }
      *(ushort *)(iVar4 + 4) = *(ushort *)(iVar4 + 4) ^ 1;
      *(ushort *)(iVar4 + 4) = *(ushort *)(iVar4 + 4) ^ 1;
    }
    if (*(char *)((int)piVar8 + 0x16) != '\0') {
      if (bVar7 == 2) {
        uVar5 = FUN_80020078((int)*(short *)(iVar9 + 0x18));
        *(char *)((int)piVar8 + 0x17) = (char)uVar5;
        if (('\x02' < *(char *)(piVar8 + 6)) &&
           (*(char *)((int)piVar8 + 0x17) != *(char *)((int)piVar8 + 0x19))) {
          if ((int)(uint)*(byte *)(iVar9 + 0x20) >> 2 != 0) {
            FUN_8000bb38(uVar3,*(ushort *)(iVar9 + 0x24));
          }
          *(undefined *)(piVar8 + 6) = 0;
          *(undefined *)((int)piVar8 + 0x19) = *(undefined *)((int)piVar8 + 0x17);
        }
        if ('\x02' < *(char *)(piVar8 + 6)) goto LAB_8019364c;
      }
      else {
        if ('\x02' < *(char *)(piVar8 + 6)) goto LAB_8019364c;
        if (*(char *)((int)piVar8 + 0x17) == '\0') {
          uVar5 = FUN_80020078((int)*(short *)(iVar9 + 0x18));
          *(char *)((int)piVar8 + 0x17) = (char)uVar5;
          if (*(char *)((int)piVar8 + 0x17) == '\0') goto LAB_8019364c;
          if ((int)(uint)*(byte *)(iVar9 + 0x20) >> 2 != 0) {
            FUN_8000bb38(uVar3,*(ushort *)(iVar9 + 0x24));
          }
        }
      }
      if (bVar7 == 2) {
        if (*(char *)((int)piVar8 + 0x17) == '\0') {
          if (*(byte *)(iVar9 + 0x1d) < *(byte *)(iVar9 + 0x1c)) {
            *(ushort *)(piVar8 + 5) =
                 *(short *)(piVar8 + 5) + (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
            if ((short)(ushort)*(byte *)(iVar9 + 0x1c) <= *(short *)(piVar8 + 5)) {
              *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1c);
              if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
                FUN_800201ac((int)*(short *)(iVar9 + 0x1a),0);
              }
              *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
            }
          }
          else {
            *(ushort *)(piVar8 + 5) =
                 *(short *)(piVar8 + 5) - (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
            if (*(short *)(piVar8 + 5) <= (short)(ushort)*(byte *)(iVar9 + 0x1c)) {
              *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1c);
              if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
                FUN_800201ac((int)*(short *)(iVar9 + 0x1a),0);
              }
              *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
            }
          }
        }
        else if (*(byte *)(iVar9 + 0x1d) < *(byte *)(iVar9 + 0x1c)) {
          *(ushort *)(piVar8 + 5) =
               *(short *)(piVar8 + 5) - (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
          if (*(short *)(piVar8 + 5) <= (short)(ushort)*(byte *)(iVar9 + 0x1d)) {
            *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
            if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
              FUN_800201ac((int)*(short *)(iVar9 + 0x1a),1);
            }
            *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
          }
        }
        else {
          *(ushort *)(piVar8 + 5) =
               *(short *)(piVar8 + 5) + (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
          if ((short)(ushort)*(byte *)(iVar9 + 0x1d) <= *(short *)(piVar8 + 5)) {
            *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
            if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
              FUN_800201ac((int)*(short *)(iVar9 + 0x1a),1);
            }
            *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
          }
        }
      }
      else if (bVar7 < 2) {
        if ((bVar1 & 3) == 0) {
          if (*(byte *)(iVar9 + 0x1d) < *(byte *)(iVar9 + 0x1c)) {
            *(ushort *)(piVar8 + 5) =
                 *(short *)(piVar8 + 5) - (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
            if (*(short *)(piVar8 + 5) <= (short)(ushort)*(byte *)(iVar9 + 0x1d)) {
              *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
              if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
                FUN_800201ac((int)*(short *)(iVar9 + 0x1a),1);
              }
              *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
            }
          }
          else {
            *(ushort *)(piVar8 + 5) =
                 *(short *)(piVar8 + 5) + (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
            if ((short)(ushort)*(byte *)(iVar9 + 0x1d) <= *(short *)(piVar8 + 5)) {
              *(ushort *)(piVar8 + 5) = (ushort)*(byte *)(iVar9 + 0x1d);
              if ((int)*(short *)(iVar9 + 0x1a) != 0xffffffff) {
                FUN_800201ac((int)*(short *)(iVar9 + 0x1a),1);
              }
              *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
            }
          }
        }
        else if (*(byte *)(iVar9 + 0x1d) < *(byte *)(iVar9 + 0x1c)) {
          *(ushort *)(piVar8 + 5) =
               *(short *)(piVar8 + 5) - (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
          if (*(short *)(piVar8 + 5) < (short)(ushort)*(byte *)(iVar9 + 0x1d)) {
            *(ushort *)(piVar8 + 5) =
                 (ushort)*(byte *)(iVar9 + 0x1c) -
                 ((ushort)*(byte *)(iVar9 + 0x1d) - *(short *)(piVar8 + 5));
          }
        }
        else {
          *(ushort *)(piVar8 + 5) =
               *(short *)(piVar8 + 5) + (short)*(char *)(iVar9 + 0x1f) * (ushort)DAT_803dc070;
          if ((short)(ushort)*(byte *)(iVar9 + 0x1c) < *(short *)(piVar8 + 5)) {
            *(short *)(piVar8 + 5) = *(short *)(piVar8 + 5);
          }
        }
      }
      else if (bVar7 < 4) {
        uVar3 = (uint)*(char *)(iVar9 + 0x1f);
        if ((int)uVar3 < 0) {
          uVar3 = -uVar3;
        }
        piVar8[1] = (int)(((float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e4c28
                                  ) / FLOAT_803e4c18) * FLOAT_803dc074 + (float)piVar8[1]);
        if ((float)piVar8[3] < (float)piVar8[1]) {
          piVar8[1] = piVar8[3];
          FUN_800201ac((int)*(short *)(iVar9 + 0x1a),1);
          *(char *)(piVar8 + 6) = *(char *)(piVar8 + 6) + '\x01';
        }
        piVar8[2] = (int)((float)piVar8[1] - FLOAT_803e4c1c);
      }
    }
  }
LAB_8019364c:
  FUN_8028688c();
  return;
}

