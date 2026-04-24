// Function: FUN_8017adb4
// Entry: 8017adb4
// Size: 1600 bytes

void FUN_8017adb4(void)

{
  char cVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  bool bVar9;
  byte bVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  int iVar14;
  char *pcVar15;
  int iVar16;
  int iVar17;
  double dVar18;
  float local_58;
  undefined auStack84 [4];
  undefined2 local_50;
  undefined2 local_4e;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  undefined4 local_38;
  uint uStack52;
  
  iVar5 = FUN_802860cc();
  iVar16 = *(int *)(iVar5 + 0x4c);
  pcVar15 = *(char **)(iVar5 + 0xb8);
  if (pcVar15[0x84] < '\0') {
    if (((byte)pcVar15[0x84] >> 5 & 1) == 0) {
      *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) | 8;
    }
    else {
      *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) & 0xf7;
    }
  }
  else {
    *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) | 8;
  }
  if ((*(short *)(iVar16 + 0x20) == -1) || (iVar6 = FUN_8001ffb4(), iVar6 != 0)) {
    cVar1 = *pcVar15;
    *pcVar15 = cVar1 + -1;
    if ((char)(cVar1 + -1) < '\0') {
      *pcVar15 = '\0';
    }
    local_58 = FLOAT_803e3758;
    iVar6 = FUN_80036e58(5,iVar5,&local_58);
    if (iVar6 != 0) {
      *pcVar15 = '\x05';
    }
    if ('\0' < *(char *)(*(int *)(iVar5 + 0x58) + 0x10f)) {
      iVar17 = 0;
      for (iVar14 = 0; iVar14 < *(char *)(*(int *)(iVar5 + 0x58) + 0x10f); iVar14 = iVar14 + 1) {
        iVar11 = *(int *)(*(int *)(iVar5 + 0x58) + iVar17 + 0x100);
        if ((((*(short *)(iVar11 + 0x44) == 1) || (*(short *)(iVar11 + 0x44) == 2)) ||
            (*(short *)(iVar11 + 0x46) == 0x754)) || (*(short *)(iVar11 + 0x46) == 0x6d)) {
          bVar9 = true;
        }
        else {
          bVar9 = false;
        }
        if ((bVar9) && (iVar11 != iVar6)) {
          uStack52 = (uint)*(byte *)(iVar16 + 0x1d);
          local_38 = 0x43300000;
          if ((float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e3770) <
              *(float *)(iVar11 + 0x10) - *(float *)(iVar5 + 0x10)) {
            iVar12 = *(int *)(iVar5 + 0xb8);
            uVar13 = 0;
            if (((*(byte *)(iVar12 + 0x84) >> 6 & 1) == 0) ||
               (iVar7 = FUN_8002b9ec(), iVar11 == iVar7)) {
              for (; (uVar4 = uVar13 & 0xff, *(int *)(iVar12 + uVar4 * 4 + 4) != 0 && (uVar4 != 9));
                  uVar13 = uVar13 + 1) {
              }
              *(int *)(iVar12 + uVar4 * 4 + 4) = iVar11;
              iVar12 = iVar12 + uVar4 * 8;
              *(undefined4 *)(iVar12 + 0x2c) = *(undefined4 *)(iVar11 + 0xc);
              *(undefined4 *)(iVar12 + 0x30) = *(undefined4 *)(iVar11 + 0x14);
            }
          }
        }
        iVar17 = iVar17 + 4;
      }
    }
    iVar6 = *(int *)(iVar5 + 0xb8);
    bVar9 = false;
    for (bVar10 = 0; bVar10 < 10; bVar10 = bVar10 + 1) {
      iVar17 = (uint)bVar10 * 4 + 4;
      iVar14 = *(int *)(iVar6 + iVar17);
      if (iVar14 != 0) {
        iVar11 = iVar6 + (uint)bVar10 * 8;
        if ((*(float *)(iVar11 + 0x2c) == *(float *)(iVar14 + 0xc)) &&
           (*(float *)(iVar11 + 0x30) == *(float *)(iVar14 + 0x14))) {
          bVar9 = true;
        }
        else {
          *(undefined4 *)(iVar6 + iVar17) = 0;
        }
      }
    }
    if (bVar9) {
      *pcVar15 = '\x05';
    }
    bVar9 = false;
    if ((*pcVar15 == '\0') || (((byte)pcVar15[0x84] >> 4 & 1) != 0)) {
      if (((byte)pcVar15[0x84] >> 4 & 1) == 0) {
        if (*(float *)(iVar5 + 0x10) < *(float *)(pcVar15 + 0x7c)) {
          *(float *)(iVar5 + 0x10) =
               *(float *)(pcVar15 + 0x80) * FLOAT_803db414 + *(float *)(iVar5 + 0x10);
          if (*(float *)(iVar5 + 0x10) <= *(float *)(pcVar15 + 0x7c)) {
            bVar9 = true;
          }
          else {
            *(float *)(iVar5 + 0x10) = *(float *)(pcVar15 + 0x7c);
            FUN_800200e8((int)*(short *)(iVar16 + 0x1a),0);
          }
        }
      }
      else {
        iVar6 = FUN_8001ffb4((int)*(short *)(iVar16 + 0x1a));
        if (iVar6 == 0) {
          puVar8 = (undefined4 *)FUN_800394ac(iVar5,0,0);
          if (puVar8 != (undefined4 *)0x0) {
            *puVar8 = 0;
          }
          pcVar15[0x84] = pcVar15[0x84] & 0xef;
          pcVar15[0x84] = pcVar15[0x84] & 0xdfU | 0x20;
        }
      }
    }
    else {
      if (pcVar15[0x84] < '\0') {
        FUN_8002b9ec();
        iVar6 = FUN_80295c5c();
        if (iVar6 != 0) {
          pcVar15[0x84] = pcVar15[0x84] & 0xdf;
        }
      }
      if (((byte)pcVar15[0x84] >> 5 & 1) == 0) {
        uStack52 = (uint)*(byte *)(iVar16 + 0x1c);
        local_38 = 0x43300000;
        fVar3 = *(float *)(pcVar15 + 0x7c) -
                (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e3770);
        fVar2 = *(float *)(iVar5 + 0x10);
        if (fVar3 <= fVar2) {
          *(float *)(iVar5 + 0x10) = -(*(float *)(pcVar15 + 0x80) * FLOAT_803db414 - fVar2);
          if (fVar3 <= *(float *)(iVar5 + 0x10)) {
            bVar9 = true;
          }
          else {
            *(float *)(iVar5 + 0x10) = fVar3;
            FUN_800200e8((int)*(short *)(iVar16 + 0x1a),1);
            if (pcVar15[0x84] < '\0') {
              puVar8 = (undefined4 *)FUN_800394ac(iVar5,0,0);
              if (puVar8 != (undefined4 *)0x0) {
                *puVar8 = 0x100;
              }
              pcVar15[0x84] = pcVar15[0x84] & 0xefU | 0x10;
            }
          }
        }
        else {
          *(float *)(iVar5 + 0x10) = *(float *)(pcVar15 + 0x80) * FLOAT_803db414 + fVar2;
          if (fVar3 < *(float *)(iVar5 + 0x10)) {
            *(float *)(iVar5 + 0x10) = fVar3;
          }
          FUN_800200e8((int)*(short *)(iVar16 + 0x1a),1);
          if (pcVar15[0x84] < '\0') {
            puVar8 = (undefined4 *)FUN_800394ac(iVar5,0,0);
            if (puVar8 != (undefined4 *)0x0) {
              *puVar8 = 0x100;
            }
            pcVar15[0x84] = pcVar15[0x84] & 0xefU | 0x10;
          }
        }
      }
      else {
        *(float *)(iVar5 + 0x10) =
             *(float *)(pcVar15 + 0x80) * FLOAT_803db414 + *(float *)(iVar5 + 0x10);
        if (*(float *)(iVar5 + 0x10) <= *(float *)(pcVar15 + 0x7c)) {
          bVar9 = true;
        }
        else {
          *(float *)(iVar5 + 0x10) = *(float *)(pcVar15 + 0x7c);
        }
      }
    }
    if ((((*(ushort *)(iVar5 + 0xb0) & 0x800) != 0) && (((byte)pcVar15[0x84] >> 4 & 1) == 0)) &&
       (pcVar15[0x84] < '\0')) {
      iVar6 = FUN_8002b9ec();
      dVar18 = (double)FUN_80021704(iVar5 + 0x18,iVar6 + 0x18);
      if (dVar18 < (double)FLOAT_803e375c) {
        local_48 = FLOAT_803e3760;
        local_44 = FLOAT_803e3764;
        local_40 = FLOAT_803e3760;
        local_4c = FLOAT_803e3768;
        local_4e = 0x12;
        local_50 = 10;
        iVar6 = 0;
        do {
          (**(code **)(*DAT_803dca88 + 8))(iVar5,0x7c3,auStack84,2,0xffffffff,0);
          iVar6 = iVar6 + 1;
        } while (iVar6 < 3);
      }
    }
    if (bVar9) {
      FUN_8000bb18(iVar5,0x61);
    }
    else {
      FUN_8000b7bc(iVar5,8);
    }
    if (((*(char *)(iVar16 + 0x1e) != '\0') && (iVar6 = FUN_8002b9ac(), iVar6 != 0)) &&
       ((iVar16 = FUN_8001ffb4((int)*(short *)(iVar16 + 0x1a)), iVar16 == 0 &&
        (*(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) & 0xf7,
        (*(byte *)(iVar5 + 0xaf) & 4) != 0)))) {
      (**(code **)(**(int **)(iVar6 + 0x68) + 0x28))(iVar6,iVar5,1,3);
    }
  }
  FUN_80286118();
  return;
}

