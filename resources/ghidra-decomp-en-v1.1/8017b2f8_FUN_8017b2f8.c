// Function: FUN_8017b2f8
// Entry: 8017b2f8
// Size: 1600 bytes

void FUN_8017b2f8(void)

{
  char cVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  undefined4 *puVar10;
  byte bVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  char *pcVar15;
  int iVar16;
  int iVar17;
  double dVar18;
  float local_58;
  undefined auStack_54 [4];
  undefined2 local_50;
  undefined2 local_4e;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  undefined4 local_38;
  uint uStack_34;
  
  uVar6 = FUN_80286830();
  iVar16 = *(int *)(uVar6 + 0x4c);
  pcVar15 = *(char **)(uVar6 + 0xb8);
  if (pcVar15[0x84] < '\0') {
    if (((byte)pcVar15[0x84] >> 5 & 1) == 0) {
      *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) | 8;
    }
    else {
      *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) & 0xf7;
    }
  }
  else {
    *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) | 8;
  }
  if (((int)*(short *)(iVar16 + 0x20) == 0xffffffff) ||
     (uVar7 = FUN_80020078((int)*(short *)(iVar16 + 0x20)), uVar7 != 0)) {
    cVar1 = *pcVar15;
    *pcVar15 = cVar1 + -1;
    if ((char)(cVar1 + -1) < '\0') {
      *pcVar15 = '\0';
    }
    local_58 = FLOAT_803e43f0;
    iVar8 = FUN_80036f50(5,uVar6,&local_58);
    if (iVar8 != 0) {
      *pcVar15 = '\x05';
    }
    if ('\0' < *(char *)(*(int *)(uVar6 + 0x58) + 0x10f)) {
      iVar17 = 0;
      for (iVar14 = 0; iVar14 < *(char *)(*(int *)(uVar6 + 0x58) + 0x10f); iVar14 = iVar14 + 1) {
        iVar12 = *(int *)(*(int *)(uVar6 + 0x58) + iVar17 + 0x100);
        if ((((*(short *)(iVar12 + 0x44) == 1) || (*(short *)(iVar12 + 0x44) == 2)) ||
            (*(short *)(iVar12 + 0x46) == 0x754)) || (*(short *)(iVar12 + 0x46) == 0x6d)) {
          bVar4 = true;
        }
        else {
          bVar4 = false;
        }
        if ((bVar4) && (iVar12 != iVar8)) {
          uStack_34 = (uint)*(byte *)(iVar16 + 0x1d);
          local_38 = 0x43300000;
          if ((float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4408) <
              *(float *)(iVar12 + 0x10) - *(float *)(uVar6 + 0x10)) {
            iVar13 = *(int *)(uVar6 + 0xb8);
            uVar7 = 0;
            if (((*(byte *)(iVar13 + 0x84) >> 6 & 1) == 0) ||
               (iVar9 = FUN_8002bac4(), iVar12 == iVar9)) {
              for (; (uVar5 = uVar7 & 0xff, *(int *)(iVar13 + uVar5 * 4 + 4) != 0 && (uVar5 != 9));
                  uVar7 = uVar7 + 1) {
              }
              *(int *)(iVar13 + uVar5 * 4 + 4) = iVar12;
              iVar13 = iVar13 + uVar5 * 8;
              *(undefined4 *)(iVar13 + 0x2c) = *(undefined4 *)(iVar12 + 0xc);
              *(undefined4 *)(iVar13 + 0x30) = *(undefined4 *)(iVar12 + 0x14);
            }
          }
        }
        iVar17 = iVar17 + 4;
      }
    }
    iVar8 = *(int *)(uVar6 + 0xb8);
    bVar4 = false;
    for (bVar11 = 0; bVar11 < 10; bVar11 = bVar11 + 1) {
      iVar17 = (uint)bVar11 * 4 + 4;
      iVar14 = *(int *)(iVar8 + iVar17);
      if (iVar14 != 0) {
        iVar12 = iVar8 + (uint)bVar11 * 8;
        if ((*(float *)(iVar12 + 0x2c) == *(float *)(iVar14 + 0xc)) &&
           (*(float *)(iVar12 + 0x30) == *(float *)(iVar14 + 0x14))) {
          bVar4 = true;
        }
        else {
          *(undefined4 *)(iVar8 + iVar17) = 0;
        }
      }
    }
    if (bVar4) {
      *pcVar15 = '\x05';
    }
    bVar4 = false;
    if ((*pcVar15 == '\0') || (((byte)pcVar15[0x84] >> 4 & 1) != 0)) {
      if (((byte)pcVar15[0x84] >> 4 & 1) == 0) {
        if (*(float *)(uVar6 + 0x10) < *(float *)(pcVar15 + 0x7c)) {
          *(float *)(uVar6 + 0x10) =
               *(float *)(pcVar15 + 0x80) * FLOAT_803dc074 + *(float *)(uVar6 + 0x10);
          if (*(float *)(uVar6 + 0x10) <= *(float *)(pcVar15 + 0x7c)) {
            bVar4 = true;
          }
          else {
            *(float *)(uVar6 + 0x10) = *(float *)(pcVar15 + 0x7c);
            FUN_800201ac((int)*(short *)(iVar16 + 0x1a),0);
          }
        }
      }
      else {
        uVar7 = FUN_80020078((int)*(short *)(iVar16 + 0x1a));
        if (uVar7 == 0) {
          puVar10 = (undefined4 *)FUN_800395a4(uVar6,0);
          if (puVar10 != (undefined4 *)0x0) {
            *puVar10 = 0;
          }
          pcVar15[0x84] = pcVar15[0x84] & 0xef;
          pcVar15[0x84] = pcVar15[0x84] & 0xdfU | 0x20;
        }
      }
    }
    else {
      if (pcVar15[0x84] < '\0') {
        iVar8 = FUN_8002bac4();
        iVar8 = FUN_802963bc(iVar8);
        if (iVar8 != 0) {
          pcVar15[0x84] = pcVar15[0x84] & 0xdf;
        }
      }
      if (((byte)pcVar15[0x84] >> 5 & 1) == 0) {
        uStack_34 = (uint)*(byte *)(iVar16 + 0x1c);
        local_38 = 0x43300000;
        fVar3 = *(float *)(pcVar15 + 0x7c) -
                (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4408);
        fVar2 = *(float *)(uVar6 + 0x10);
        if (fVar3 <= fVar2) {
          *(float *)(uVar6 + 0x10) = -(*(float *)(pcVar15 + 0x80) * FLOAT_803dc074 - fVar2);
          if (fVar3 <= *(float *)(uVar6 + 0x10)) {
            bVar4 = true;
          }
          else {
            *(float *)(uVar6 + 0x10) = fVar3;
            FUN_800201ac((int)*(short *)(iVar16 + 0x1a),1);
            if (pcVar15[0x84] < '\0') {
              puVar10 = (undefined4 *)FUN_800395a4(uVar6,0);
              if (puVar10 != (undefined4 *)0x0) {
                *puVar10 = 0x100;
              }
              pcVar15[0x84] = pcVar15[0x84] & 0xefU | 0x10;
            }
          }
        }
        else {
          *(float *)(uVar6 + 0x10) = *(float *)(pcVar15 + 0x80) * FLOAT_803dc074 + fVar2;
          if (fVar3 < *(float *)(uVar6 + 0x10)) {
            *(float *)(uVar6 + 0x10) = fVar3;
          }
          FUN_800201ac((int)*(short *)(iVar16 + 0x1a),1);
          if (pcVar15[0x84] < '\0') {
            puVar10 = (undefined4 *)FUN_800395a4(uVar6,0);
            if (puVar10 != (undefined4 *)0x0) {
              *puVar10 = 0x100;
            }
            pcVar15[0x84] = pcVar15[0x84] & 0xefU | 0x10;
          }
        }
      }
      else {
        *(float *)(uVar6 + 0x10) =
             *(float *)(pcVar15 + 0x80) * FLOAT_803dc074 + *(float *)(uVar6 + 0x10);
        if (*(float *)(uVar6 + 0x10) <= *(float *)(pcVar15 + 0x7c)) {
          bVar4 = true;
        }
        else {
          *(float *)(uVar6 + 0x10) = *(float *)(pcVar15 + 0x7c);
        }
      }
    }
    if ((((*(ushort *)(uVar6 + 0xb0) & 0x800) != 0) && (((byte)pcVar15[0x84] >> 4 & 1) == 0)) &&
       (pcVar15[0x84] < '\0')) {
      iVar8 = FUN_8002bac4();
      dVar18 = (double)FUN_800217c8((float *)(uVar6 + 0x18),(float *)(iVar8 + 0x18));
      if (dVar18 < (double)FLOAT_803e43f4) {
        local_48 = FLOAT_803e43f8;
        local_44 = FLOAT_803e43fc;
        local_40 = FLOAT_803e43f8;
        local_4c = FLOAT_803e4400;
        local_4e = 0x12;
        local_50 = 10;
        iVar8 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(uVar6,0x7c3,auStack_54,2,0xffffffff,0);
          iVar8 = iVar8 + 1;
        } while (iVar8 < 3);
      }
    }
    if (bVar4) {
      FUN_8000bb38(uVar6,0x61);
    }
    else {
      FUN_8000b7dc(uVar6,8);
    }
    if (((*(char *)(iVar16 + 0x1e) != '\0') && (iVar8 = FUN_8002ba84(), iVar8 != 0)) &&
       ((uVar7 = FUN_80020078((int)*(short *)(iVar16 + 0x1a)), uVar7 == 0 &&
        (*(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) & 0xf7,
        (*(byte *)(uVar6 + 0xaf) & 4) != 0)))) {
      (**(code **)(**(int **)(iVar8 + 0x68) + 0x28))(iVar8,uVar6,1,3);
    }
  }
  FUN_8028687c();
  return;
}

