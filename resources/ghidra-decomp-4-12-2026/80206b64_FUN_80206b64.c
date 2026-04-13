// Function: FUN_80206b64
// Entry: 80206b64
// Size: 792 bytes

void FUN_80206b64(void)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  byte bVar7;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar8;
  ushort uVar9;
  int iVar10;
  int iVar11;
  int local_28;
  int local_24 [9];
  
  uVar3 = FUN_80286840();
  iVar11 = *(int *)(uVar3 + 0x4c);
  iVar10 = *(int *)(uVar3 + 0xb8);
  uVar9 = 0xffff;
  bVar7 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(uVar3 + 0xac));
  if (bVar7 == 2) {
    uVar4 = FUN_80020078(0xe58);
    if (uVar4 != 0) {
      *(float *)(uVar3 + 0x10) = *(float *)(iVar11 + 0xc) - FLOAT_803e70a4;
      goto LAB_80206e64;
    }
  }
  else if ((bVar7 < 2) && (bVar7 != 0)) {
    if (5 < *(byte *)(iVar10 + 5)) goto LAB_80206e64;
    uVar4 = FUN_80020078(0xe57);
    if (uVar4 != 0) {
      *(float *)(uVar3 + 0x10) = *(float *)(iVar11 + 0xc) - FLOAT_803e70a4;
      goto LAB_80206e64;
    }
  }
  uVar4 = FUN_80020078(0x5e4);
  uVar5 = FUN_80020078(0x5e5);
  if ((uVar5 != 0) || ((uVar4 & 0xff) != (uint)*(byte *)(iVar10 + 7))) {
    *(undefined *)(iVar10 + 4) = 0;
  }
  *(char *)(iVar10 + 7) = (char)uVar4;
  if (*(int *)(iVar10 + 8) == 0) {
    iVar6 = FUN_8002e1f4(local_24,&local_28);
    for (; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
      iVar8 = *(int *)(iVar6 + local_24[0] * 4);
      if (*(short *)(iVar8 + 0x46) == 0x431) {
        *(int *)(iVar10 + 8) = iVar8;
        local_24[0] = local_28;
      }
    }
    if (*(int *)(iVar10 + 8) == 0) goto LAB_80206e64;
  }
  (**(code **)(**(int **)(*(int *)(iVar10 + 8) + 0x68) + 0x20))(*(int *)(iVar10 + 8),&DAT_8032a660);
  *(undefined *)(iVar10 + 6) = (&DAT_8032a660)[*(byte *)(iVar10 + 5)];
  if ((*(char *)(iVar10 + 4) == '\0') ||
     (*(float *)(uVar3 + 0x10) <= *(float *)(iVar11 + 0xc) - FLOAT_803e70a4)) {
    if (*(char *)(iVar10 + 6) != '\0') {
      if (*(char *)(iVar10 + 4) == '\0') {
        *(undefined4 *)(uVar3 + 0x10) = *(undefined4 *)(iVar11 + 0xc);
      }
      if ((*(char *)(iVar10 + 4) == '\0') && (iVar11 = FUN_8002bac4(), iVar11 != 0)) {
        fVar1 = *(float *)(uVar3 + 0x10) - *(float *)(iVar11 + 0x10);
        if (fVar1 < FLOAT_803e70b0) {
          fVar1 = fVar1 * FLOAT_803e70ac;
        }
        if (fVar1 < FLOAT_803e70b4) {
          fVar1 = *(float *)(iVar11 + 0xc) - (*(float *)(uVar3 + 0xc) - FLOAT_803e70b4);
          fVar2 = *(float *)(uVar3 + 0x14) - *(float *)(iVar11 + 0x14);
          if (fVar2 < FLOAT_803e70b0) {
            fVar2 = fVar2 * FLOAT_803e70ac;
          }
          if (fVar2 < FLOAT_803e70b8) {
            if (fVar1 < FLOAT_803e70bc) {
              if (fVar1 < FLOAT_803e70b4) {
                if (fVar1 < FLOAT_803e70c0) {
                  if (FLOAT_803e70b0 <= fVar1) {
                    uVar9 = 1;
                  }
                }
                else {
                  uVar9 = 2;
                }
              }
              else {
                uVar9 = 3;
              }
            }
            else {
              uVar9 = 4;
            }
            if (uVar9 == *(byte *)(iVar10 + 6)) {
              *(undefined *)(iVar10 + 4) = 1;
            }
            else {
              FUN_800201ac(0x5e5,1);
            }
          }
        }
      }
    }
  }
  else {
    FUN_8000da78(uVar3,0x1c8);
    *(float *)(uVar3 + 0x10) = *(float *)(uVar3 + 0x10) - FLOAT_803dc074 / FLOAT_803e70a8;
    fVar1 = *(float *)(iVar11 + 0xc) - FLOAT_803e70a4;
    if (*(float *)(uVar3 + 0x10) <= fVar1) {
      *(float *)(uVar3 + 0x10) = fVar1;
    }
  }
LAB_80206e64:
  FUN_8028688c();
  return;
}

