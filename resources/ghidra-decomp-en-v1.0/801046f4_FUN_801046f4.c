// Function: FUN_801046f4
// Entry: 801046f4
// Size: 612 bytes

void FUN_801046f4(undefined4 param_1,undefined4 param_2,undefined param_3,float *param_4,
                 float *param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  int iVar7;
  undefined uVar9;
  int iVar8;
  int iVar10;
  undefined4 uVar11;
  int iVar12;
  ulonglong uVar13;
  int local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined auStack48 [48];
  
  uVar13 = FUN_802860dc();
  iVar7 = (int)(uVar13 >> 0x20);
  uVar11 = *(undefined4 *)(iVar7 + 0xa4);
  if ((uVar13 & 1) != 0) {
    *(float *)(iVar7 + 0x74) = FLOAT_803e1688;
    *(undefined *)(iVar7 + 0x84) = 0xff;
    *(undefined *)(iVar7 + 0x88) = param_3;
    uVar9 = FUN_800640cc(iVar7 + 0xb8,iVar7 + 0x18,1,0,0,0x10,0xffffffff,0xff,0);
    *(undefined *)(iVar7 + 0x142) = uVar9;
    local_3c = *(undefined4 *)(iVar7 + 0x18);
    local_38 = *(undefined4 *)(iVar7 + 0x1c);
    local_34 = *(undefined4 *)(iVar7 + 0x20);
    FUN_8006961c(auStack48,iVar7 + 0xb8,&local_3c,iVar7 + 0x74,1);
    FUN_800691c0(uVar11,auStack48,0x240,1);
    FUN_80067958(uVar11,iVar7 + 0xb8,&local_3c,1,iVar7 + 0x34,0);
    *(undefined4 *)(iVar7 + 0x18) = local_3c;
    *(undefined4 *)(iVar7 + 0x1c) = local_38;
    *(undefined4 *)(iVar7 + 0x20) = local_34;
  }
  if ((uVar13 & 2) != 0) {
    iVar8 = FUN_80065e50((double)*(float *)(iVar7 + 0x18),(double)*(float *)(iVar7 + 0x1c),
                         (double)*(float *)(iVar7 + 0x20),uVar11,&local_40,1,0x40);
    *param_4 = FLOAT_803e16d0;
    fVar5 = FLOAT_803e16d4;
    *param_5 = FLOAT_803e16d4;
    fVar2 = FLOAT_803e16b4;
    fVar6 = FLOAT_803e16ac;
    iVar10 = 0;
    iVar12 = iVar8;
    fVar3 = fVar5;
    if (0 < iVar8) {
      do {
        if ((*(float **)(local_40 + iVar10))[2] < fVar6) {
          fVar1 = **(float **)(local_40 + iVar10);
          if (*(float *)(iVar7 + 0x1c) - fVar2 < fVar1) {
            fVar4 = *(float *)(iVar7 + 0x1c) - fVar1;
            if (fVar4 < fVar6) {
              fVar4 = -fVar4;
            }
            if (fVar4 < fVar3) {
              *param_5 = fVar1;
              *(undefined4 *)(iVar7 + 300) = *(undefined4 *)(*(int *)(local_40 + iVar10) + 8);
              fVar3 = fVar4;
            }
          }
        }
        iVar10 = iVar10 + 4;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
    }
    fVar6 = FLOAT_803e16b4;
    fVar3 = FLOAT_803e16ac;
    iVar12 = 0;
    if (0 < iVar8) {
      do {
        if (fVar3 < (*(float **)(local_40 + iVar12))[2]) {
          fVar2 = **(float **)(local_40 + iVar12);
          if (fVar2 < fVar6 + *(float *)(iVar7 + 0x1c)) {
            fVar1 = *(float *)(iVar7 + 0x1c) - fVar2;
            if (fVar1 < fVar3) {
              fVar1 = -fVar1;
            }
            if (fVar1 < fVar5) {
              *param_4 = fVar2;
              *(undefined4 *)(iVar7 + 0x130) = *(undefined4 *)(*(int *)(local_40 + iVar12) + 8);
              fVar5 = fVar1;
            }
          }
        }
        iVar12 = iVar12 + 4;
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
    }
  }
  FUN_8000e034((double)*(float *)(iVar7 + 0x18),(double)*(float *)(iVar7 + 0x1c),
               (double)*(float *)(iVar7 + 0x20),iVar7 + 0xc,iVar7 + 0x10,iVar7 + 0x14,
               *(undefined4 *)(iVar7 + 0x30));
  FUN_80286128();
  return;
}

