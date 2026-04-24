// Function: FUN_801fc420
// Entry: 801fc420
// Size: 1348 bytes

/* WARNING: Removing unreachable block (ram,0x801fc500) */

void FUN_801fc420(void)

{
  uint uVar1;
  char cVar2;
  byte bVar3;
  float fVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  short *psVar9;
  undefined8 local_20;
  
  uVar5 = FUN_8028683c();
  psVar9 = *(short **)(uVar5 + 0xb8);
  cVar2 = *(char *)((int)psVar9 + 3);
  if (cVar2 == '\n') {
    uVar6 = FUN_80020078((int)*psVar9);
    if (uVar6 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,uVar5,0xffffffff);
    }
  }
  else {
    fVar4 = *(float *)(uVar5 + 0xc);
    uVar6 = (uint)fVar4;
    uVar1 = (uint)*(float *)(uVar5 + 0x14);
    uVar7 = (uint)*(float *)(*(int *)(uVar5 + 0x4c) + 8);
    uVar8 = (uint)*(float *)(*(int *)(uVar5 + 0x4c) + 0x10);
    if (cVar2 != 'c') {
      if (*(short *)(uVar5 + 0x46) == 0x3c0) {
        FUN_801fc100(uVar5);
      }
      else {
        bVar3 = *(byte *)(psVar9 + 1);
        if (bVar3 == 3) {
          if ((cVar2 == '\x03') && (uVar7 = uVar7 - 0x3c, (int)uVar7 < (int)uVar6)) {
            *(float *)(uVar5 + 0xc) = fVar4 - FLOAT_803dc074;
            if ((int)*(float *)(uVar5 + 0xc) <= (int)uVar7) {
              local_20 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              *(float *)(uVar5 + 0xc) = (float)(local_20 - DOUBLE_803e6da8);
              *(undefined *)(psVar9 + 1) = 1;
              psVar9[2] = 200;
            }
          }
          else {
            uVar8 = uVar8 - 0x3c;
            if (((int)uVar8 < (int)uVar1) &&
               (*(float *)(uVar5 + 0x14) = *(float *)(uVar5 + 0x14) - FLOAT_803dc074,
               (int)*(float *)(uVar5 + 0x14) <= (int)uVar8)) {
              local_20 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
              *(float *)(uVar5 + 0x14) = (float)(local_20 - DOUBLE_803e6da8);
              *(undefined *)(psVar9 + 1) = 1;
              psVar9[2] = 200;
            }
          }
        }
        else if (bVar3 < 3) {
          if (bVar3 == 1) {
            if (psVar9[2] == 0) {
              if (cVar2 == '\0') {
                if (uVar1 == uVar8 - 0x3c) {
                  *(undefined *)(psVar9 + 1) = 2;
                  FUN_8000bb38(uVar5,0x115);
                }
                if (uVar1 == uVar8) {
                  *(undefined *)(psVar9 + 1) = 3;
                  FUN_8000bb38(uVar5,0x115);
                }
              }
              else if (cVar2 == '\x03') {
                if (uVar6 == uVar7 - 0x3c) {
                  *(undefined *)(psVar9 + 1) = 2;
                  FUN_8000bb38(uVar5,0x115);
                }
                if (uVar6 == uVar7) {
                  *(undefined *)(psVar9 + 1) = 3;
                  FUN_8000bb38(uVar5,0x115);
                }
              }
              else {
                if (uVar1 == uVar8 + 0x3c) {
                  *(undefined *)(psVar9 + 1) = 4;
                  FUN_8000bb38(uVar5,0x115);
                }
                if (uVar1 == uVar8) {
                  *(undefined *)(psVar9 + 1) = 5;
                  FUN_8000bb38(uVar5,0x115);
                }
              }
            }
            else {
              psVar9[2] = psVar9[2] - (short)(int)FLOAT_803dc074;
              if (psVar9[2] < 1) {
                psVar9[2] = 0;
              }
            }
          }
          else if (bVar3 == 0) {
            uVar5 = FUN_80020078((int)*psVar9);
            if (uVar5 != 0) {
              *(undefined *)(psVar9 + 1) = 1;
            }
          }
          else if ((cVar2 == '\x03') && ((int)uVar6 < (int)uVar7)) {
            *(float *)(uVar5 + 0xc) = fVar4 + FLOAT_803dc074;
            if ((int)uVar7 <= (int)*(float *)(uVar5 + 0xc)) {
              local_20 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              *(float *)(uVar5 + 0xc) = (float)(local_20 - DOUBLE_803e6da8);
              *(undefined *)(psVar9 + 1) = 1;
            }
          }
          else if (((int)uVar1 < (int)uVar8) &&
                  (*(float *)(uVar5 + 0x14) = *(float *)(uVar5 + 0x14) + FLOAT_803dc074,
                  (int)uVar8 <= (int)*(float *)(uVar5 + 0x14))) {
            local_20 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
            *(float *)(uVar5 + 0x14) = (float)(local_20 - DOUBLE_803e6da8);
            *(undefined *)(psVar9 + 1) = 1;
          }
        }
        else if (bVar3 == 5) {
          if ((cVar2 == '\x03') && (uVar7 = uVar7 + 0x3c, (int)uVar6 < (int)uVar7)) {
            *(float *)(uVar5 + 0xc) = fVar4 + FLOAT_803dc074;
            if ((int)uVar7 <= (int)*(float *)(uVar5 + 0xc)) {
              local_20 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              *(float *)(uVar5 + 0xc) = (float)(local_20 - DOUBLE_803e6da8);
              *(undefined *)(psVar9 + 1) = 1;
              psVar9[2] = 200;
            }
          }
          else {
            uVar8 = uVar8 + 0x3c;
            if (((int)uVar1 < (int)uVar8) &&
               (*(float *)(uVar5 + 0x14) = *(float *)(uVar5 + 0x14) + FLOAT_803dc074,
               (int)uVar8 <= (int)*(float *)(uVar5 + 0x14))) {
              local_20 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
              *(float *)(uVar5 + 0x14) = (float)(local_20 - DOUBLE_803e6da8);
              *(undefined *)(psVar9 + 1) = 1;
              psVar9[2] = 200;
            }
          }
        }
        else if (bVar3 < 5) {
          if ((cVar2 == '\x03') && ((int)uVar7 < (int)uVar6)) {
            *(float *)(uVar5 + 0xc) = fVar4 - FLOAT_803dc074;
            if ((int)*(float *)(uVar5 + 0xc) <= (int)uVar7) {
              local_20 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              *(float *)(uVar5 + 0xc) = (float)(local_20 - DOUBLE_803e6da8);
              *(undefined *)(psVar9 + 1) = 1;
            }
          }
          else if (((int)uVar8 < (int)uVar1) &&
                  (*(float *)(uVar5 + 0x14) = *(float *)(uVar5 + 0x14) - FLOAT_803dc074,
                  (int)*(float *)(uVar5 + 0x14) <= (int)uVar8)) {
            local_20 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
            *(float *)(uVar5 + 0x14) = (float)(local_20 - DOUBLE_803e6da8);
            *(undefined *)(psVar9 + 1) = 1;
          }
        }
      }
    }
  }
  FUN_80286888();
  return;
}

