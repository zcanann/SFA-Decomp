// Function: FUN_801fbde8
// Entry: 801fbde8
// Size: 1348 bytes

/* WARNING: Removing unreachable block (ram,0x801fbec8) */

void FUN_801fbde8(void)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  byte bVar4;
  float fVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  short *psVar10;
  double local_20;
  
  iVar6 = FUN_802860d8();
  psVar10 = *(short **)(iVar6 + 0xb8);
  cVar3 = *(char *)((int)psVar10 + 3);
  if (cVar3 == '\n') {
    iVar7 = FUN_8001ffb4((int)*psVar10);
    if (iVar7 != 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,iVar6,0xffffffff);
    }
  }
  else {
    fVar5 = *(float *)(iVar6 + 0xc);
    uVar1 = (uint)fVar5;
    uVar2 = (uint)*(float *)(iVar6 + 0x14);
    uVar8 = (uint)*(float *)(*(int *)(iVar6 + 0x4c) + 8);
    uVar9 = (uint)*(float *)(*(int *)(iVar6 + 0x4c) + 0x10);
    if (cVar3 != 'c') {
      if (*(short *)(iVar6 + 0x46) == 0x3c0) {
        FUN_801fbac8();
      }
      else {
        bVar4 = *(byte *)(psVar10 + 1);
        if (bVar4 == 3) {
          if ((cVar3 == '\x03') && (uVar8 = uVar8 - 0x3c, (int)uVar8 < (int)uVar1)) {
            *(float *)(iVar6 + 0xc) = fVar5 - FLOAT_803db414;
            if ((int)*(float *)(iVar6 + 0xc) <= (int)uVar8) {
              local_20 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
              *(float *)(iVar6 + 0xc) = (float)(local_20 - DOUBLE_803e6110);
              *(undefined *)(psVar10 + 1) = 1;
              psVar10[2] = 200;
            }
          }
          else {
            uVar9 = uVar9 - 0x3c;
            if (((int)uVar9 < (int)uVar2) &&
               (*(float *)(iVar6 + 0x14) = *(float *)(iVar6 + 0x14) - FLOAT_803db414,
               (int)*(float *)(iVar6 + 0x14) <= (int)uVar9)) {
              local_20 = (double)CONCAT44(0x43300000,uVar9 ^ 0x80000000);
              *(float *)(iVar6 + 0x14) = (float)(local_20 - DOUBLE_803e6110);
              *(undefined *)(psVar10 + 1) = 1;
              psVar10[2] = 200;
            }
          }
        }
        else if (bVar4 < 3) {
          if (bVar4 == 1) {
            if (psVar10[2] == 0) {
              if (cVar3 == '\0') {
                if (uVar2 == uVar9 - 0x3c) {
                  *(undefined *)(psVar10 + 1) = 2;
                  FUN_8000bb18(iVar6,0x115);
                }
                if (uVar2 == uVar9) {
                  *(undefined *)(psVar10 + 1) = 3;
                  FUN_8000bb18(iVar6,0x115);
                }
              }
              else if (cVar3 == '\x03') {
                if (uVar1 == uVar8 - 0x3c) {
                  *(undefined *)(psVar10 + 1) = 2;
                  FUN_8000bb18(iVar6,0x115);
                }
                if (uVar1 == uVar8) {
                  *(undefined *)(psVar10 + 1) = 3;
                  FUN_8000bb18(iVar6,0x115);
                }
              }
              else {
                if (uVar2 == uVar9 + 0x3c) {
                  *(undefined *)(psVar10 + 1) = 4;
                  FUN_8000bb18(iVar6,0x115);
                }
                if (uVar2 == uVar9) {
                  *(undefined *)(psVar10 + 1) = 5;
                  FUN_8000bb18(iVar6,0x115);
                }
              }
            }
            else {
              psVar10[2] = psVar10[2] - (short)(int)FLOAT_803db414;
              if (psVar10[2] < 1) {
                psVar10[2] = 0;
              }
            }
          }
          else if (bVar4 == 0) {
            iVar6 = FUN_8001ffb4((int)*psVar10);
            if (iVar6 != 0) {
              *(undefined *)(psVar10 + 1) = 1;
            }
          }
          else if ((cVar3 == '\x03') && ((int)uVar1 < (int)uVar8)) {
            *(float *)(iVar6 + 0xc) = fVar5 + FLOAT_803db414;
            if ((int)uVar8 <= (int)*(float *)(iVar6 + 0xc)) {
              local_20 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
              *(float *)(iVar6 + 0xc) = (float)(local_20 - DOUBLE_803e6110);
              *(undefined *)(psVar10 + 1) = 1;
            }
          }
          else if (((int)uVar2 < (int)uVar9) &&
                  (*(float *)(iVar6 + 0x14) = *(float *)(iVar6 + 0x14) + FLOAT_803db414,
                  (int)uVar9 <= (int)*(float *)(iVar6 + 0x14))) {
            local_20 = (double)CONCAT44(0x43300000,uVar9 ^ 0x80000000);
            *(float *)(iVar6 + 0x14) = (float)(local_20 - DOUBLE_803e6110);
            *(undefined *)(psVar10 + 1) = 1;
          }
        }
        else if (bVar4 == 5) {
          if ((cVar3 == '\x03') && (uVar8 = uVar8 + 0x3c, (int)uVar1 < (int)uVar8)) {
            *(float *)(iVar6 + 0xc) = fVar5 + FLOAT_803db414;
            if ((int)uVar8 <= (int)*(float *)(iVar6 + 0xc)) {
              local_20 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
              *(float *)(iVar6 + 0xc) = (float)(local_20 - DOUBLE_803e6110);
              *(undefined *)(psVar10 + 1) = 1;
              psVar10[2] = 200;
            }
          }
          else {
            uVar9 = uVar9 + 0x3c;
            if (((int)uVar2 < (int)uVar9) &&
               (*(float *)(iVar6 + 0x14) = *(float *)(iVar6 + 0x14) + FLOAT_803db414,
               (int)uVar9 <= (int)*(float *)(iVar6 + 0x14))) {
              local_20 = (double)CONCAT44(0x43300000,uVar9 ^ 0x80000000);
              *(float *)(iVar6 + 0x14) = (float)(local_20 - DOUBLE_803e6110);
              *(undefined *)(psVar10 + 1) = 1;
              psVar10[2] = 200;
            }
          }
        }
        else if (bVar4 < 5) {
          if ((cVar3 == '\x03') && ((int)uVar8 < (int)uVar1)) {
            *(float *)(iVar6 + 0xc) = fVar5 - FLOAT_803db414;
            if ((int)*(float *)(iVar6 + 0xc) <= (int)uVar8) {
              local_20 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
              *(float *)(iVar6 + 0xc) = (float)(local_20 - DOUBLE_803e6110);
              *(undefined *)(psVar10 + 1) = 1;
            }
          }
          else if (((int)uVar9 < (int)uVar2) &&
                  (*(float *)(iVar6 + 0x14) = *(float *)(iVar6 + 0x14) - FLOAT_803db414,
                  (int)*(float *)(iVar6 + 0x14) <= (int)uVar9)) {
            local_20 = (double)CONCAT44(0x43300000,uVar9 ^ 0x80000000);
            *(float *)(iVar6 + 0x14) = (float)(local_20 - DOUBLE_803e6110);
            *(undefined *)(psVar10 + 1) = 1;
          }
        }
      }
    }
  }
  FUN_80286124();
  return;
}

