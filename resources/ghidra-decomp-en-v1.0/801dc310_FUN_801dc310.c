// Function: FUN_801dc310
// Entry: 801dc310
// Size: 1116 bytes

void FUN_801dc310(void)

{
  uint uVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  int iVar8;
  int *piVar9;
  double dVar10;
  undefined auStack104 [4];
  undefined auStack100 [4];
  undefined auStack96 [4];
  undefined auStack92 [12];
  float local_50;
  float local_4c;
  float local_48;
  undefined auStack68 [28];
  longlong local_28;
  
  iVar4 = FUN_802860dc();
  piVar9 = *(int **)(iVar4 + 0xb8);
  FUN_8002fa48((double)(float)piVar9[0xd],(double)FLOAT_803db414,iVar4,auStack68);
  if (*(char *)(piVar9 + 0x13) != '\0') {
    if (FLOAT_803e5590 < (float)piVar9[0xf]) {
      piVar9[0xf] = (int)((float)piVar9[0xf] - FLOAT_803db414);
    }
    if (FLOAT_803e5594 < (float)piVar9[0xd]) {
      piVar9[0xd] = (int)((float)piVar9[0xd] - FLOAT_803e5598);
    }
    if (((*(byte *)(piVar9 + 0x13) & 0x80) != 0) && (*(int *)(iVar4 + 0xf8) != 0)) {
      iVar8 = 0;
      piVar6 = piVar9;
      piVar7 = piVar9;
      do {
        if (*piVar7 == 0) {
          FUN_801dbfa0(iVar4,piVar9,DAT_803db410,(int)(char)iVar8);
        }
        else {
          iVar5 = (**(code **)(**(int **)(*piVar7 + 0x68) + 0x28))();
          if (iVar5 < 4) {
            (**(code **)(**(int **)(*piVar7 + 0x68) + 0x24))(*piVar7,piVar6 + 3);
          }
          else {
            *piVar7 = 0;
          }
        }
        piVar7 = piVar7 + 1;
        piVar6 = piVar6 + 3;
        iVar8 = iVar8 + 1;
      } while (iVar8 < 3);
    }
    if ((*(byte *)(piVar9 + 0x13) & 0x20) != 0) {
      if ((*(byte *)(piVar9 + 0x13) & 0xc0) == 0) {
        iVar8 = FUN_80037b40(iVar4,8,0xff,0xff,0x78,0x129,piVar9 + 0x11);
      }
      else {
        iVar8 = FUN_80036770(iVar4,auStack96,auStack100,auStack104,&local_50,&local_4c,&local_48);
      }
      if (FLOAT_803e5590 <= (float)piVar9[0x10]) {
        piVar9[0x10] = (int)((float)piVar9[0x10] - FLOAT_803db414);
      }
      if (((iVar8 != 0) && (iVar8 != 0x11)) && ((float)piVar9[0x10] <= FLOAT_803e5590)) {
        if ((*(byte *)(piVar9 + 0x13) & 0xc0) == 0) {
          FUN_8000bb18(iVar4,0x129);
          FUN_8000bb18(iVar4,0x12a);
        }
        else {
          local_50 = local_50 + FLOAT_803dcdd8;
          local_48 = local_48 + FLOAT_803dcddc;
          FUN_8009a1dc((double)FLOAT_803e559c,iVar4,auStack92,1,0);
          FUN_8002ac30(iVar4,0xf,200,0,0,1);
          FUN_801dc0bc(iVar4,piVar9,*(byte *)(piVar9 + 0x13) & 0xf);
        }
        local_50 = FLOAT_803e5590;
        local_4c = FLOAT_803e55a0 * (float)piVar9[0xe];
        local_48 = FLOAT_803e5590;
        FUN_80096c94((double)(FLOAT_803e55a4 * (float)piVar9[0xe]),iVar4,
                     *(byte *)(piVar9 + 0x13) & 0xf,0x14,auStack92,0);
        piVar9[0xd] = (int)FLOAT_803e5588;
        piVar9[0x10] = (int)FLOAT_803e55a8;
        if ((*(byte *)(piVar9 + 0x13) & 0x80) != 0) {
          iVar8 = 0;
          piVar6 = piVar9;
          do {
            if ((*piVar6 != 0) &&
               (iVar5 = (**(code **)(**(int **)(*piVar6 + 0x68) + 0x28))(), 1 < iVar5)) {
              FUN_80036450(*piVar6,iVar4,0xe,1,0);
            }
            piVar6 = piVar6 + 1;
            iVar8 = iVar8 + 1;
          } while (iVar8 < 3);
        }
      }
    }
    iVar8 = FUN_8002b9ec();
    fVar2 = *(float *)(iVar4 + 0xc) - *(float *)(iVar8 + 0xc);
    fVar3 = *(float *)(iVar4 + 0x14) - *(float *)(iVar8 + 0x14);
    dVar10 = (double)FUN_802931a0((double)(fVar2 * fVar2 + fVar3 * fVar3));
    uVar1 = (uint)dVar10;
    local_28 = (longlong)(int)uVar1;
    if ((uVar1 & 0xffff) < (uint)*(ushort *)(piVar9 + 0x12)) {
      if (((*(byte *)(piVar9 + 0x13) & 0x10) != 0) &&
         ((uint)*(ushort *)(piVar9 + 0x12) <= (uint)*(ushort *)((int)piVar9 + 0x4a))) {
        if ((float)piVar9[0xf] <= FLOAT_803e5590) {
          local_50 = FLOAT_803e5590;
          local_4c = FLOAT_803e55ac * FLOAT_803e55a0 * (float)piVar9[0xe];
          local_48 = FLOAT_803e5590;
          FUN_80096c94((double)(FLOAT_803e55a4 * (float)piVar9[0xe]),iVar4,
                       *(byte *)(piVar9 + 0x13) & 0xf,10,auStack92,1);
          piVar9[0xf] = (int)FLOAT_803e55b0;
        }
      }
      piVar9[0xc] = (int)((float)piVar9[0xc] - FLOAT_803db414);
      if ((float)piVar9[0xc] <= FLOAT_803e5590) {
        local_50 = FLOAT_803e5590;
        local_4c = FLOAT_803e55a0 * (float)piVar9[0xe];
        local_48 = FLOAT_803e5590;
        FUN_80021ac8(iVar4,&local_50);
        FUN_80096c94((double)(FLOAT_803e55a4 * (float)piVar9[0xe]),iVar4,
                     *(byte *)(piVar9 + 0x13) & 0xf,1,auStack92,0);
        piVar9[0xc] = (int)((float)piVar9[0xc] + FLOAT_803e55b4);
      }
    }
    *(short *)((int)piVar9 + 0x4a) = (short)uVar1;
  }
  FUN_80286128();
  return;
}

