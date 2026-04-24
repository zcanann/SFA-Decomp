// Function: FUN_80152514
// Entry: 80152514
// Size: 1408 bytes

void FUN_80152514(void)

{
  int iVar1;
  short *psVar2;
  int iVar3;
  char cVar7;
  short sVar5;
  short sVar6;
  undefined4 uVar4;
  int *piVar8;
  int iVar9;
  int iVar10;
  undefined8 uVar11;
  undefined auStack72 [8];
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  longlong local_30;
  longlong local_28;
  
  uVar11 = FUN_802860dc();
  psVar2 = (short *)((ulonglong)uVar11 >> 0x20);
  piVar8 = (int *)uVar11;
  iVar10 = *(int *)(psVar2 + 0x26);
  iVar9 = *piVar8;
  if (FLOAT_803e2814 < (float)piVar8[0xcb]) {
    if (*(int *)(psVar2 + 100) != 0) {
      FUN_8002cbc4();
      FUN_80037cb0(psVar2,*(undefined4 *)(psVar2 + 100));
      *(undefined4 *)(psVar2 + 100) = 0;
    }
    piVar8[0xcb] = (int)((float)piVar8[0xcb] - FLOAT_803db414);
    if (FLOAT_803e2814 < (float)piVar8[0xcb]) {
      if ((piVar8[0xb9] & 0x20U) == 0) goto LAB_80152a7c;
    }
    else {
      piVar8[0xcb] = (int)FLOAT_803e2814;
      piVar8[0xb9] = piVar8[0xb9] | 0x20;
      FUN_8000b7bc(psVar2,4);
      FUN_8014d08c((double)FLOAT_803e2820,psVar2,piVar8,0,0,0);
    }
  }
  if ((piVar8[0xb7] & 0x2000U) == 0) {
    if (FLOAT_803e2830 <= *(float *)(psVar2 + 8) - *(float *)(iVar10 + 0xc)) {
      *(undefined *)((int)piVar8 + 0x33a) = 0;
    }
    else {
      iVar9 = FUN_8000b5d0(psVar2,0x18d);
      if (iVar9 == 0) {
        FUN_8000bb18(psVar2,0x18d);
      }
      *(undefined *)((int)piVar8 + 0x33a) = 1;
    }
    *psVar2 = *psVar2 + (short)*(char *)(iVar10 + 0x2a);
  }
  else {
    iVar3 = FUN_80010320((double)(float)piVar8[0xbf],iVar9);
    if ((((iVar3 != 0) || (*(int *)(iVar9 + 0x10) != 0)) &&
        (cVar7 = (**(code **)(*DAT_803dca9c + 0x90))(iVar9), cVar7 != '\0')) &&
       (cVar7 = (**(code **)(*DAT_803dca9c + 0x8c))
                          ((double)FLOAT_803e2824,*piVar8,psVar2,&DAT_803dbca8,0xffffffff),
       cVar7 != '\0')) {
      piVar8[0xb7] = piVar8[0xb7] & 0xffffdfff;
    }
    *(float *)(psVar2 + 0x12) = (*(float *)(iVar9 + 0x68) - *(float *)(psVar2 + 6)) / FLOAT_803db414
    ;
    *(float *)(psVar2 + 0x16) =
         (*(float *)(iVar9 + 0x70) - *(float *)(psVar2 + 10)) / FLOAT_803db414;
    iVar3 = (int)*(char *)(iVar10 + 0x2a);
    if (iVar3 == 0) {
      FUN_8014cf7c((double)*(float *)(iVar9 + 0x68),(double)*(float *)(iVar9 + 0x70),psVar2,piVar8,
                   0xf,0);
    }
    else if ((piVar8[0xb7] & 0x2000U) == 0) {
      iVar1 = (int)(FLOAT_803e2828 * *(float *)(iVar9 + 0x78));
      local_28 = (longlong)iVar1;
      if (iVar1 < 0) {
        iVar3 = -iVar3;
      }
      *psVar2 = *psVar2 + (short)iVar3;
    }
    else {
      sVar6 = (short)(iVar3 << 8);
      iVar3 = (int)(FLOAT_803e2828 * *(float *)(iVar9 + 0x78));
      local_30 = (longlong)iVar3;
      sVar5 = sVar6;
      if (iVar3 < 0) {
        sVar5 = -sVar6;
      }
      *psVar2 = *psVar2 - sVar5;
      FUN_8014cf7c((double)*(float *)(iVar9 + 0x68),(double)*(float *)(iVar9 + 0x70),psVar2,piVar8,
                   0xf,0);
      iVar3 = (int)(FLOAT_803e2828 * *(float *)(iVar9 + 0x78));
      local_28 = (longlong)iVar3;
      if (iVar3 < 0) {
        sVar6 = -sVar6;
      }
      *psVar2 = *psVar2 + sVar6;
    }
    if (FLOAT_803e282c <= *(float *)(psVar2 + 8) - *(float *)(iVar9 + 0x6c)) {
      *(undefined *)((int)piVar8 + 0x33a) = 0;
    }
    else {
      iVar9 = FUN_8000b5d0(psVar2,0x18d);
      if (iVar9 == 0) {
        FUN_8000bb18(psVar2,0x18d);
      }
      *(undefined *)((int)piVar8 + 0x33a) = 1;
    }
  }
  if (*(char *)((int)piVar8 + 0x33a) != '\0') {
    *(float *)(psVar2 + 0x14) = FLOAT_803dbcb0 * FLOAT_803db414 + *(float *)(psVar2 + 0x14);
  }
  if ((psVar2[0x58] & 0x800U) != 0) {
    local_3c = FLOAT_803e2814;
    local_38 = FLOAT_803e2814;
    local_34 = FLOAT_803e2814;
    local_40 = FLOAT_803e2820;
    FUN_8009837c((double)FLOAT_803e2834,(double)FLOAT_803e2838,psVar2,2,0,6,auStack72);
    local_38 = FLOAT_803e283c;
    FUN_800971a0((double)FLOAT_803e2840,psVar2,1,6,0x20,auStack72);
    local_3c = FLOAT_803e2814;
    local_38 = FLOAT_803e2844;
    local_34 = FLOAT_803e2844;
  }
  if (FLOAT_803e2848 <= *(float *)(psVar2 + 0x14)) {
    if (FLOAT_803e2834 < *(float *)(psVar2 + 0x14)) {
      *(float *)(psVar2 + 0x14) = FLOAT_803e2834;
    }
  }
  else {
    *(float *)(psVar2 + 0x14) = FLOAT_803e2848;
  }
  if (FLOAT_803e2814 == (float)piVar8[0xcb]) {
    if (((*(char *)(iVar10 + 0x2e) != -1) && (*(int *)(psVar2 + 100) != 0)) &&
       (iVar9 = FUN_801a0174(), iVar9 != 0)) {
      uVar4 = FUN_8002b9ec();
      FUN_80036450(uVar4,psVar2,0x16,2,0);
      FUN_80152370(psVar2,0x3b2);
      FUN_8000bb18(psVar2,0xe9);
      piVar8[0xcb] = (int)FLOAT_803dbcb4;
    }
    local_28 = (longlong)(int)(FLOAT_803e284c * FLOAT_803db418);
    iVar9 = FUN_800221a0(0,(int)(FLOAT_803e284c * FLOAT_803db418));
    if (iVar9 == 0) {
      FUN_8000bb18(psVar2,0xe7);
    }
    if (*(int *)(psVar2 + 100) == 0) {
      cVar7 = *(char *)(iVar10 + 0x2a);
      iVar9 = FUN_80152370(psVar2,0x639);
      uVar4 = 0;
      if ((*(char *)(iVar10 + 0x2a) != '\0') && ((piVar8[0xb7] & 0x2000U) == 0)) {
        uVar4 = 1;
      }
      *(undefined4 *)(iVar9 + 0xf4) = uVar4;
      FUN_80037d2c(psVar2,iVar9,cVar7 != '\0');
    }
    else {
      iVar9 = FUN_800394ac(*(int *)(psVar2 + 100),0,0);
      if (iVar9 != 0) {
        iVar10 = *(short *)(iVar9 + 8) + -0x3c;
        if (iVar10 < 0) {
          iVar10 = *(short *)(iVar9 + 8) + 0x26d4;
        }
        *(short *)(iVar9 + 8) = (short)iVar10;
      }
    }
  }
LAB_80152a7c:
  FUN_80286128();
  return;
}

