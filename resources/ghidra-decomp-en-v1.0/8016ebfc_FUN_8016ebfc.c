// Function: FUN_8016ebfc
// Entry: 8016ebfc
// Size: 756 bytes

void FUN_8016ebfc(int param_1)

{
  float fVar1;
  float fVar2;
  short sVar3;
  int iVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  int *piVar8;
  double local_18;
  
  piVar8 = *(int **)(param_1 + 0xb8);
  iVar4 = FUN_8002b588();
  *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
  FUN_8002fa48((double)(float)piVar8[0x14],(double)FLOAT_803db414,param_1,0);
  iVar4 = 3;
  piVar5 = piVar8;
  do {
    if ((*(byte *)(piVar5 + 5) & 2) != 0) {
      uVar6 = (uint)*(ushort *)(piVar5 + 3);
      iVar7 = *piVar5 + uVar6 * 0x14;
      for (; (int)uVar6 < (int)(uint)*(ushort *)((int)piVar5 + 0xe); uVar6 = uVar6 + 2) {
        if (piVar5 == (int *)piVar8[0x12]) {
          fVar1 = FLOAT_803e32f4 *
                  (FLOAT_803e330c * (float)piVar8[0x26] - *(float *)(iVar7 + 0xc)) * FLOAT_803e3310;
          fVar2 = FLOAT_803e32b4;
          if ((FLOAT_803e32b4 <= fVar1) && (fVar2 = fVar1, FLOAT_803e32f4 < fVar1)) {
            fVar2 = FLOAT_803e32f4;
          }
          *(short *)(iVar7 + 0x10) = (short)(int)(FLOAT_803e32f4 - fVar2);
          *(undefined2 *)(iVar7 + 0x24) = *(undefined2 *)(iVar7 + 0x10);
        }
        else {
          local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + 0x10) ^ 0x80000000);
          *(short *)(iVar7 + 0x10) =
               (short)(int)-(FLOAT_803e332c * FLOAT_803db414 - (float)(local_18 - DOUBLE_803e3318));
          *(undefined2 *)(iVar7 + 0x24) = *(undefined2 *)(iVar7 + 0x10);
        }
        sVar3 = *(short *)(iVar7 + 0x10);
        if (sVar3 < 0) {
          sVar3 = 0;
        }
        else if (0xff < sVar3) {
          sVar3 = 0xff;
        }
        *(short *)(iVar7 + 0x10) = sVar3;
        sVar3 = *(short *)(iVar7 + 0x24);
        if (sVar3 < 0) {
          sVar3 = 0;
        }
        else if (0xff < sVar3) {
          sVar3 = 0xff;
        }
        *(short *)(iVar7 + 0x24) = sVar3;
        if ((*(short *)(iVar7 + 0x10) < 1) && (*(short *)(iVar7 + 0x24) < 1)) {
          *(short *)((int)piVar5 + 0x12) = *(short *)((int)piVar5 + 0x12) + -2;
          *(short *)(piVar5 + 3) = *(short *)(piVar5 + 3) + 2;
        }
        iVar7 = iVar7 + 0x28;
      }
      if ((piVar5 != (int *)piVar8[0x12]) && (*(short *)((int)piVar5 + 0x12) == 0)) {
        *(byte *)(piVar5 + 5) = *(byte *)(piVar5 + 5) & 0xfd;
      }
    }
    piVar5 = piVar5 + 6;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  FUN_8016cee8(param_1,*(undefined4 *)(param_1 + 0xc4));
  FUN_80296ba0(*(undefined4 *)(param_1 + 0xc4));
  *(undefined *)((int)piVar8 + 0xb9) = 0;
  if (DAT_803ac6d8 != '\0') {
    DAT_803ac6c4 = DAT_803ac6c4 + FLOAT_803e32e0;
    FUN_80035974(DAT_803ac6d4,(int)DAT_803ac6c4);
    FUN_80035df4(DAT_803ac6d4,0x11,5,0);
    DAT_803ac6d0 = DAT_803ac6d0 + FLOAT_803e32e4;
    DAT_803ac6c8 = DAT_803ac6c8 * FLOAT_803e32e8;
    DAT_803ac6cc = DAT_803ac6cc * FLOAT_803e32ec;
    *(char *)(DAT_803ac6d4 + 0x36) = (char)(int)DAT_803ac6d0;
    *(float *)(DAT_803ac6d4 + 8) = *(float *)(DAT_803ac6d4 + 8) + FLOAT_803e32f0;
    if (DAT_803ac6d0 < FLOAT_803e3288) {
      DAT_803ac6d8 = '\0';
      FUN_8002cbc4(DAT_803ac6d4);
      DAT_803ac6d4 = 0;
    }
  }
  return;
}

