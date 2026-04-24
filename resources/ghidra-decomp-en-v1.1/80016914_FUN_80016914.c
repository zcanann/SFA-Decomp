// Function: FUN_80016914
// Entry: 80016914
// Size: 824 bytes

void FUN_80016914(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  ushort *puVar2;
  int *piVar3;
  uint *puVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  int local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  uVar10 = FUN_80286840();
  piVar3 = (int *)uVar10;
  if (*(int *)(DAT_803dd66c + 0x1c) != 1) {
    puVar2 = FUN_800195a8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                          (uint)((ulonglong)uVar10 >> 0x20));
    bVar1 = false;
    if (((ushort *)((int)&DAT_8033a61c + 3U) < puVar2) && (puVar2 < (ushort *)0x8033a680)) {
      bVar1 = true;
    }
    if (bVar1) {
      piVar3[2] = 1;
    }
    else {
      iVar6 = *(int *)(*(int *)(puVar2 + 4) + piVar3[1] * 4);
      uVar8 = 0;
      iVar7 = 0;
      if (iVar6 != 0) {
        while (uVar5 = FUN_80015cf0((byte *)(iVar6 + iVar7),local_28), uVar5 != 0) {
          iVar7 = iVar7 + local_28[0];
          if ((uVar5 < 0xe000) || (0xf8ff < uVar5)) {
            uVar8 = uVar8 + 1;
          }
          else {
            puVar4 = &DAT_802c8e70;
            iVar9 = 0x17;
            do {
              if (*puVar4 == uVar5) {
                uVar5 = puVar4[1];
                goto LAB_80016a0c;
              }
              if (puVar4[2] == uVar5) {
                uVar5 = puVar4[3];
                goto LAB_80016a0c;
              }
              puVar4 = puVar4 + 4;
              iVar9 = iVar9 + -1;
            } while (iVar9 != 0);
            uVar5 = 0;
LAB_80016a0c:
            iVar7 = iVar7 + uVar5 * 2;
          }
        }
      }
      if (*piVar3 == 0) {
        DAT_803dd618 = 0;
        FLOAT_803dd614 = FLOAT_803df380;
        piVar3[4] = (uint)puVar2[1];
        piVar3[2] = 0;
        *piVar3 = 1;
      }
      if (FLOAT_803df380 == FLOAT_803dd614) {
        FUN_8000bb38(0,0x397);
      }
      DAT_803dd61c = 1;
      DAT_803dd618 = 0;
      FLOAT_803dd614 = FLOAT_803dc074 * FLOAT_803dc030 + FLOAT_803dd614;
      uStack_1c = uVar8 - 2 ^ 0x80000000;
      local_20 = 0x43300000;
      if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803df378) <= FLOAT_803dd614) {
        FUN_8000b844(0,0x397);
      }
      if (piVar3[3] != 0) {
        uStack_1c = uVar8 ^ 0x80000000;
        if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803df378) <= FLOAT_803dd614) {
          do {
            if (piVar3[3] < 1) {
              piVar3[1] = piVar3[1] + -1;
            }
            else {
              piVar3[1] = piVar3[1] + 1;
            }
            iVar6 = piVar3[1];
            uVar5 = (uint)puVar2[1];
          } while ((iVar6 < (int)uVar5) && (**(char **)(*(int *)(puVar2 + 4) + iVar6 * 4) == '\0'));
          if (iVar6 < 0) {
            piVar3[1] = 0;
          }
          else if (iVar6 < (int)uVar5) {
            FLOAT_803dd614 = FLOAT_803df380;
          }
          else {
            piVar3[1] = uVar5 - 1;
          }
          if (piVar3[1] < 0) {
            piVar3[1] = 0;
          }
          if ((piVar3[1] != puVar2[1] - 1) ||
             (piVar3[3] = 1,
             FLOAT_803dd614 <
             (float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - DOUBLE_803df378))) {
            piVar3[2] = 0;
          }
          else {
            piVar3[2] = 1;
          }
          uStack_1c = uVar8 ^ 0x80000000;
          local_20 = 0x43300000;
          piVar3[3] = 0;
        }
        else {
          local_20 = 0x43300000;
          FLOAT_803dd614 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803df378);
        }
      }
      FUN_80015ebc();
    }
  }
  FUN_8028688c();
  return;
}

