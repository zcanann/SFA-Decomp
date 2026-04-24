// Function: FUN_8026de58
// Entry: 8026de58
// Size: 536 bytes

int FUN_8026de58(byte param_1)

{
  uint uVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  ushort *puVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  uint uVar9;
  
  uVar1 = (uint)param_1;
  piVar3 = (int *)(DAT_803de218 + (uint)param_1 * 8 + 0x124);
  puVar7 = (uint *)(DAT_803de218 + uVar1 * 0x2c + 0x364);
  if (piVar3[1] == 0) {
    return 0;
  }
  iVar4 = DAT_803de218 + uVar1 * 0x18 + 0xee4;
  *(byte *)(iVar4 + 0x15) = param_1;
  *(uint **)(iVar4 + 0x10) = puVar7;
  if (puVar7[2] == 0) {
LAB_8026dea4:
    if (*(short *)(piVar3[1] + 8) == -1) {
      piVar3[1] = 0;
      return 0;
    }
    if (*(short *)(piVar3[1] + 8) != -2) {
      *(undefined *)(iVar4 + 0x14) = 4;
      *(undefined4 *)(iVar4 + 8) = *(undefined4 *)piVar3[1];
      *(int *)(iVar4 + 0xc) = piVar3[1];
      piVar3[1] = piVar3[1] + 0xc;
      return iVar4;
    }
    if (*(int *)(DAT_803de218 + 0x14e4) == 0) {
      if (*(char *)(DAT_803de218 + 0x151e) != '\0') {
        piVar3[1] = 0;
        return 0;
      }
    }
    else if (*(char *)(DAT_803de218 +
                       (uint)*(byte *)(*(int *)(DAT_803de218 + 0x14e4) + uVar1) * 0x38 + 0x151e) !=
             '\0') {
      piVar3[1] = 0;
      return 0;
    }
    *(undefined *)(iVar4 + 0x14) = 3;
    *(undefined4 *)(iVar4 + 8) = *(undefined4 *)piVar3[1];
    piVar3[1] = *piVar3 + (uint)*(ushort *)(piVar3[1] + 10) * 0xc;
    return iVar4;
  }
  uVar8 = puVar7[6];
  uVar9 = puVar7[9];
  do {
    puVar5 = (ushort *)puVar7[2];
    uVar2 = (uint)*puVar5 + *puVar7;
    if (uVar8 <= uVar2) {
      if (uVar8 < uVar9) {
        *(uint *)(iVar4 + 8) = uVar8 + puVar7[1];
        *(undefined *)(iVar4 + 0x14) = 2;
      }
      else {
LAB_8026e04c:
        *(uint *)(iVar4 + 8) = uVar9 + puVar7[1];
        *(undefined *)(iVar4 + 0x14) = 1;
      }
      return iVar4;
    }
    if (uVar9 <= uVar2) goto LAB_8026e04c;
    if ((*(char *)(puVar5 + 1) == -1) && (*(char *)((int)puVar5 + 3) == -1)) {
      puVar7[2] = 0;
      goto LAB_8026dea4;
    }
    *(ushort **)(iVar4 + 0xc) = puVar5;
    *puVar7 = uVar2;
    uVar6 = puVar7[2];
    if ((*(byte *)(uVar6 + 2) & 0x80) != 0) {
      puVar7[2] = uVar6 + 4;
LAB_8026e014:
      *(undefined *)(iVar4 + 0x14) = 0;
      *(uint *)(iVar4 + 8) = uVar2 + puVar7[1];
      return iVar4;
    }
    if ((*(byte *)(uVar6 + 2) | *(byte *)(uVar6 + 3)) != 0) {
      puVar7[2] = uVar6 + 6;
      goto LAB_8026e014;
    }
    puVar7[2] = uVar6 + 4;
  } while( true );
}

