// Function: FUN_80201358
// Entry: 80201358
// Size: 660 bytes

void FUN_80201358(void)

{
  float fVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  short sVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  undefined4 local_58;
  undefined4 local_54;
  int local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  uVar11 = FUN_802860dc();
  fVar1 = FLOAT_803e62a8;
  psVar2 = (short *)((ulonglong)uVar11 >> 0x20);
  iVar3 = (int)uVar11;
  iVar9 = *(int *)(*(int *)(psVar2 + 0x5c) + 0x40c);
  uVar7 = *(undefined4 *)(iVar9 + 0x30);
  uVar6 = *(undefined4 *)(iVar9 + 0x2c);
  *(float *)(iVar3 + 0x280) = FLOAT_803e62a8;
  *(float *)(iVar3 + 0x284) = fVar1;
  *(byte *)(iVar9 + 0x14) = *(byte *)(iVar9 + 0x14) | 2;
  if ((*(int *)(iVar9 + 0x18) == 0) && (*(short *)(iVar9 + 0x1c) != -1)) {
    local_38 = *(undefined4 *)(iVar9 + 0x30);
    local_3c = *(undefined4 *)(iVar9 + 0x2c);
    uVar8 = *(undefined4 *)(iVar9 + 0x24);
    local_40 = *(undefined4 *)(iVar9 + 0x28);
    iVar3 = FUN_800138c4(uVar8);
    if (iVar3 == 0) {
      FUN_80013958(uVar8,&local_40);
    }
    uVar8 = *(undefined4 *)(iVar9 + 0x24);
    local_4c = 8;
    local_48 = uVar6;
    local_44 = uVar7;
    iVar3 = FUN_800138c4(uVar8);
    if (iVar3 == 0) {
      FUN_80013958(uVar8,&local_4c);
    }
    *(undefined *)(iVar9 + 0x34) = 1;
    local_50 = (int)*(short *)(iVar9 + 0x1c);
    uVar6 = *(undefined4 *)(iVar9 + 0x24);
    local_58 = 9;
    local_54 = 0;
    iVar3 = FUN_800138c4(uVar6);
    if (iVar3 == 0) {
      FUN_80013958(uVar6,&local_58);
    }
    *(undefined *)(iVar9 + 0x34) = 1;
  }
  else {
    *(byte *)(iVar9 + 0x15) = *(byte *)(iVar9 + 0x15) | 4;
    if ((*(int *)(iVar9 + 0x18) != 0) && ((*(uint *)(iVar3 + 0x314) & 0x200) != 0)) {
      iVar4 = *(int *)(iVar3 + 0x2d0);
      local_34 = *(float *)(iVar4 + 0xc) - *(float *)(psVar2 + 6);
      local_30 = *(float *)(iVar4 + 0x10) - *(float *)(psVar2 + 8);
      local_2c = *(float *)(iVar4 + 0x14) - *(float *)(psVar2 + 10);
      dVar10 = (double)FUN_802931a0((double)(local_34 * local_34 + local_2c * local_2c));
      local_30 = local_30 * FLOAT_803e6310;
      fVar1 = (float)(dVar10 / (double)FLOAT_803e6314);
      local_24 = (-(fVar1 * FLOAT_803e6318 * fVar1 - local_30) / fVar1) * FLOAT_803e631c;
      local_28 = FLOAT_803e62a8;
      local_20 = FLOAT_803e6320;
      FUN_800378c4(*(undefined4 *)(iVar9 + 0x18),0x11,psVar2,0x11);
      (**(code **)(**(int **)(*(int *)(iVar9 + 0x18) + 0x68) + 0x24))
                (*(int *)(iVar9 + 0x18),&local_28);
      *(undefined4 *)(iVar9 + 0x18) = 0;
      *(undefined2 *)(iVar9 + 0x1c) = 0xffff;
    }
    sVar5 = FUN_800385e8(psVar2,*(undefined4 *)(iVar3 + 0x2d0),0);
    *psVar2 = *psVar2 + sVar5;
    *(undefined *)(iVar3 + 0x34d) = 0x11;
    if (*(char *)(iVar3 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e62a8,psVar2,0x12,0);
      *(undefined *)(iVar3 + 0x346) = 0;
    }
    if (*(char *)(iVar3 + 0x346) != '\0') {
      *(undefined *)(iVar9 + 0x34) = 1;
    }
  }
  FUN_80286128(0);
  return;
}

