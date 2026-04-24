// Function: FUN_802015ec
// Entry: 802015ec
// Size: 440 bytes

void FUN_802015ec(void)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int iVar8;
  undefined8 uVar9;
  undefined4 local_38;
  undefined4 local_34;
  int local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  uVar9 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  iVar8 = *(int *)(*(int *)(iVar3 + 0xb8) + 0x40c);
  uVar7 = *(undefined4 *)(iVar8 + 0x30);
  *(byte *)(iVar8 + 0x14) = *(byte *)(iVar8 + 0x14) | 2;
  fVar2 = FLOAT_803e62a8;
  *(float *)(iVar5 + 0x280) = FLOAT_803e62a8;
  *(float *)(iVar5 + 0x284) = fVar2;
  if ((*(int *)(iVar5 + 0x2d0) == 0) ||
     (iVar4 = (**(code **)(**(int **)(*(int *)(iVar5 + 0x2d0) + 0x68) + 0x20))(), iVar4 == 0)) {
    *(undefined *)(iVar8 + 0x34) = 1;
  }
  if ((*(int *)(iVar8 + 0x18) == 0) && (sVar1 = *(short *)(iVar8 + 0x1c), sVar1 != -1)) {
    local_24 = *(undefined4 *)(iVar8 + 0x30);
    local_28 = *(undefined4 *)(iVar8 + 0x2c);
    uVar6 = *(undefined4 *)(iVar8 + 0x24);
    local_2c = *(undefined4 *)(iVar8 + 0x28);
    iVar4 = FUN_800138c4(uVar6);
    if (iVar4 == 0) {
      FUN_80013958(uVar6,&local_2c);
    }
    uVar6 = *(undefined4 *)(iVar8 + 0x24);
    local_38 = 7;
    local_34 = 0;
    local_30 = (int)sVar1;
    iVar4 = FUN_800138c4(uVar6);
    if (iVar4 == 0) {
      FUN_80013958(uVar6,&local_38);
    }
    *(undefined *)(iVar8 + 0x34) = 1;
    *(undefined2 *)(iVar8 + 0x1c) = 0xffff;
  }
  if ((*(uint *)(iVar5 + 0x314) & 0x200) != 0) {
    *(undefined4 *)(iVar8 + 0x18) = *(undefined4 *)(iVar5 + 0x2d0);
    *(short *)(iVar8 + 0x1c) = (short)uVar7;
    *(undefined4 *)(iVar8 + 0x2c) = 0;
    FUN_800378c4(*(undefined4 *)(iVar8 + 0x18),0x11,iVar3,0x12);
    FUN_8000bb18(iVar3,0x1eb);
  }
  *(undefined *)(iVar5 + 0x34d) = 0x12;
  if (*(char *)(iVar5 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e62a8,iVar3,0x10,0);
    *(undefined *)(iVar5 + 0x346) = 0;
  }
  if (*(char *)(iVar5 + 0x346) != '\0') {
    *(undefined *)(iVar8 + 0x34) = 1;
  }
  FUN_80286124(0);
  return;
}

