// Function: FUN_801f7954
// Entry: 801f7954
// Size: 756 bytes

void FUN_801f7954(void)

{
  undefined2 *puVar1;
  char cVar5;
  int iVar2;
  undefined2 uVar4;
  undefined4 uVar3;
  int iVar6;
  short sVar7;
  int iVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_802860d8();
  puVar1 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  iVar6 = (int)uVar9;
  iVar8 = *(int *)(puVar1 + 0x5c);
  *(undefined **)(puVar1 + 0x5e) = &LAB_801f6e8c;
  cVar5 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(puVar1 + 0x56));
  if ((cVar5 == '\x03') && (iVar2 = FUN_8001ffb4(0x21b), iVar2 == 0)) {
    FUN_800200e8(0x21b,1);
  }
  *(undefined4 *)(iVar8 + 8) = 0;
  *(undefined *)(iVar8 + 0xd) = 1;
  sVar7 = puVar1[0x23];
  if (sVar7 == 0x262) {
    *puVar1 = (short)((int)*(char *)(iVar6 + 0x18) << 8);
    *(undefined2 *)(iVar8 + 2) = 100;
    if (*(short *)(iVar6 + 0x1c) < 1000) {
      *(float *)(puVar1 + 4) = FLOAT_803e5f24;
    }
    else {
      *(float *)(puVar1 + 4) =
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                  DOUBLE_803e5f70) / FLOAT_803e5f8c;
    }
  }
  else if (sVar7 == 0x2bd) {
    DAT_803ddcb0 = 800;
    DAT_803ddcae = 800;
    DAT_803ddcac = 800;
    DAT_803ddcaa = 800;
    DAT_803ddca8 = 800;
    *puVar1 = (short)((int)*(char *)(iVar6 + 0x18) << 8);
    if (*(short *)(iVar6 + 0x1c) < 0) {
      *(float *)(puVar1 + 4) = FLOAT_803e5f24;
    }
    else {
      *(float *)(puVar1 + 4) =
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                  DOUBLE_803e5f70) / FLOAT_803e5f8c;
    }
    *(undefined *)((int)puVar1 + 0xad) = *(undefined *)(iVar6 + 0x19);
    cVar5 = *(char *)((int)puVar1 + 0xad);
    if (cVar5 == '\0') {
      uVar4 = FUN_800221a0(300,600);
      *(undefined2 *)(iVar8 + 2) = uVar4;
      uVar4 = FUN_800221a0(300,600);
      *(undefined2 *)(iVar8 + 4) = uVar4;
    }
    else if (cVar5 == '\x01') {
      uVar4 = FUN_800221a0(500,800);
      *(undefined2 *)(iVar8 + 2) = uVar4;
      uVar4 = FUN_800221a0(500,800);
      *(undefined2 *)(iVar8 + 4) = uVar4;
    }
    else if (cVar5 == '\x02') {
      uVar4 = FUN_800221a0(700,1000);
      *(undefined2 *)(iVar8 + 2) = uVar4;
      uVar4 = FUN_800221a0(700,1000);
      *(undefined2 *)(iVar8 + 4) = uVar4;
    }
    *(undefined *)(puVar1 + 0x1b) = 0;
  }
  else if (sVar7 == 0x2c2) {
    uVar3 = FUN_80023cc8(0xa0,0xe,0);
    *(undefined4 *)(iVar8 + 8) = uVar3;
    iVar2 = 0x28;
    for (sVar7 = 0x14; sVar7 != 0; sVar7 = sVar7 + -1) {
      *(undefined2 *)(*(int *)(iVar8 + 8) + iVar2 + 0x26) = 0;
      uVar4 = FUN_800221a0(10,0x14);
      *(undefined2 *)(*(int *)(iVar8 + 8) + iVar2 + 0x4e) = uVar4;
      uVar4 = FUN_800221a0(0x50,0xff);
      *(undefined2 *)(*(int *)(iVar8 + 8) + iVar2 + 0x76) = uVar4;
      iVar2 = iVar2 + -2;
    }
    *(undefined *)(puVar1 + 0x1b) = 0;
    if ((int)*(short *)(iVar6 + 0x1c) != 0) {
      *(float *)(puVar1 + 4) =
           FLOAT_803e5f24 /
           ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                   DOUBLE_803e5f70) / FLOAT_803e5f8c);
    }
  }
  FUN_80286124();
  return;
}

