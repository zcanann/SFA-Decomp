// Function: FUN_801f7f8c
// Entry: 801f7f8c
// Size: 756 bytes

void FUN_801f7f8c(void)

{
  undefined2 *puVar1;
  char cVar4;
  uint uVar2;
  int iVar3;
  int iVar5;
  short sVar6;
  int iVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_8028683c();
  puVar1 = (undefined2 *)((ulonglong)uVar8 >> 0x20);
  iVar5 = (int)uVar8;
  iVar7 = *(int *)(puVar1 + 0x5c);
  *(undefined **)(puVar1 + 0x5e) = &LAB_801f74c4;
  cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(puVar1 + 0x56));
  if ((cVar4 == '\x03') && (uVar2 = FUN_80020078(0x21b), uVar2 == 0)) {
    FUN_800201ac(0x21b,1);
  }
  *(undefined4 *)(iVar7 + 8) = 0;
  *(undefined *)(iVar7 + 0xd) = 1;
  sVar6 = puVar1[0x23];
  if (sVar6 == 0x262) {
    *puVar1 = (short)((int)*(char *)(iVar5 + 0x18) << 8);
    *(undefined2 *)(iVar7 + 2) = 100;
    if (*(short *)(iVar5 + 0x1c) < 1000) {
      *(float *)(puVar1 + 4) = FLOAT_803e6bbc;
    }
    else {
      *(float *)(puVar1 + 4) =
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1c) ^ 0x80000000) -
                  DOUBLE_803e6c08) / FLOAT_803e6c24;
    }
  }
  else if (sVar6 == 0x2bd) {
    DAT_803de930 = 800;
    DAT_803de92e = 800;
    DAT_803de92c = 800;
    DAT_803de92a = 800;
    DAT_803de928 = 800;
    *puVar1 = (short)((int)*(char *)(iVar5 + 0x18) << 8);
    if (*(short *)(iVar5 + 0x1c) < 0) {
      *(float *)(puVar1 + 4) = FLOAT_803e6bbc;
    }
    else {
      *(float *)(puVar1 + 4) =
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1c) ^ 0x80000000) -
                  DOUBLE_803e6c08) / FLOAT_803e6c24;
    }
    *(undefined *)((int)puVar1 + 0xad) = *(undefined *)(iVar5 + 0x19);
    cVar4 = *(char *)((int)puVar1 + 0xad);
    if (cVar4 == '\0') {
      uVar2 = FUN_80022264(300,600);
      *(short *)(iVar7 + 2) = (short)uVar2;
      uVar2 = FUN_80022264(300,600);
      *(short *)(iVar7 + 4) = (short)uVar2;
    }
    else if (cVar4 == '\x01') {
      uVar2 = FUN_80022264(500,800);
      *(short *)(iVar7 + 2) = (short)uVar2;
      uVar2 = FUN_80022264(500,800);
      *(short *)(iVar7 + 4) = (short)uVar2;
    }
    else if (cVar4 == '\x02') {
      uVar2 = FUN_80022264(700,1000);
      *(short *)(iVar7 + 2) = (short)uVar2;
      uVar2 = FUN_80022264(700,1000);
      *(short *)(iVar7 + 4) = (short)uVar2;
    }
    *(undefined *)(puVar1 + 0x1b) = 0;
  }
  else if (sVar6 == 0x2c2) {
    iVar3 = FUN_80023d8c(0xa0,0xe);
    *(int *)(iVar7 + 8) = iVar3;
    iVar3 = 0x28;
    for (sVar6 = 0x14; sVar6 != 0; sVar6 = sVar6 + -1) {
      *(undefined2 *)(*(int *)(iVar7 + 8) + iVar3 + 0x26) = 0;
      uVar2 = FUN_80022264(10,0x14);
      *(short *)(*(int *)(iVar7 + 8) + iVar3 + 0x4e) = (short)uVar2;
      uVar2 = FUN_80022264(0x50,0xff);
      *(short *)(*(int *)(iVar7 + 8) + iVar3 + 0x76) = (short)uVar2;
      iVar3 = iVar3 + -2;
    }
    *(undefined *)(puVar1 + 0x1b) = 0;
    if ((int)*(short *)(iVar5 + 0x1c) != 0) {
      *(float *)(puVar1 + 4) =
           FLOAT_803e6bbc /
           ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1c) ^ 0x80000000) -
                   DOUBLE_803e6c08) / FLOAT_803e6c24);
    }
  }
  FUN_80286888();
  return;
}

