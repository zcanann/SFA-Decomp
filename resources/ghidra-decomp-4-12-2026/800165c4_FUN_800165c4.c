// Function: FUN_800165c4
// Entry: 800165c4
// Size: 644 bytes

void FUN_800165c4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  undefined uVar4;
  uint uVar5;
  ushort *puVar6;
  int iVar7;
  char cVar8;
  undefined *puVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  int local_38;
  int local_34;
  int iStack_30;
  int aiStack_2c [11];
  
  uVar10 = FUN_8028682c();
  uVar5 = (uint)((ulonglong)uVar10 >> 0x20);
  puVar6 = FUN_800195a8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar5);
  uVar4 = DAT_803dd627;
  uVar3 = DAT_803dd626;
  uVar2 = DAT_803dd625;
  uVar1 = DAT_803dd624;
  DAT_803dd640 = 1;
  puVar9 = DAT_803dd64c;
  if (DAT_803dd64c == (undefined *)0x0) {
    if (*(byte *)(puVar6 + 2) == 0xff) {
      puVar9 = (undefined *)0x802c7bc0;
    }
    else {
      puVar9 = &DAT_802c7b80 + (uint)*(byte *)(puVar6 + 2) * 0x20;
    }
  }
  if (puVar9 == (undefined *)0x802c8c20) {
    DAT_803dd627 = 0xff;
    DAT_803dd626 = 0xff;
    DAT_803dd625 = 0xff;
    DAT_803dd624 = 0xff;
  }
  if (*(char *)((int)puVar6 + 5) == '\0') {
    puVar9[0x12] = puVar9[0x10];
  }
  *(short *)(puVar9 + 0x18) = (short)uVar10;
  *(short *)(puVar9 + 0x1a) = (short)param_11;
  if (DAT_803dd63c == 0) {
    cVar8 = *(char *)(puVar6 + 3);
    if (cVar8 == '\0') {
      cVar8 = puVar9[0x11];
    }
    if ((cVar8 == '\x02') || (cVar8 == '\x03')) {
      FUN_800162c4(uVar5,(int)uVar10,param_11,aiStack_2c,&iStack_30,&local_34,&local_38);
      iVar7 = (uint)*(ushort *)(puVar9 + 10) - (local_38 - local_34);
      if (cVar8 == '\x02') {
        *(short *)(puVar9 + 0x1a) = (short)(iVar7 / 2);
      }
      else {
        *(short *)(puVar9 + 0x1a) = (short)iVar7;
      }
    }
  }
  if (DAT_803dd63c == 0) {
    FUN_8001bf44(puVar6,0,(int)puVar9);
  }
  if (DAT_803dd5ec == 0) {
    if (*(short *)(puVar9 + 0x14) < 0) {
      *(undefined2 *)(puVar9 + 0x14) = 0;
    }
    if (*(short *)(puVar9 + 0x16) < 0) {
      *(undefined2 *)(puVar9 + 0x16) = 0;
    }
    if (DAT_803dd63c == 0) {
      FUN_8005524c(0,0,(int)*(short *)(puVar9 + 0x14),(int)*(short *)(puVar9 + 0x16),
                   (int)*(short *)(puVar9 + 0x14) + (uint)*(ushort *)(puVar9 + 8),
                   (int)*(short *)(puVar9 + 0x16) + (uint)*(ushort *)(puVar9 + 10));
    }
  }
  else {
    FUN_8005524c(0,0,0,0,0x280,0x1e0);
  }
  for (iVar7 = 0; iVar7 < (int)(uint)puVar6[1]; iVar7 = iVar7 + 1) {
    FUN_80015ebc();
  }
  DAT_803dd640 = 0;
  if (DAT_803dd63c == 0) {
    FUN_8000f0d8();
  }
  DAT_803dd624 = uVar1;
  DAT_803dd625 = uVar2;
  DAT_803dd626 = uVar3;
  DAT_803dd627 = uVar4;
  FUN_80286878();
  return;
}

