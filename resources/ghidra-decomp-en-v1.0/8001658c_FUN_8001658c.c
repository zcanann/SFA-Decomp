// Function: FUN_8001658c
// Entry: 8001658c
// Size: 644 bytes

void FUN_8001658c(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  undefined uVar4;
  undefined *puVar5;
  int iVar6;
  int iVar7;
  char cVar8;
  int iVar9;
  undefined8 uVar10;
  int local_38;
  int local_34;
  undefined auStack48 [4];
  undefined auStack44 [44];
  
  uVar10 = FUN_802860c8();
  iVar6 = FUN_80019570();
  uVar4 = DAT_803dc9a7;
  uVar3 = DAT_803dc9a6;
  uVar2 = DAT_803dc9a5;
  uVar1 = DAT_803dc9a4;
  DAT_803dc9c0 = 1;
  puVar5 = DAT_803dc9cc;
  if (DAT_803dc9cc == (undefined *)0x0) {
    if (*(byte *)(iVar6 + 4) == 0xff) {
      puVar5 = (undefined *)0x802c7440;
    }
    else {
      puVar5 = &DAT_802c7400 + (uint)*(byte *)(iVar6 + 4) * 0x20;
    }
  }
  if (puVar5 == (undefined *)0x802c84a0) {
    DAT_803dc9a7 = 0xff;
    DAT_803dc9a6 = 0xff;
    DAT_803dc9a5 = 0xff;
    DAT_803dc9a4 = 0xff;
  }
  if (*(char *)(iVar6 + 5) == '\0') {
    puVar5[0x12] = puVar5[0x10];
  }
  *(short *)(puVar5 + 0x18) = (short)uVar10;
  *(short *)(puVar5 + 0x1a) = (short)param_3;
  if (DAT_803dc9bc == 0) {
    cVar8 = *(char *)(iVar6 + 6);
    if (cVar8 == '\0') {
      cVar8 = puVar5[0x11];
    }
    if ((cVar8 == '\x02') || (cVar8 == '\x03')) {
      FUN_8001628c((int)((ulonglong)uVar10 >> 0x20),(int)uVar10,param_3,auStack44,auStack48,
                   &local_34,&local_38);
      iVar7 = (uint)*(ushort *)(puVar5 + 10) - (local_38 - local_34);
      if (cVar8 == '\x02') {
        *(short *)(puVar5 + 0x1a) = (short)(iVar7 / 2);
      }
      else {
        *(short *)(puVar5 + 0x1a) = (short)iVar7;
      }
    }
  }
  if (DAT_803dc9bc == 0) {
    FUN_8001be90(iVar6,0,puVar5);
  }
  if (DAT_803dc96c == 0) {
    if (*(short *)(puVar5 + 0x14) < 0) {
      *(undefined2 *)(puVar5 + 0x14) = 0;
    }
    if (*(short *)(puVar5 + 0x16) < 0) {
      *(undefined2 *)(puVar5 + 0x16) = 0;
    }
    if (DAT_803dc9bc == 0) {
      FUN_800550d0(0,0,(int)*(short *)(puVar5 + 0x14),(int)*(short *)(puVar5 + 0x16),
                   (int)*(short *)(puVar5 + 0x14) + (uint)*(ushort *)(puVar5 + 8),
                   (int)*(short *)(puVar5 + 0x16) + (uint)*(ushort *)(puVar5 + 10));
    }
  }
  else {
    FUN_800550d0(0,0,0,0,0x280,0x1e0);
  }
  iVar7 = 0;
  puVar5 = puVar5 + 0x7fd38c00;
  for (iVar9 = 0; iVar9 < (int)(uint)*(ushort *)(iVar6 + 2); iVar9 = iVar9 + 1) {
    FUN_80015e84(*(undefined4 *)(*(int *)(iVar6 + 8) + iVar7),
                 ((int)puVar5 >> 5) + (uint)((int)puVar5 < 0 && ((uint)puVar5 & 0x1f) != 0));
    iVar7 = iVar7 + 4;
  }
  DAT_803dc9c0 = 0;
  if (DAT_803dc9bc == 0) {
    FUN_8000f0b8(0);
  }
  DAT_803dc9a4 = uVar1;
  DAT_803dc9a5 = uVar2;
  DAT_803dc9a6 = uVar3;
  DAT_803dc9a7 = uVar4;
  FUN_80286114();
  return;
}

