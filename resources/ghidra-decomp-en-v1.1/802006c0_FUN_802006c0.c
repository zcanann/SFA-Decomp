// Function: FUN_802006c0
// Entry: 802006c0
// Size: 572 bytes

void FUN_802006c0(void)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined8 uVar9;
  float local_28;
  undefined auStack_24 [36];
  
  uVar9 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  iVar6 = (int)uVar9;
  iVar7 = *(int *)(iVar2 + 0x4c);
  local_28 = FLOAT_803e6f44;
  puVar8 = *(undefined4 **)(*(int *)(iVar2 + 0xb8) + 0x40c);
  if ((*(char *)(iVar6 + 0x27b) == '\0') && ((*(byte *)(puVar8 + 0x11) >> 6 & 1) == 0)) {
    if ((puVar8[6] == 0) && (FLOAT_803e6f48 < (float)puVar8[0xe])) {
      puVar8[0xe] = (float)puVar8[0xe] - FLOAT_803e6f48;
      local_28 = FLOAT_803e6f4c;
      iVar1 = 3;
      puVar8 = (undefined4 *)0x8032a348;
      iVar7 = 0;
      while( true ) {
        puVar8 = puVar8 + -1;
        iVar1 = iVar1 + -1;
        if (iVar1 < 0) break;
        iVar5 = FUN_80036e58(*puVar8,iVar2,&local_28);
        if (iVar5 != 0) {
          iVar7 = iVar5;
        }
      }
      *(int *)(iVar6 + 0x2d0) = iVar7;
      if (iVar7 != 0) {
        if (FLOAT_803e6f50 <= local_28) {
          (**(code **)(*DAT_803dd70c + 0x14))(iVar2,iVar6,4);
        }
        else {
          (**(code **)(*DAT_803dd70c + 0x14))(iVar2,iVar6,2);
        }
      }
    }
  }
  else {
    *(byte *)((int)puVar8 + 0x15) = *(byte *)((int)puVar8 + 0x15) & 0xfb;
    *(byte *)(puVar8 + 0x11) = *(byte *)(puVar8 + 0x11) & 0xbf;
    uVar3 = FUN_800138d4((short *)puVar8[9]);
    if (uVar3 == 0) {
      FUN_80013900((short *)puVar8[9],(uint)auStack_24);
    }
    iVar1 = puVar8[8] - *(int *)*puVar8;
    iVar1 = iVar1 / 0xc + (iVar1 >> 0x1f);
    if ((int)*(short *)((int *)*puVar8 + 1) <= iVar1 - (iVar1 >> 0x1f)) {
      puVar8[8] = 0;
    }
    if (puVar8[8] == 0) {
      puVar8[8] = *(undefined4 *)*puVar8;
      *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar7 + 8);
      *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar7 + 0xc);
      *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(iVar7 + 0x10);
    }
    if (*(int *)(puVar8[8] + 4) != 0) {
      uVar4 = FUN_80036e58(*(int *)(puVar8[8] + 4),iVar2,&local_28);
      *(undefined4 *)(iVar6 + 0x2d0) = uVar4;
    }
    if (*(int *)(iVar6 + 0x2d0) != 0) {
      (**(code **)(*DAT_803dd70c + 0x14))(iVar2,iVar6,*(undefined4 *)puVar8[8]);
    }
  }
  FUN_8028688c();
  return;
}

