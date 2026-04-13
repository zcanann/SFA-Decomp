// Function: FUN_8017bb20
// Entry: 8017bb20
// Size: 788 bytes

void FUN_8017bb20(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  undefined4 *puVar2;
  uint uVar3;
  uint uVar4;
  bool bVar5;
  int iVar6;
  int iVar7;
  ushort *puVar8;
  
  uVar1 = FUN_8028683c();
  puVar8 = *(ushort **)(uVar1 + 0xb8);
  iVar7 = *(int *)(uVar1 + 0x4c);
  if (*(char *)(uVar1 + 0x36) == '\0') {
    FUN_80035ff8(uVar1);
  }
  if (*(char *)(*(int *)(uVar1 + 0x50) + 0x59) != '\0') {
    if (((*(byte *)(puVar8 + 3) & 1) != 0) &&
       (puVar2 = (undefined4 *)FUN_800395a4(uVar1,0), puVar2 != (undefined4 *)0x0)) {
      *puVar2 = 0x100;
    }
    if (((*(byte *)(puVar8 + 3) & 2) != 0) &&
       (puVar2 = (undefined4 *)FUN_800395a4(uVar1,1), puVar2 != (undefined4 *)0x0)) {
      *puVar2 = 0x100;
    }
  }
  if (*(char *)(puVar8 + 2) == '\0') {
    uVar3 = FUN_80020078((int)*(short *)(iVar7 + 0x18));
    bVar5 = false;
    if (((int)*(short *)(iVar7 + 0x22) == 0xffffffff) ||
       (uVar4 = FUN_80020078((int)*(short *)(iVar7 + 0x22)), uVar4 != 0)) {
      bVar5 = true;
    }
    if ((uVar3 != 0) && ((*(byte *)(puVar8 + 3) & 1) == 0)) {
      if (*(char *)(*(int *)(uVar1 + 0x50) + 0x59) != '\0') {
        FUN_8000bb38(uVar1,0x4b);
      }
      *(byte *)(puVar8 + 3) = *(byte *)(puVar8 + 3) | 1;
    }
    if ((bVar5) && ((*(byte *)(puVar8 + 3) & 2) == 0)) {
      if (*(char *)(*(int *)(uVar1 + 0x50) + 0x59) != '\0') {
        FUN_8000bb38(uVar1,0x4b);
      }
      *(byte *)(puVar8 + 3) = *(byte *)(puVar8 + 3) | 2;
    }
    if (*(char *)(puVar8 + 3) == '\x03') {
      *(undefined *)(puVar8 + 2) = 2;
      if (*puVar8 != 0) {
        FUN_8000bb38(uVar1,*puVar8);
      }
    }
  }
  else if ((*(char *)(puVar8 + 2) == '\x01') &&
          (uVar3 = FUN_80020078((int)*(short *)(iVar7 + 0x18)), uVar3 == 0)) {
    *(undefined *)(puVar8 + 2) = 3;
    if (*puVar8 != 0) {
      FUN_8000bb38(uVar1,*puVar8);
    }
  }
  if (*(char *)(puVar8 + 2) == '\x02') {
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
      if (*(char *)(param_3 + iVar6 + 0x81) == '\x02') {
        *(undefined *)(puVar8 + 2) = 1;
        if ((int)*(short *)(iVar7 + 0x1a) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(iVar7 + 0x1a),1);
        }
        if ((*puVar8 != 0) && (bVar5 = FUN_8000b5f0(uVar1,*puVar8), bVar5)) {
          FUN_8000b844(uVar1,*puVar8);
        }
        if (puVar8[1] != 0) {
          FUN_8000bb38(uVar1,puVar8[1]);
        }
      }
    }
  }
  else if (*(char *)(puVar8 + 2) == '\x03') {
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
      if (*(char *)(param_3 + iVar6 + 0x81) == '\x01') {
        *(undefined *)(puVar8 + 2) = 0;
        *(undefined *)(puVar8 + 3) = 0;
        if ((int)*(short *)(iVar7 + 0x1a) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(iVar7 + 0x1a),0);
        }
        if ((*puVar8 != 0) && (bVar5 = FUN_8000b5f0(uVar1,*puVar8), bVar5)) {
          FUN_8000b844(uVar1,*puVar8);
        }
        if (puVar8[1] != 0) {
          FUN_8000bb38(uVar1,puVar8[1]);
        }
      }
    }
  }
  FUN_80286888();
  return;
}

