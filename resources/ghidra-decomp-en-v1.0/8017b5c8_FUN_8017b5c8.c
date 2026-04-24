// Function: FUN_8017b5c8
// Entry: 8017b5c8
// Size: 788 bytes

void FUN_8017b5c8(undefined4 param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  short *psVar8;
  
  iVar2 = FUN_802860d8();
  psVar8 = *(short **)(iVar2 + 0xb8);
  iVar7 = *(int *)(iVar2 + 0x4c);
  if (*(char *)(iVar2 + 0x36) == '\0') {
    FUN_80035f00();
  }
  if (*(char *)(*(int *)(iVar2 + 0x50) + 0x59) != '\0') {
    if (((*(byte *)(psVar8 + 3) & 1) != 0) &&
       (puVar3 = (undefined4 *)FUN_800394ac(iVar2,0,0), puVar3 != (undefined4 *)0x0)) {
      *puVar3 = 0x100;
    }
    if (((*(byte *)(psVar8 + 3) & 2) != 0) &&
       (puVar3 = (undefined4 *)FUN_800394ac(iVar2,1,0), puVar3 != (undefined4 *)0x0)) {
      *puVar3 = 0x100;
    }
  }
  if (*(char *)(psVar8 + 2) == '\0') {
    iVar4 = FUN_8001ffb4((int)*(short *)(iVar7 + 0x18));
    bVar1 = false;
    if ((*(short *)(iVar7 + 0x22) == -1) || (iVar5 = FUN_8001ffb4(), iVar5 != 0)) {
      bVar1 = true;
    }
    if ((iVar4 != 0) && ((*(byte *)(psVar8 + 3) & 1) == 0)) {
      if (*(char *)(*(int *)(iVar2 + 0x50) + 0x59) != '\0') {
        FUN_8000bb18(iVar2,0x4b);
      }
      *(byte *)(psVar8 + 3) = *(byte *)(psVar8 + 3) | 1;
    }
    if ((bVar1) && ((*(byte *)(psVar8 + 3) & 2) == 0)) {
      if (*(char *)(*(int *)(iVar2 + 0x50) + 0x59) != '\0') {
        FUN_8000bb18(iVar2,0x4b);
      }
      *(byte *)(psVar8 + 3) = *(byte *)(psVar8 + 3) | 2;
    }
    if ((*(char *)(psVar8 + 3) == '\x03') && (*(undefined *)(psVar8 + 2) = 2, *psVar8 != 0)) {
      FUN_8000bb18(iVar2);
    }
  }
  else if (((*(char *)(psVar8 + 2) == '\x01') &&
           (iVar4 = FUN_8001ffb4((int)*(short *)(iVar7 + 0x18)), iVar4 == 0)) &&
          (*(undefined *)(psVar8 + 2) = 3, *psVar8 != 0)) {
    FUN_8000bb18(iVar2);
  }
  if (*(char *)(psVar8 + 2) == '\x02') {
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
      if (*(char *)(param_3 + iVar4 + 0x81) == '\x02') {
        *(undefined *)(psVar8 + 2) = 1;
        if (*(short *)(iVar7 + 0x1a) != -1) {
          FUN_800200e8((int)*(short *)(iVar7 + 0x1a),1);
        }
        if ((*psVar8 != 0) && (iVar5 = FUN_8000b5d0(iVar2), iVar5 != 0)) {
          FUN_8000b824(iVar2,*psVar8);
        }
        if (psVar8[1] != 0) {
          FUN_8000bb18(iVar2);
        }
      }
    }
  }
  else if (*(char *)(psVar8 + 2) == '\x03') {
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
      if (*(char *)(param_3 + iVar4 + 0x81) == '\x01') {
        *(undefined *)(psVar8 + 2) = 0;
        *(undefined *)(psVar8 + 3) = 0;
        if (*(short *)(iVar7 + 0x1a) != -1) {
          FUN_800200e8((int)*(short *)(iVar7 + 0x1a),0);
        }
        if ((*psVar8 != 0) && (iVar5 = FUN_8000b5d0(iVar2), iVar5 != 0)) {
          FUN_8000b824(iVar2,*psVar8);
        }
        if (psVar8[1] != 0) {
          FUN_8000bb18(iVar2);
        }
      }
    }
  }
  uVar6 = 0;
  if ((*(char *)(psVar8 + 2) != '\x02') && (*(char *)(psVar8 + 2) != '\x03')) {
    uVar6 = 1;
  }
  FUN_80286124(uVar6);
  return;
}

