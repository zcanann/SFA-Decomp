// Function: FUN_80185f7c
// Entry: 80185f7c
// Size: 332 bytes

void FUN_80185f7c(void)

{
  short sVar1;
  int iVar2;
  int *piVar3;
  char in_r8;
  
  iVar2 = FUN_80286840();
  piVar3 = *(int **)(iVar2 + 0xb8);
  if (((*(short *)(piVar3 + 4) == 0) || (0x32 < *(short *)(piVar3 + 4))) && (*piVar3 == 0)) {
    if (*(int *)(iVar2 + 0xf8) == 0) {
      if (in_r8 == '\0') goto LAB_801860b0;
    }
    else if (in_r8 != -1) goto LAB_801860b0;
    sVar1 = *(short *)((int)piVar3 + 0x1e);
    if (sVar1 != 0) {
      if (sVar1 < 0x3c) {
        *(char *)((int)piVar3 + 0x26) = *(char *)((int)piVar3 + 0x26) + DAT_803dc070 * '\n';
        if (0x80 < *(byte *)((int)piVar3 + 0x26)) {
          *(undefined *)((int)piVar3 + 0x26) = 0;
        }
        FUN_8003b6d8(200,0x1e,0x1e,*(undefined *)((int)piVar3 + 0x26));
      }
      else if (sVar1 < 0xf0) {
        *(char *)((int)piVar3 + 0x26) = *(char *)((int)piVar3 + 0x26) + DAT_803dc070 * '\x05';
        if (0x80 < *(byte *)((int)piVar3 + 0x26)) {
          *(undefined *)((int)piVar3 + 0x26) = 0;
        }
        FUN_8003b6d8(200,0x1e,0x1e,*(undefined *)((int)piVar3 + 0x26));
      }
    }
    FUN_8003b9ec(iVar2);
  }
LAB_801860b0:
  FUN_8028688c();
  return;
}

