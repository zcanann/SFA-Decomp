// Function: FUN_80185a24
// Entry: 80185a24
// Size: 332 bytes

void FUN_80185a24(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  short sVar1;
  int iVar2;
  int *piVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar4 >> 0x20);
  piVar3 = *(int **)(iVar2 + 0xb8);
  if (((*(short *)(piVar3 + 4) == 0) || (0x32 < *(short *)(piVar3 + 4))) && (*piVar3 == 0)) {
    if (*(int *)(iVar2 + 0xf8) == 0) {
      if (param_6 == '\0') goto LAB_80185b58;
    }
    else if (param_6 != -1) goto LAB_80185b58;
    sVar1 = *(short *)((int)piVar3 + 0x1e);
    if (sVar1 != 0) {
      if (sVar1 < 0x3c) {
        *(char *)((int)piVar3 + 0x26) = *(char *)((int)piVar3 + 0x26) + DAT_803db410 * '\n';
        if (0x80 < *(byte *)((int)piVar3 + 0x26)) {
          *(undefined *)((int)piVar3 + 0x26) = 0;
        }
        FUN_8003b5e0(200,0x1e,0x1e,*(undefined *)((int)piVar3 + 0x26));
      }
      else if (sVar1 < 0xf0) {
        *(char *)((int)piVar3 + 0x26) = *(char *)((int)piVar3 + 0x26) + DAT_803db410 * '\x05';
        if (0x80 < *(byte *)((int)piVar3 + 0x26)) {
          *(undefined *)((int)piVar3 + 0x26) = 0;
        }
        FUN_8003b5e0(200,0x1e,0x1e,*(undefined *)((int)piVar3 + 0x26));
      }
    }
    FUN_8003b8f4((double)FLOAT_803e3a5c,iVar2,(int)uVar4,param_3,param_4,param_5);
  }
LAB_80185b58:
  FUN_80286128();
  return;
}

