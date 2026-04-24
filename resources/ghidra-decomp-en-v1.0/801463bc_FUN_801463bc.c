// Function: FUN_801463bc
// Entry: 801463bc
// Size: 464 bytes

void FUN_801463bc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860cc();
  iVar2 = (int)((ulonglong)uVar7 >> 0x20);
  if (param_6 != '\0') {
    iVar6 = *(int *)(iVar2 + 0xb8);
    FUN_8003b8f4((double)FLOAT_803e23e8);
    iVar4 = *(int *)(iVar2 + 0xb8);
    iVar5 = 0;
    iVar3 = iVar4;
    do {
      FUN_8003842c(iVar2,iVar5 + 4,iVar3 + 0x3d8,iVar3 + 0x3dc,iVar3 + 0x3e0,0);
      iVar3 = iVar3 + 0xc;
      iVar5 = iVar5 + 1;
    } while (iVar5 < 4);
    FUN_8003842c(iVar2,8,iVar4 + 0x408,iVar4 + 0x40c,iVar4 + 0x410,0);
    iVar3 = FUN_800395d8(iVar2,0);
    *(undefined2 *)(iVar4 + 0x414) = *(undefined2 *)(iVar3 + 2);
    if ((*(uint *)(iVar6 + 0x54) & 0x10) != 0) {
      bVar1 = *(byte *)(iVar6 + 8);
      if (bVar1 == 3) {
        if (*(char *)(iVar6 + 10) == '\x04') {
          FUN_8013adfc(iVar2);
        }
      }
      else if ((bVar1 < 3) && (1 < bVar1)) {
        FUN_8013adfc(iVar2);
      }
      if ((((*(uint *)(iVar6 + 0x54) & 0x200) == 0) && (*(char *)(iVar6 + 8) == '\v')) &&
         (2 < *(byte *)(iVar6 + 10))) {
        if (*(byte *)(iVar6 + 10) != 3) {
          *(undefined4 *)(*(int *)(iVar6 + 0x700) + 0xc) = *(undefined4 *)(iVar6 + 0x408);
          *(undefined4 *)(*(int *)(iVar6 + 0x700) + 0x10) = *(undefined4 *)(iVar6 + 0x40c);
          *(undefined4 *)(*(int *)(iVar6 + 0x700) + 0x14) = *(undefined4 *)(iVar6 + 0x410);
        }
        FUN_8003b8f4((double)FLOAT_803e23e8,*(undefined4 *)(iVar6 + 0x700),(int)uVar7,param_3,
                     param_4,param_5);
      }
    }
    FUN_80139164(iVar2,iVar6);
    FUN_80038280(iVar2,4,4,iVar6 + 0x7d8);
    *(float *)(iVar6 + 0x838) = *(float *)(iVar6 + 0x838) - FLOAT_803db414;
    if (FLOAT_803e23dc < *(float *)(iVar6 + 0x838)) {
      FUN_80099d84((double)FLOAT_803e253c,(double)FLOAT_803e23e8,iVar2,6,0);
    }
  }
  FUN_80286118();
  return;
}

