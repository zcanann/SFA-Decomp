// Function: FUN_801847f4
// Entry: 801847f4
// Size: 316 bytes

void FUN_801847f4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860d4();
  iVar1 = (int)((ulonglong)uVar7 >> 0x20);
  iVar5 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_8002b588();
  if (*(short *)(iVar1 + 0x46) == 0x3d6) {
    iVar4 = 0;
    pcVar3 = &DAT_803dbdbc;
    iVar6 = 7;
    do {
      if (*pcVar3 == *(char *)(*(int *)(iVar2 + 0x34) + 8)) {
        iVar4 = iVar4 + 1;
        if (iVar4 == 7) {
          iVar4 = 0;
        }
        *(undefined *)(*(int *)(iVar2 + 0x34) + 8) = (&DAT_803dbdbc)[iVar4];
        break;
      }
      pcVar3 = pcVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
  }
  if (*(short *)(iVar5 + 0x10) == 0) {
    if (*(int *)(iVar1 + 0xf8) == 0) {
      if (param_6 == '\0') goto LAB_80184918;
    }
    else if (param_6 != -1) goto LAB_80184918;
    FUN_8003b8f4((double)FLOAT_803e3a00,iVar1,(int)uVar7,param_3,param_4,param_5);
    if ((param_6 != '\0') && (*(char *)(iVar1 + 0x36) != '\0')) {
      FUN_800972dc((double)FLOAT_803e3a00,(double)FLOAT_803e3a04,iVar1,5,
                   *(ushort *)(iVar5 + 0x22) & 0xff,1,0x14,0,0);
    }
  }
LAB_80184918:
  FUN_80286120();
  return;
}

