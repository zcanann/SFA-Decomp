// Function: FUN_80183b8c
// Entry: 80183b8c
// Size: 268 bytes

void FUN_80183b8c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_802860d4();
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  iVar4 = *(int *)(iVar2 + 0xb8);
  iVar3 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(*(int *)(iVar2 + 0x4c) + 0x14));
  if ((iVar3 == 0) ||
     (((sVar1 = *(short *)(iVar4 + 8), sVar1 != 0 && (sVar1 < 0x33)) ||
      (FLOAT_803e39b8 < *(float *)(iVar4 + 4))))) {
    *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
  }
  else {
    if (*(int *)(iVar2 + 0xf8) == 0) {
      if (param_6 == '\0') {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        goto LAB_80183c80;
      }
    }
    else if (param_6 != -1) {
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
      goto LAB_80183c80;
    }
    FUN_8003b8f4((double)FLOAT_803e39ac,iVar2,(int)uVar5,param_3,param_4,param_5);
  }
LAB_80183c80:
  FUN_80286120();
  return;
}

