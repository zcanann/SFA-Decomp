// Function: FUN_801840e4
// Entry: 801840e4
// Size: 268 bytes

void FUN_801840e4(void)

{
  short sVar1;
  int iVar2;
  int iVar3;
  char in_r8;
  int iVar4;
  
  iVar2 = FUN_80286838();
  iVar4 = *(int *)(iVar2 + 0xb8);
  iVar3 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(*(int *)(iVar2 + 0x4c) + 0x14));
  if ((iVar3 == 0) ||
     (((sVar1 = *(short *)(iVar4 + 8), sVar1 != 0 && (sVar1 < 0x33)) ||
      (FLOAT_803e4650 < *(float *)(iVar4 + 4))))) {
    *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
  }
  else {
    if (*(int *)(iVar2 + 0xf8) == 0) {
      if (in_r8 == '\0') {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        goto LAB_801841d8;
      }
    }
    else if (in_r8 != -1) {
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
      goto LAB_801841d8;
    }
    FUN_8003b9ec(iVar2);
  }
LAB_801841d8:
  FUN_80286884();
  return;
}

