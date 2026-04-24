// Function: FUN_801825ec
// Entry: 801825ec
// Size: 252 bytes

void FUN_801825ec(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
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
  if (iVar3 == 0) {
    *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
  }
  else {
    sVar1 = *(short *)(iVar4 + 10);
    if (((sVar1 == 0) || (0x32 < sVar1)) && (*(int *)(iVar4 + 0x14) == 0)) {
      if ((*(int *)(iVar2 + 0xf8) == 0) || (param_6 == -1)) {
        FUN_8003b8f4((double)FLOAT_803e3950,iVar2,(int)uVar5,param_3,param_4,param_5);
      }
      else {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
      }
    }
    else {
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
    }
  }
  FUN_80286120();
  return;
}

