// Function: FUN_80235904
// Entry: 80235904
// Size: 200 bytes

void FUN_80235904(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0x4c);
  iVar3 = *(int *)(iVar1 + 0xb8);
  if (param_6 != '\0') {
    FUN_8003b608(*(undefined *)(iVar2 + 0x20),*(undefined *)(iVar2 + 0x21),
                 *(undefined *)(iVar2 + 0x22));
    FUN_8003b8f4((double)FLOAT_803e7308,iVar1,(int)uVar4,param_3,param_4,param_5);
    if ((*(ushort *)(iVar3 + 0x58) & 0x80) != 0) {
      iVar2 = 0;
      do {
        FUN_8003842c(iVar1,iVar2,iVar3 + 0xc,iVar3 + 0x10,iVar3 + 0x14,0);
        iVar3 = iVar3 + 0xc;
        iVar2 = iVar2 + 1;
      } while (iVar2 < 3);
    }
    *(undefined4 *)(iVar1 + 0xf8) = 1;
  }
  FUN_80286124();
  return;
}

