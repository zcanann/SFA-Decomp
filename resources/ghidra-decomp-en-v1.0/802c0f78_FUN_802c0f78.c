// Function: FUN_802c0f78
// Entry: 802c0f78
// Size: 200 bytes

void FUN_802c0f78(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860d4();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0xb8);
  if (*(int *)(iVar1 + 0xf4) == 0) {
    if (param_6 == -1) {
      FUN_8003b8f4((double)FLOAT_803e83a8);
      FUN_8003842c(iVar1,3,iVar2 + 0xae8,iVar2 + 0xaec,iVar2 + 0xaf0,0);
    }
    if ((*(char *)(iVar2 + 0xbb2) != '\x02') && (param_6 != '\0')) {
      FUN_8003b8f4((double)FLOAT_803e83a8,iVar1,(int)uVar3,param_3,param_4,param_5);
      FUN_80114dec(iVar1,iVar2 + 0x4c4,0);
    }
  }
  FUN_80286120();
  return;
}

