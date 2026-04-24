// Function: FUN_80168bfc
// Entry: 80168bfc
// Size: 268 bytes

void FUN_80168bfc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0xb8);
  if ((param_6 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) {
    if (*(float *)(iVar2 + 1000) != FLOAT_803e3060) {
      FUN_8003b5e0(200,0,0,(int)*(float *)(iVar2 + 1000));
    }
    FUN_8003b8f4((double)FLOAT_803e3078,iVar1,(int)uVar3,param_3,param_4,param_5);
    if ((*(ushort *)(iVar2 + 0x400) & 0x60) != 0) {
      FUN_80099d84((double)FLOAT_803e3078,(double)*(float *)(iVar2 + 1000),iVar1,3,0);
    }
    iVar2 = *(int *)(iVar2 + 0x40c);
    FUN_8003842c(iVar1,2,iVar2 + 0x10,iVar2 + 0x14,iVar2 + 0x18,0);
    FUN_8003842c(iVar1,1,iVar2 + 0x28,iVar2 + 0x2c,iVar2 + 0x30,0);
  }
  FUN_80286124();
  return;
}

