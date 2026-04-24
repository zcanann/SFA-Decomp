// Function: FUN_8015d6b4
// Entry: 8015d6b4
// Size: 192 bytes

void FUN_8015d6b4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0xb8);
  if (((param_6 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) && (*(short *)(iVar2 + 0x402) != 0)) {
    if (*(float *)(iVar2 + 1000) != FLOAT_803e2d14) {
      FUN_8003b5e0(200,0,0,(int)*(float *)(iVar2 + 1000));
    }
    FUN_8003b8f4((double)FLOAT_803e2d48,iVar1,(int)uVar3,param_3,param_4,param_5);
    FUN_8015ce68(iVar1,iVar2);
  }
  FUN_80286124();
  return;
}

