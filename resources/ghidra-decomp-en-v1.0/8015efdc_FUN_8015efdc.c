// Function: FUN_8015efdc
// Entry: 8015efdc
// Size: 180 bytes

void FUN_8015efdc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  float fVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar3 >> 0x20);
  if (((param_6 != '\0') && (*(int *)(iVar2 + 0xf4) == 0)) &&
     (*(short *)(*(int *)(iVar2 + 0xb8) + 0x402) != 0)) {
    fVar1 = *(float *)(*(int *)(iVar2 + 0xb8) + 1000);
    if (fVar1 != FLOAT_803e2dc8) {
      FUN_8003b5e0(200,0,0,(int)fVar1);
    }
    FUN_8003b8f4((double)FLOAT_803e2e10,iVar2,(int)uVar3,param_3,param_4,param_5);
  }
  FUN_80286128();
  return;
}

