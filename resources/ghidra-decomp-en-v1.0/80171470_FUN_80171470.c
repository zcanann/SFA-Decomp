// Function: FUN_80171470
// Entry: 80171470
// Size: 168 bytes

void FUN_80171470(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar4 >> 0x20);
  pfVar3 = *(float **)(iVar2 + 0xb8);
  if ((*(char *)((int)pfVar3 + 9) == '\0') && (param_6 != '\0')) {
    fVar1 = *pfVar3;
    if (fVar1 != FLOAT_803e3400) {
      FUN_8003b5e0(200,0,0,(int)fVar1);
    }
    FUN_8003b8f4((double)FLOAT_803e3404,iVar2,(int)uVar4,param_3,param_4,param_5);
  }
  FUN_80286128();
  return;
}

