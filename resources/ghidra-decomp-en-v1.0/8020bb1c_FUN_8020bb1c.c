// Function: FUN_8020bb1c
// Entry: 8020bb1c
// Size: 148 bytes

void FUN_8020bb1c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  int iVar1;
  int iVar2;
  double dVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0xb8);
  if (*(short *)(iVar1 + 0x46) == 0x709) {
    dVar3 = (double)*(float *)(iVar2 + 0x68);
    if (dVar3 < (double)FLOAT_803e6590) {
      dVar3 = (double)FLOAT_803e658c;
    }
    FUN_80221978(dVar3,iVar1,iVar2 + 0x14,3,iVar2 + 100);
  }
  FUN_8003b8f4((double)FLOAT_803e6594,iVar1,(int)uVar4,param_3,param_4,param_5);
  FUN_80286128();
  return;
}

