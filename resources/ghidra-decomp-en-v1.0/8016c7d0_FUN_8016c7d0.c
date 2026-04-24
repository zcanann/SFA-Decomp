// Function: FUN_8016c7d0
// Entry: 8016c7d0
// Size: 468 bytes

void FUN_8016c7d0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  undefined auStack648 [48];
  undefined auStack600 [48];
  undefined auStack552 [48];
  undefined auStack504 [48];
  undefined auStack456 [48];
  undefined auStack408 [12];
  float local_18c;
  float local_17c;
  float local_16c;
  undefined auStack360 [48];
  undefined auStack312 [48];
  undefined auStack264 [48];
  undefined auStack216 [48];
  undefined auStack168 [48];
  undefined auStack120 [48];
  undefined auStack72 [72];
  
  uVar3 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  FUN_8016c4ac();
  if ((*(byte *)(*(int *)(iVar1 + 0xb8) + 0x7f) & 4) == 0) {
    FUN_8003b8f4((double)FLOAT_803e3270,iVar1,(int)uVar3,param_3,param_4,param_5);
  }
  else {
    FUN_8002b47c(iVar1,auStack72,0);
    iVar2 = *(int *)(iVar1 + 0x4c);
    FUN_802472e4(-(double)(*(float *)(iVar2 + 8) - FLOAT_803dcdd8),-(double)*(float *)(iVar2 + 0xc),
                 -(double)(*(float *)(iVar2 + 0x10) - FLOAT_803dcddc),auStack120);
    FUN_80246eb4(auStack120,auStack72,auStack168);
    iVar2 = (**(code **)(*DAT_803dca50 + 0xc))();
    *(short *)(iVar2 + 2) = *(short *)(iVar2 + 2) + -0x8000;
    *(float *)(iVar2 + 8) = FLOAT_803e3270;
    FUN_8002b47c(iVar2,auStack408,0);
    *(short *)(iVar2 + 2) = *(short *)(iVar2 + 2) + -0x8000;
    *(float *)(iVar2 + 8) = FLOAT_803e325c;
    FUN_802472e4(-(double)local_18c,-(double)local_17c,-(double)local_16c,auStack216);
    FUN_802470c8((double)FLOAT_803e327c,auStack264,0x79);
    FUN_802470c8((double)FLOAT_803e327c,auStack312,0x7a);
    FUN_802472e4((double)local_18c,(double)local_17c,(double)local_16c,auStack360);
    FUN_80246eb4(auStack216,auStack408,auStack456);
    FUN_80246eb4(auStack264,auStack456,auStack504);
    FUN_80246eb4(auStack312,auStack504,auStack552);
    FUN_80246eb4(auStack360,auStack552,auStack600);
    FUN_80246eb4(auStack600,auStack168,auStack648);
    FUN_800412d4(auStack648);
    FUN_80041ac4(iVar1);
  }
  FUN_80286128();
  return;
}

