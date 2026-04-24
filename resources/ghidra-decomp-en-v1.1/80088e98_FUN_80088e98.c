// Function: FUN_80088e98
// Entry: 80088e98
// Size: 136 bytes

void FUN_80088e98(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined2 *puVar1;
  int iVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar3;
  
  if (DAT_803dddd4 == 0) {
    puVar1 = FUN_8002becc(0x20,0x62b);
    DAT_803dddc8 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                puVar1,4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    uVar3 = extraout_f1;
    puVar1 = FUN_8002becc(0x20,0x62c);
    DAT_803dddcc = FUN_8002e088(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar1
                                ,4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    DAT_803dddd4 = 1;
    iVar2 = FUN_8002b660(DAT_803dddcc);
    FUN_80028600(iVar2,FUN_8007428c);
  }
  return;
}

