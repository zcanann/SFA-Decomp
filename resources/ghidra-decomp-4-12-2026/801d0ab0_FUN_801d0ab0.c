// Function: FUN_801d0ab0
// Entry: 801d0ab0
// Size: 444 bytes

void FUN_801d0ab0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  int iVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar3;
  undefined8 extraout_f1;
  undefined8 uVar4;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  FUN_8002bac4();
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x6000;
  uVar1 = FUN_80020078(0x19f);
  if (uVar1 == 0) {
    uVar1 = FUN_80020078(0x19d);
    if (uVar1 == 0) {
      *(undefined *)(pfVar3 + 1) = 0;
    }
    else {
      *(undefined *)(pfVar3 + 1) = 1;
    }
  }
  else {
    *(undefined *)(pfVar3 + 1) = 0xc;
  }
  *pfVar3 = FLOAT_803e5f18;
  FUN_80088afc(&DAT_803276c4,&DAT_8032768c,&DAT_803276fc,&DAT_80327734);
  iVar2 = FUN_800e8a48();
  if (iVar2 == 0) {
    uVar4 = FUN_80088a84(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1f);
    FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x23c,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  else {
    uVar4 = FUN_80088a84(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3f);
    FUN_80008b74(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x23c,0,in_r7,
                 in_r8,in_r9,in_r10);
  }
  (**(code **)(*DAT_803dd72c + 0x50))(7,0,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,2,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,5,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,10,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,0x1c,0);
  (**(code **)(*DAT_803dd72c + 0x50))(7,9,1);
  return;
}

