// Function: FUN_801d04e0
// Entry: 801d04e0
// Size: 444 bytes

void FUN_801d04e0(int param_1)

{
  int iVar1;
  float *pfVar2;
  
  pfVar2 = *(float **)(param_1 + 0xb8);
  FUN_8002b9ec();
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  iVar1 = FUN_8001ffb4(0x19f);
  if (iVar1 == 0) {
    iVar1 = FUN_8001ffb4(0x19d);
    if (iVar1 == 0) {
      *(undefined *)(pfVar2 + 1) = 0;
    }
    else {
      *(undefined *)(pfVar2 + 1) = 1;
    }
  }
  else {
    *(undefined *)(pfVar2 + 1) = 0xc;
  }
  *pfVar2 = FLOAT_803e5280;
  FUN_80088870(&DAT_80326a84,&DAT_80326a4c,&DAT_80326abc,&DAT_80326af4);
  iVar1 = FUN_800e87c4();
  if (iVar1 == 0) {
    FUN_800887f8(0x1f);
    FUN_80008cbc(0,0,0x23c,0);
  }
  else {
    FUN_800887f8(0x3f);
    FUN_80008b74(0,0,0x23c,0);
  }
  (**(code **)(*DAT_803dcaac + 0x50))(7,0,0);
  (**(code **)(*DAT_803dcaac + 0x50))(7,2,0);
  (**(code **)(*DAT_803dcaac + 0x50))(7,5,0);
  (**(code **)(*DAT_803dcaac + 0x50))(7,10,0);
  (**(code **)(*DAT_803dcaac + 0x50))(7,0x1c,0);
  (**(code **)(*DAT_803dcaac + 0x50))(7,9,1);
  return;
}

