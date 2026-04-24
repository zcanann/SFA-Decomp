// Function: FUN_80230fc8
// Entry: 80230fc8
// Size: 268 bytes

undefined4
FUN_80230fc8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            undefined4 param_10,int param_11)

{
  char cVar1;
  int unaff_r30;
  int iVar2;
  
  *(code **)(param_11 + 0xe8) = FUN_80230f78;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar2 = iVar2 + 1) {
    cVar1 = *(char *)(param_11 + iVar2 + 0x81);
    if (cVar1 == '\x01') {
      param_1 = (**(code **)(*DAT_803dd6d4 + 0x50))(0x56,0,0,0);
    }
    else if (cVar1 == '\x04') {
      cVar1 = *(char *)(param_9 + 0xac);
      if (cVar1 == '<') {
        unaff_r30 = 2;
      }
      else if (cVar1 < '<') {
        if (cVar1 == ':') {
          unaff_r30 = 0;
        }
        else if ('9' < cVar1) {
          unaff_r30 = 1;
        }
      }
      else if (cVar1 == '>') {
        unaff_r30 = 3;
      }
      else if (cVar1 < '>') {
        unaff_r30 = 4;
      }
      param_1 = FUN_80125e88(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             unaff_r30);
    }
  }
  return 0;
}

