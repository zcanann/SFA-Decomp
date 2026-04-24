// Function: FUN_80230904
// Entry: 80230904
// Size: 268 bytes

undefined4 FUN_80230904(int param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  undefined4 unaff_r30;
  int iVar2;
  
  *(code **)(param_3 + 0xe8) = FUN_802308b4;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    cVar1 = *(char *)(param_3 + iVar2 + 0x81);
    if (cVar1 == '\x01') {
      (**(code **)(*DAT_803dca54 + 0x50))(0x56,0,0,0);
    }
    else if (cVar1 == '\x04') {
      cVar1 = *(char *)(param_1 + 0xac);
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
      FUN_80125ba4(unaff_r30);
    }
  }
  return 0;
}

