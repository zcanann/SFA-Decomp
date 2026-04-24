// Function: FUN_80223004
// Entry: 80223004
// Size: 276 bytes

undefined4 FUN_80223004(int param_1,undefined4 param_2,int param_3,char param_4)

{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar2 + 0x659) = *(byte *)(iVar2 + 0x659) & 0xfe;
  FUN_8003b310(param_1,iVar2 + 0x624);
  iVar2 = FUN_80114bb0(param_1,param_3,iVar2,0,0);
  if (iVar2 == 0) {
    if (param_4 != '\0') {
      FUN_8002fa48((double)FLOAT_803e6cdc,(double)FLOAT_803db414,param_1,0);
    }
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
      bVar1 = *(byte *)(param_3 + iVar2 + 0x81);
      if (bVar1 == 2) {
        FUN_80008b74(param_1,param_1,0x200,0);
      }
      else if ((bVar1 < 2) && (bVar1 != 0)) {
        FUN_80008b74(param_1,param_1,0x1fd,0);
      }
    }
  }
  return 0;
}

