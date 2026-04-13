// Function: FUN_8027bdf4
// Entry: 8027bdf4
// Size: 156 bytes

void FUN_8027bdf4(ushort *param_1,int *param_2,byte param_3,int param_4)

{
  ushort uVar1;
  uint uVar2;
  
  while( true ) {
    uVar1 = *param_1;
    if (uVar1 == 0xffff) break;
    if ((uVar1 & 0x8000) == 0) {
      uVar1 = *param_1;
      param_1 = param_1 + 1;
      FUN_8027bb90((uint)uVar1,param_2,param_3,param_4);
    }
    else {
      for (uVar2 = uVar1 & 0x3fff; (uVar2 & 0xffff) <= (uint)param_1[1]; uVar2 = uVar2 + 1) {
        FUN_8027bb90(uVar2,param_2,param_3,param_4);
      }
      param_1 = param_1 + 2;
    }
  }
  return;
}

