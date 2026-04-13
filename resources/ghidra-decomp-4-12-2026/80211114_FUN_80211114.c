// Function: FUN_80211114
// Entry: 80211114
// Size: 236 bytes

void FUN_80211114(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  if (*(int *)(param_9 + 0xf8) == 0) {
    uVar1 = FUN_80020078(0xdcb);
    if (uVar1 != 0) {
      uVar3 = FUN_80008b74(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x174,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80008b74(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x1e1,0,in_r7,in_r8,in_r9,in_r10);
      param_1 = FUN_800201ac(0xdcb,0);
      FUN_80043604(0,0,1);
    }
    *(undefined4 *)(param_9 + 0xf4) = 1;
  }
  FUN_80210e44(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  *(byte *)(iVar2 + 9) = *(byte *)(iVar2 + 9) & 0xfe;
  FUN_801d84c4(iVar2 + 0xc,1,-1,-1,0xe24,(int *)0xe8);
  FUN_801d84c4(iVar2 + 0xc,2,-1,-1,0xe24,(int *)0x38);
  return;
}

