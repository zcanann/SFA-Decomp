// Function: FUN_80211270
// Entry: 80211270
// Size: 204 bytes

void FUN_80211270(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  piVar3 = *(int **)(iVar1 + 0xb8);
  if (*(int *)(iVar1 + 0xc4) != 0) {
    *piVar3 = *(int *)(iVar1 + 0xc4);
    *(undefined4 *)(iVar1 + 0xc4) = 0;
  }
  iVar2 = FUN_80080150(piVar3 + 5);
  if ((iVar2 == 0) &&
     (iVar2 = FUN_8005b2fc((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x10),
                           (double)*(float *)(iVar1 + 0x14)), iVar2 != -1)) {
    iVar2 = piVar3[1];
    if ((iVar2 != 0) && ((*(char *)(iVar2 + 0x2f8) != '\0' && (*(char *)(iVar2 + 0x4c) != '\0')))) {
      FUN_800604b4();
    }
    FUN_8003b8f4((double)FLOAT_803e6778,iVar1,(int)uVar4,param_3,param_4,param_5);
  }
  FUN_80286124();
  return;
}

