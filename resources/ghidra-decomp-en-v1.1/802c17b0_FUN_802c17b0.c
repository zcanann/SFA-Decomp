// Function: FUN_802c17b0
// Entry: 802c17b0
// Size: 380 bytes

void FUN_802c17b0(short *param_1)

{
  short sVar1;
  int iVar2;
  int iVar3;
  short *local_18 [4];
  
  iVar3 = *(int *)(param_1 + 0x5c);
  if ((((*(short *)(iVar3 + 0xbb0) != 0) && (param_1[0x50] != 0xf)) &&
      (iVar2 = FUN_80036974((int)param_1,local_18,(int *)0x0,(uint *)0x0), iVar2 != 0)) &&
     ((iVar2 != 0xf && (*(char *)(iVar3 + 0xbb2) == '\x02')))) {
    sVar1 = *param_1 - *local_18[0];
    if (0x8000 < sVar1) {
      sVar1 = sVar1 + 1;
    }
    if (sVar1 < -0x8000) {
      sVar1 = sVar1 + -1;
    }
    if ((sVar1 < 0x4001) && (-0x4001 < sVar1)) {
      *(byte *)(iVar3 + 0xbc0) = *(byte *)(iVar3 + 0xbc0) & 0xbf | 0x40;
    }
    else {
      *(byte *)(iVar3 + 0xbc0) = *(byte *)(iVar3 + 0xbc0) & 0xbf;
    }
    *(short *)(iVar3 + 0xbb0) = *(short *)(iVar3 + 0xbb0) + -1;
    if (*(short *)(iVar3 + 0xbb0) < 1) {
      (**(code **)(*DAT_803dd6e8 + 0x60))();
      (**(code **)(*DAT_803dd6d4 + 0x48))(5,param_1,0xffffffff);
      *(undefined2 *)(iVar3 + 0xbb0) = 1;
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,iVar3,7);
    }
    FUN_8000bb38((uint)param_1,0x11f);
  }
  return;
}

