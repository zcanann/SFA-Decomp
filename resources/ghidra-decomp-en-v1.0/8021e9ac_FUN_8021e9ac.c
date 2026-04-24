// Function: FUN_8021e9ac
// Entry: 8021e9ac
// Size: 364 bytes

void FUN_8021e9ac(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  int local_28 [10];
  
  uVar5 = FUN_802860d0();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  iVar4 = *(int *)(iVar1 + 0xb8);
  if (param_6 == '\0') {
    *(byte *)(iVar4 + 0xc49) = *(byte *)(iVar4 + 0xc49) & 0xfb;
  }
  else {
    FUN_8003b8f4((double)FLOAT_803e6ab8);
    FUN_8003842c(iVar1,2,iVar4 + 0xb6c,iVar4 + 0xb70,iVar4 + 0xb74,0);
    FUN_80038280(iVar1,3,4,iVar4 + 0xb18);
    FUN_8003842c(iVar1,0,iVar4 + 0xb78,iVar4 + 0xb7c,iVar4 + 0xb80,0);
    *(byte *)(iVar4 + 0xc49) = *(byte *)(iVar4 + 0xc49) & 0xfb | 4;
    FUN_80114dec(iVar1,iVar4 + 0x3ec,0);
    if ((*(byte *)(iVar4 + 0xc49) >> 6 & 1) != 0) {
      piVar2 = (int *)FUN_80036f50(0x37,local_28);
      for (iVar4 = 0; iVar4 < local_28[0]; iVar4 = iVar4 + 1) {
        iVar3 = (**(code **)(**(int **)(*piVar2 + 0x68) + 0x24))();
        (**(code **)(**(int **)(*piVar2 + 0x68) + 0x20))
                  (*piVar2,iVar1,*(undefined4 *)(&DAT_8032ab48 + iVar3 * 4),(int)uVar5,param_3,
                   param_4,param_5);
        piVar2 = piVar2 + 1;
      }
    }
  }
  FUN_8028611c();
  return;
}

