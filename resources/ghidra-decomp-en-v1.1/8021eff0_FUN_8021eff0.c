// Function: FUN_8021eff0
// Entry: 8021eff0
// Size: 364 bytes

void FUN_8021eff0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  short *psVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  int local_28 [10];
  
  uVar5 = FUN_80286834();
  psVar1 = (short *)((ulonglong)uVar5 >> 0x20);
  iVar4 = *(int *)(psVar1 + 0x5c);
  if (param_6 == '\0') {
    *(byte *)(iVar4 + 0xc49) = *(byte *)(iVar4 + 0xc49) & 0xfb;
  }
  else {
    FUN_8003b9ec((int)psVar1);
    FUN_80038524(psVar1,2,(float *)(iVar4 + 0xb6c),(undefined4 *)(iVar4 + 0xb70),
                 (float *)(iVar4 + 0xb74),0);
    FUN_80038378(psVar1,3,4,(float *)(iVar4 + 0xb18));
    FUN_80038524(psVar1,0,(float *)(iVar4 + 0xb78),(undefined4 *)(iVar4 + 0xb7c),
                 (float *)(iVar4 + 0xb80),0);
    *(byte *)(iVar4 + 0xc49) = *(byte *)(iVar4 + 0xc49) & 0xfb | 4;
    FUN_80115088(psVar1,iVar4 + 0x3ec,0);
    if ((*(byte *)(iVar4 + 0xc49) >> 6 & 1) != 0) {
      piVar2 = FUN_80037048(0x37,local_28);
      for (iVar4 = 0; iVar4 < local_28[0]; iVar4 = iVar4 + 1) {
        iVar3 = (**(code **)(**(int **)(*piVar2 + 0x68) + 0x24))();
        (**(code **)(**(int **)(*piVar2 + 0x68) + 0x20))
                  (*piVar2,psVar1,*(undefined4 *)(&DAT_8032b7a0 + iVar3 * 4),(int)uVar5,param_3,
                   param_4,param_5);
        piVar2 = piVar2 + 1;
      }
    }
  }
  FUN_80286880();
  return;
}

