// Function: FUN_80028b54
// Entry: 80028b54
// Size: 540 bytes

void FUN_80028b54(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  undefined2 local_30;
  undefined2 local_2e;
  undefined2 local_2c;
  undefined auStack40 [40];
  
  uVar4 = FUN_802860dc();
  piVar1 = (int *)((ulonglong)uVar4 >> 0x20);
  FUN_80028664(param_3,piVar1[0xb],(int)uVar4);
  *(ushort *)(piVar1 + 6) = *(ushort *)(piVar1 + 6) ^ 1;
  iVar3 = piVar1[0xb];
  if ((*(byte *)(iVar3 + 99) & 4) != 0) {
    FUN_80027e00((double)*(float *)(param_3 + 0x98),(double)*(float *)(param_3 + 8),piVar1,0,0,
                 auStack40,&local_30);
    DAT_803dc7a4 = local_30;
    DAT_803dc7a6 = local_2e;
    DAT_803dc7a8 = local_2c;
  }
  if ((*(ushort *)(*piVar1 + 2) & 8) == 0) {
    if ((*(byte *)(piVar1[0xb] + 99) & 8) == 0) {
      FUN_800248b8((double)*(float *)(param_3 + 0x98),param_4,piVar1,piVar1[0xb],0x7f);
      if ((piVar1[0xc] != 0) && (-1 < *(short *)(param_3 + 0xa2))) {
        FUN_80028664(param_3,piVar1[0xc],(int)uVar4);
        FUN_800248b8((double)*(float *)(param_3 + 0x9c),param_4,piVar1,piVar1[0xc],0xffffffff);
      }
    }
    else {
      iVar2 = piVar1[0xc];
      FUN_800246a0((double)*(float *)(param_3 + 0x98),param_4,piVar1,iVar3,0x7f,0,0,2,0x14,
                   (int)*(short *)(iVar3 + 0x5a));
      FUN_800246a0((double)*(float *)(param_3 + 0x9c),param_4,piVar1,iVar2,0x7f,0,0,2,0x18,
                   (int)*(short *)(iVar2 + 0x5a));
      FUN_800246a0((double)*(float *)(param_3 + 0x98),param_4,piVar1,iVar3,0x7f,0,0,0,7,
                   (int)*(short *)(iVar2 + 0x58));
      FUN_800246a0((double)*(float *)(param_3 + 0x98),param_4,piVar1,iVar3,0x7f,0,1,1,1,
                   (int)*(short *)(iVar3 + 0x58));
    }
  }
  else {
    FUN_800248b8((double)*(float *)(param_3 + 0x98),param_4,piVar1,piVar1[0xb],0x7f);
  }
  FUN_80286128();
  return;
}

