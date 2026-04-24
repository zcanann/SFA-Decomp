// Function: FUN_801e8ce4
// Entry: 801e8ce4
// Size: 436 bytes

undefined4 FUN_801e8ce4(undefined2 *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  *(code **)(param_3 + 0xe8) = FUN_801e8c50;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffb;
  *(ushort *)(param_3 + 0x70) = *(ushort *)(param_3 + 0x70) & 0xfffb;
  if (*(int *)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4) != 0) {
    FUN_8002fb40((double)FLOAT_803e66f8,(double)FLOAT_803dc074);
  }
  if (param_1[0x23] == 0x467) {
    if (FLOAT_803e66c8 < *(float *)(iVar1 + 0x40)) {
      *(float *)(iVar1 + 0x40) = *(float *)(iVar1 + 0x40) - FLOAT_803e66c8;
      if (*(byte *)(iVar1 + 0x68) < 4) {
        FUN_801f538c(param_1,iVar1);
      }
      else {
        *(byte *)(iVar1 + 0x68) = *(byte *)(iVar1 + 0x68) + 1;
      }
      FUN_801f5504(param_1,iVar1);
    }
    dVar2 = FUN_80010f00((double)*(float *)(iVar1 + 0x40),(float *)(iVar1 + 4),(float *)0x0);
    *(float *)(param_1 + 6) = (float)dVar2;
    dVar2 = FUN_80010f00((double)*(float *)(iVar1 + 0x40),(float *)(iVar1 + 0x14),(float *)0x0);
    *(float *)(param_1 + 8) = (float)dVar2;
    dVar2 = FUN_80010f00((double)*(float *)(iVar1 + 0x40),(float *)(iVar1 + 0x24),(float *)0x0);
    *(float *)(param_1 + 10) = (float)dVar2;
    *(float *)(iVar1 + 0x40) = *(float *)(iVar1 + 0x44) * FLOAT_803dc074 + *(float *)(iVar1 + 0x40);
    iVar1 = FUN_80021884();
    *param_1 = (short)iVar1;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x19f,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x1a0,0,1,0xffffffff,0);
  }
  return 0;
}

