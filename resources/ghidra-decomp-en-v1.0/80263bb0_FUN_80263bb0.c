// Function: FUN_80263bb0
// Entry: 80263bb0
// Size: 276 bytes

int FUN_80263bb0(undefined4 *param_1,undefined4 param_2,uint param_3,uint param_4,undefined *param_5
                )

{
  int iVar1;
  uint uVar2;
  int local_1c [2];
  
  iVar1 = FUN_80263518(param_1,param_3,param_4,local_1c);
  if (-1 < iVar1) {
    uVar2 = *(int *)(local_1c[0] + 0xc) - 1;
    if (((param_4 & uVar2) == 0) && ((param_3 & uVar2) == 0)) {
      iVar1 = FUN_802608b0();
      iVar1 = FUN_80262d94(local_1c[0],iVar1 + param_1[1] * 0x40);
      if (iVar1 < 0) {
        iVar1 = FUN_8025ee80(local_1c[0]);
      }
      else {
        FUN_80241a1c(param_2,param_3);
        if (param_5 == (undefined *)0x0) {
          param_5 = &DAT_8025de80;
        }
        *(undefined **)(local_1c[0] + 0xd0) = param_5;
        *(undefined4 *)(local_1c[0] + 0xb4) = param_2;
        iVar1 = FUN_8025ec14(*param_1,*(int *)(local_1c[0] + 0xc) * (uint)*(ushort *)(param_1 + 4),
                             &LAB_80263b00);
        if (iVar1 < 0) {
          FUN_8025ee80(local_1c[0],iVar1);
        }
      }
    }
    else {
      iVar1 = FUN_8025ee80(local_1c[0],0xffffff80);
    }
  }
  return iVar1;
}

