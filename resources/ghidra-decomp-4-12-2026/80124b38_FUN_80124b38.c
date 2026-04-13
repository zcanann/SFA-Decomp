// Function: FUN_80124b38
// Entry: 80124b38
// Size: 324 bytes

undefined4 FUN_80124b38(int param_1,int *param_2,int param_3)

{
  int iVar1;
  undefined uVar2;
  int iVar3;
  uint3 local_28;
  undefined uStack_25;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  _local_28 = DAT_803e2a90;
  iVar3 = FUN_800284e8(*param_2,param_3);
  iVar3 = *(byte *)(iVar3 + 0x29) - 1;
  FUN_80052a6c();
  if ((-1 < iVar3) && (iVar3 < 7)) {
    if ((&DAT_803aa024)[iVar3] != 0) {
      if ((&DAT_803aa008)[iVar3] == 0) {
        uStack_1c = (uint)*(byte *)(param_1 + 0x37);
        local_20 = 0x43300000;
        iVar1 = (int)(FLOAT_803e2c90 *
                     (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2b08));
        local_18 = (longlong)iVar1;
        uVar2 = (undefined)iVar1;
      }
      else {
        uVar2 = *(undefined *)(param_1 + 0x37);
      }
      _local_28 = CONCAT31(local_28,uVar2);
      FUN_80052134((&DAT_803aa024)[iVar3],0,0,(char *)&local_28,0,1);
      goto LAB_80124c18;
    }
  }
  _local_28 = (uint)local_28 << 8;
  FUN_800528e0((char *)&local_28);
LAB_80124c18:
  FUN_80052a38();
  FUN_8025cce8(1,4,5,5);
  FUN_8007048c(0,7,0);
  FUN_80070434(0);
  FUN_8025c754(7,0,0,7,0);
  return 1;
}

