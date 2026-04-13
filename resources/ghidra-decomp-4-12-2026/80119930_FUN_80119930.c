// Function: FUN_80119930
// Entry: 80119930
// Size: 156 bytes

bool FUN_80119930(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_80246a0c(-0x7fc58498,FUN_801197c8,0,0x803a7b68,0x1000,param_1,1);
  if (iVar1 != 0) {
    FUN_802446f8((undefined4 *)&DAT_803a7f30,&DAT_803a7ec8,10);
    FUN_802446f8((undefined4 *)&DAT_803a7f10,&DAT_803a7ea0,10);
    FUN_802446f8((undefined4 *)&DAT_803a7ef0,&DAT_803a7e78,10);
    DAT_803de308 = 1;
  }
  return iVar1 != 0;
}

