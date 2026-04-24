// Function: FUN_800806f8
// Entry: 800806f8
// Size: 220 bytes

void FUN_800806f8(int param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined local_c;
  
  iVar1 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if (iVar1 != 0x4d) {
    puVar2 = *(undefined4 **)(param_2 + 0x74);
    if (((puVar2 == (undefined4 *)0x0) || (param_1 == 7)) || (param_1 == 6)) {
      local_18 = *(undefined4 *)(param_2 + 0x18);
      local_14 = *(undefined4 *)(param_2 + 0x1c);
      local_10 = *(undefined4 *)(param_2 + 0x20);
    }
    else {
      local_18 = *puVar2;
      local_14 = puVar2[1];
      local_10 = puVar2[2];
    }
    local_c = (undefined)param_1;
    DAT_803ddd7c = param_2;
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x4d,1,0,0x10,&local_18,0,0xff);
  }
  return;
}

