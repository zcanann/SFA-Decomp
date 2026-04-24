// Function: FUN_802bf838
// Entry: 802bf838
// Size: 508 bytes

void FUN_802bf838(undefined4 param_1,int param_2,char param_3)

{
  int iVar1;
  undefined4 local_18 [3];
  
  local_18[0] = DAT_803e9038;
  iVar1 = param_2 + 4;
  *(undefined *)(param_2 + 0x25f) = 1;
  if (param_3 == '\x01') {
    (**(code **)(*DAT_803dd728 + 4))(iVar1,0,0x42087,0);
    (**(code **)(*DAT_803dd728 + 8))(iVar1,1,&DAT_80336368,&DAT_803dd3dc,8);
    (**(code **)(*DAT_803dd728 + 0xc))(iVar1,1,&DAT_8033635c,&DAT_803dd3d8,local_18);
  }
  else if (param_3 == '\x02') {
    (**(code **)(*DAT_803dd728 + 4))(iVar1,3,0x42087,0);
    (**(code **)(*DAT_803dd728 + 8))(iVar1,2,&DAT_80336380,&DAT_803dd3e4,8);
    (**(code **)(*DAT_803dd728 + 0xc))(iVar1,1,&DAT_80336374,&DAT_803dd3e0,local_18);
  }
  else if (param_3 == '\0') {
    (**(code **)(*DAT_803dd728 + 4))(iVar1,3,0x42087,0);
    (**(code **)(*DAT_803dd728 + 8))(iVar1,2,&DAT_80336398,&DAT_803dd3ec,8);
    (**(code **)(*DAT_803dd728 + 0xc))(iVar1,1,&DAT_8033638c,&DAT_803dd3e8,local_18);
  }
  (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar1);
  return;
}

