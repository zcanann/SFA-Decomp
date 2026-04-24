// Function: FUN_802bf0c8
// Entry: 802bf0c8
// Size: 508 bytes

void FUN_802bf0c8(undefined4 param_1,int param_2,char param_3)

{
  int iVar1;
  undefined4 local_18 [3];
  
  local_18[0] = DAT_803e83a0;
  iVar1 = param_2 + 4;
  *(undefined *)(param_2 + 0x25f) = 1;
  if (param_3 == '\x01') {
    (**(code **)(*DAT_803dcaa8 + 4))(iVar1,0,0x42087,0);
    (**(code **)(*DAT_803dcaa8 + 8))(iVar1,1,&DAT_80335708,&DAT_803dc774,8);
    (**(code **)(*DAT_803dcaa8 + 0xc))(iVar1,1,&DAT_803356fc,&DAT_803dc770,local_18);
  }
  else if (param_3 == '\x02') {
    (**(code **)(*DAT_803dcaa8 + 4))(iVar1,3,0x42087,0);
    (**(code **)(*DAT_803dcaa8 + 8))(iVar1,2,&DAT_80335720,&DAT_803dc77c,8);
    (**(code **)(*DAT_803dcaa8 + 0xc))(iVar1,1,&DAT_80335714,&DAT_803dc778,local_18);
  }
  else if (param_3 == '\0') {
    (**(code **)(*DAT_803dcaa8 + 4))(iVar1,3,0x42087,0);
    (**(code **)(*DAT_803dcaa8 + 8))(iVar1,2,&DAT_80335738,&DAT_803dc784,8);
    (**(code **)(*DAT_803dcaa8 + 0xc))(iVar1,1,&DAT_8033572c,&DAT_803dc780,local_18);
  }
  (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar1);
  return;
}

