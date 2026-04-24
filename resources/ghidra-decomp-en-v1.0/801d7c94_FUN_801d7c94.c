// Function: FUN_801d7c94
// Entry: 801d7c94
// Size: 576 bytes

void FUN_801d7c94(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = FUN_8001ffb4(0xbf8);
  if (iVar1 != 0) {
    *(undefined *)(param_2 + 7) = 5;
    FUN_800200e8(0xbf8,0);
  }
  if (*(char *)(param_2 + 7) != '\0') {
    if (*(char *)(param_2 + 7) == '\x05') {
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),1,0);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),4,0);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),6,0);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),7,0);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),8,0);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),9,0);
      FUN_800437bc(0x13,0x20000000);
      FUN_800437bc(0x41,0x20000000);
      FUN_800437bc(0x43,0x20000000);
      FUN_800437bc(0x45,0x20000000);
    }
    if (*(char *)(param_2 + 7) == '\x01') {
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0,1);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),2,1);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),3,1);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),5,1);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),10,1);
    }
    *(char *)(param_2 + 7) = *(char *)(param_2 + 7) + -1;
  }
  return;
}

