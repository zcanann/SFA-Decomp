// Function: FUN_801fc6f4
// Entry: 801fc6f4
// Size: 624 bytes

undefined4 FUN_801fc6f4(int param_1,undefined4 param_2,int param_3)

{
  char cVar2;
  undefined4 uVar1;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    if ((*(short *)(iVar4 + 8) == 0xd) && (*(char *)(param_3 + iVar3 + 0x81) == '\x14')) {
      FUN_800200e8(0x500,0);
      FUN_800200e8(0xd72,1);
      FUN_800200e8(0xd44,1);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),1,1);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),2,1);
      (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0x16,1);
      cVar2 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
      if (cVar2 == '\x01') {
        FUN_8004350c(0,0,1);
        uVar1 = FUN_800481b0(0x46);
        FUN_80043560(uVar1,1);
        uVar1 = FUN_800481b0(4);
        FUN_80043560(uVar1,0);
        FUN_80042f78(0x46);
        (**(code **)(*DAT_803dcaac + 0x44))(0x12,2);
        FUN_800552e8(0x7c,0);
      }
      else {
        cVar2 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
        if (cVar2 == '\x02') {
          FUN_8004350c(0,0,1);
          uVar1 = FUN_800481b0(0x46);
          FUN_80043560(uVar1,1);
          uVar1 = FUN_800481b0(4);
          FUN_80043560(uVar1,0);
          FUN_80042f78(0x46);
          (**(code **)(*DAT_803dcaac + 0x44))(0xb,4);
          (**(code **)(*DAT_803dcaac + 0x44))(8,6);
          FUN_800552e8(0x7c,0);
        }
      }
    }
    *(undefined *)(param_3 + iVar3 + 0x81) = 0;
  }
  return 0;
}

