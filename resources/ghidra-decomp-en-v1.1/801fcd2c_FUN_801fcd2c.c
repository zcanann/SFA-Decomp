// Function: FUN_801fcd2c
// Entry: 801fcd2c
// Size: 624 bytes

undefined4
FUN_801fcd2c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  char cVar2;
  undefined4 uVar1;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  undefined8 extraout_f1_00;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  *(undefined2 *)(param_11 + 0x70) = 0xffff;
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar5 = iVar5 + 1) {
    if ((*(short *)(iVar6 + 8) == 0xd) && (*(char *)(param_11 + iVar5 + 0x81) == '\x14')) {
      FUN_800201ac(0x500,0);
      FUN_800201ac(0xd72,1);
      FUN_800201ac(0xd44,1);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),1,1);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),2,1);
      iVar4 = *DAT_803dd72c;
      (**(code **)(iVar4 + 0x50))((int)*(char *)(param_9 + 0xac),0x16,1);
      cVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
      if (cVar2 == '\x01') {
        uVar7 = extraout_f1;
        FUN_80043604(0,0,1);
        uVar1 = FUN_8004832c(0x46);
        FUN_80043658(uVar1,1);
        uVar1 = FUN_8004832c(4);
        FUN_80043658(uVar1,0);
        FUN_80043070(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x46);
        iVar3 = *DAT_803dd72c;
        uVar7 = (**(code **)(iVar3 + 0x44))(0x12,2);
        FUN_80055464(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x7c,'\0',iVar3,
                     iVar4,param_13,param_14,param_15,param_16);
      }
      else {
        cVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0xac));
        if (cVar2 == '\x02') {
          uVar7 = extraout_f1_00;
          FUN_80043604(0,0,1);
          uVar1 = FUN_8004832c(0x46);
          FUN_80043658(uVar1,1);
          uVar1 = FUN_8004832c(4);
          FUN_80043658(uVar1,0);
          FUN_80043070(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x46);
          (**(code **)(*DAT_803dd72c + 0x44))(0xb,4);
          iVar3 = *DAT_803dd72c;
          uVar7 = (**(code **)(iVar3 + 0x44))(8,6);
          FUN_80055464(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x7c,'\0',iVar3
                       ,iVar4,param_13,param_14,param_15,param_16);
        }
      }
    }
    *(undefined *)(param_11 + iVar5 + 0x81) = 0;
  }
  return 0;
}

