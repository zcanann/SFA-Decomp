// Function: FUN_801ba7d8
// Entry: 801ba7d8
// Size: 660 bytes

undefined4
FUN_801ba7d8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  ushort local_18;
  undefined auStack_16 [2];
  short local_14 [4];
  
  iVar3 = *(int *)(param_9 + 0xb8);
  if ((*(char *)(param_10 + 0x346) != '\0') || (*(char *)(param_10 + 0x27b) != '\0')) {
    (**(code **)(*DAT_803dd738 + 0x14))
              (param_9,*(undefined4 *)(param_10 + 0x2d0),0x10,local_14,auStack_16,&local_18);
    *(undefined *)(param_10 + 0x346) = 0;
    if (local_18 < 0x5a) {
      if ((local_18 < 0x1f) ||
         (((1 < (ushort)(local_14[0] - 3U) && (local_14[0] != 0xb)) && (local_14[0] != 0xc)))) {
        param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,9);
      }
      else {
        param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,2);
      }
    }
    else if ((local_14[0] == 0) || (local_14[0] == 0xf)) {
      *(undefined *)(param_10 + 0x346) = 0;
      if ((local_18 < 0xf1) ||
         (uVar2 = (**(code **)(*DAT_803dd738 + 0x18))((double)FLOAT_803e5854,param_9,param_10),
         (uVar2 & 1) == 0)) {
        if ((*(ushort *)(iVar3 + 0x400) & 4) == 0) {
          param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,3);
        }
        else {
          uVar2 = FUN_80022264(0,1);
          param_1 = (**(code **)(*DAT_803dd70c + 0x14))
                              (param_9,param_10,(int)*(short *)(&DAT_803dcba0 + uVar2 * 2));
        }
      }
      else {
        uVar2 = FUN_80022264(0,5);
        param_1 = (**(code **)(*DAT_803dd70c + 0x14))
                            (param_9,param_10,(int)*(short *)(&DAT_80326708 + uVar2 * 2));
      }
    }
    else {
      param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,2);
    }
  }
  sVar1 = *(short *)(param_10 + 0x274);
  if (((sVar1 == 1) || (sVar1 == 4)) || (sVar1 == 5)) {
    DAT_803adc4d = DAT_803adc4d & 0xfe;
  }
  else {
    DAT_803adc4d = DAT_803adc4d | 1;
  }
  FUN_801bc88c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return 0;
}

