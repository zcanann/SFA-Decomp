// Function: FUN_801ba480
// Entry: 801ba480
// Size: 856 bytes

undefined4
FUN_801ba480(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined4 param_9,int param_10)

{
  char cVar1;
  uint uVar2;
  ushort local_18;
  undefined auStack_16 [2];
  short local_14 [4];
  
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
      if ((local_18 < 0x1aa) ||
         (uVar2 = (**(code **)(*DAT_803dd738 + 0x18))((double)FLOAT_803e5850,param_9,param_10),
         (uVar2 & 1) == 0)) {
        if (local_18 < 0xfa) {
          param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,3);
        }
        else {
          if (6 < DAT_803de804) {
            DAT_803de804 = 0;
          }
          cVar1 = *(char *)(param_10 + 0x354);
          if (cVar1 == '\x02') {
            uVar2 = (uint)DAT_803de804;
            DAT_803de804 = DAT_803de804 + 1;
            param_1 = (**(code **)(*DAT_803dd70c + 0x14))
                                (param_9,param_10,(int)*(short *)(&DAT_80326724 + uVar2 * 2));
          }
          else {
            if (cVar1 < '\x02') {
              if ('\0' < cVar1) {
                uVar2 = (uint)DAT_803de804;
                DAT_803de804 = DAT_803de804 + 1;
                param_1 = (**(code **)(*DAT_803dd70c + 0x14))
                                    (param_9,param_10,(int)*(short *)(&DAT_80326734 + uVar2 * 2));
                goto LAB_801ba764;
              }
            }
            else if (cVar1 < '\x04') {
              uVar2 = (uint)DAT_803de804;
              DAT_803de804 = DAT_803de804 + 1;
              param_1 = (**(code **)(*DAT_803dd70c + 0x14))
                                  (param_9,param_10,(int)*(short *)(&DAT_80326714 + uVar2 * 2));
              goto LAB_801ba764;
            }
            param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,3);
          }
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
LAB_801ba764:
  if ((*(short *)(param_10 + 0x274) == 3) || (*(short *)(param_10 + 0x274) == 7)) {
    DAT_803adc4d = DAT_803adc4d | 1;
  }
  else {
    DAT_803adc4d = DAT_803adc4d & 0xfe;
  }
  FUN_801bc88c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return 0;
}

