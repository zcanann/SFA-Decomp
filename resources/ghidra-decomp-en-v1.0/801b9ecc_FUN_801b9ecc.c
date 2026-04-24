// Function: FUN_801b9ecc
// Entry: 801b9ecc
// Size: 856 bytes

undefined4 FUN_801b9ecc(undefined4 param_1,int param_2)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  ushort local_18;
  undefined auStack22 [2];
  short local_14 [4];
  
  if ((*(char *)(param_2 + 0x346) != '\0') || (*(char *)(param_2 + 0x27b) != '\0')) {
    (**(code **)(*DAT_803dcab8 + 0x14))
              (param_1,*(undefined4 *)(param_2 + 0x2d0),0x10,local_14,auStack22,&local_18);
    *(undefined *)(param_2 + 0x346) = 0;
    if (local_18 < 0x5a) {
      if ((local_18 < 0x1f) ||
         (((1 < (ushort)(local_14[0] - 3U) && (local_14[0] != 0xb)) && (local_14[0] != 0xc)))) {
        (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,9);
      }
      else {
        (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,2);
      }
    }
    else if ((local_14[0] == 0) || (local_14[0] == 0xf)) {
      *(undefined *)(param_2 + 0x346) = 0;
      if ((local_18 < 0x1aa) ||
         (uVar2 = (**(code **)(*DAT_803dcab8 + 0x18))((double)FLOAT_803e4bb8,param_1,param_2),
         (uVar2 & 1) == 0)) {
        if (local_18 < 0xfa) {
          (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,3);
        }
        else {
          if (6 < DAT_803ddb84) {
            DAT_803ddb84 = 0;
          }
          cVar1 = *(char *)(param_2 + 0x354);
          if (cVar1 == '\x02') {
            uVar2 = (uint)DAT_803ddb84;
            DAT_803ddb84 = DAT_803ddb84 + 1;
            (**(code **)(*DAT_803dca8c + 0x14))
                      (param_1,param_2,(int)*(short *)(&DAT_80325ae4 + uVar2 * 2));
          }
          else {
            if (cVar1 < '\x02') {
              if ('\0' < cVar1) {
                uVar2 = (uint)DAT_803ddb84;
                DAT_803ddb84 = DAT_803ddb84 + 1;
                (**(code **)(*DAT_803dca8c + 0x14))
                          (param_1,param_2,(int)*(short *)(&DAT_80325af4 + uVar2 * 2));
                goto LAB_801ba1b0;
              }
            }
            else if (cVar1 < '\x04') {
              uVar2 = (uint)DAT_803ddb84;
              DAT_803ddb84 = DAT_803ddb84 + 1;
              (**(code **)(*DAT_803dca8c + 0x14))
                        (param_1,param_2,(int)*(short *)(&DAT_80325ad4 + uVar2 * 2));
              goto LAB_801ba1b0;
            }
            (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,3);
          }
        }
      }
      else {
        iVar3 = FUN_800221a0(0,5);
        (**(code **)(*DAT_803dca8c + 0x14))
                  (param_1,param_2,(int)*(short *)(&DAT_80325ac8 + iVar3 * 2));
      }
    }
    else {
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,2);
    }
  }
LAB_801ba1b0:
  if ((*(short *)(param_2 + 0x274) == 3) || (*(short *)(param_2 + 0x274) == 7)) {
    DAT_803acfed = DAT_803acfed | 1;
  }
  else {
    DAT_803acfed = DAT_803acfed & 0xfe;
  }
  FUN_801bc2d8(param_1,param_2);
  return 0;
}

