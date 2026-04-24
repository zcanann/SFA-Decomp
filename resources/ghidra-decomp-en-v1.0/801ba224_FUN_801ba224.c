// Function: FUN_801ba224
// Entry: 801ba224
// Size: 660 bytes

undefined4 FUN_801ba224(int param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  ushort local_18;
  undefined auStack22 [2];
  short local_14 [4];
  
  iVar3 = *(int *)(param_1 + 0xb8);
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
      if ((local_18 < 0xf1) ||
         (uVar2 = (**(code **)(*DAT_803dcab8 + 0x18))((double)FLOAT_803e4bbc,param_1,param_2),
         (uVar2 & 1) == 0)) {
        if ((*(ushort *)(iVar3 + 0x400) & 4) == 0) {
          (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,3);
        }
        else {
          iVar3 = FUN_800221a0(0,1);
          (**(code **)(*DAT_803dca8c + 0x14))
                    (param_1,param_2,(int)*(short *)(&DAT_803dbf38 + iVar3 * 2));
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
  sVar1 = *(short *)(param_2 + 0x274);
  if (((sVar1 == 1) || (sVar1 == 4)) || (sVar1 == 5)) {
    DAT_803acfed = DAT_803acfed & 0xfe;
  }
  else {
    DAT_803acfed = DAT_803acfed | 1;
  }
  FUN_801bc2d8(param_1,param_2);
  return 0;
}

