// Function: FUN_801f6170
// Entry: 801f6170
// Size: 2196 bytes

void FUN_801f6170(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  uint uVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  undefined8 uVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  if (*(char *)(iVar3 + 0x14) == '\0') {
    *(byte *)(iVar3 + 0x12) = *(byte *)(iVar3 + 0x12) & 0xfe;
    iVar1 = *(int *)(*(int *)(param_9 + 0x4c) + 0x14);
    if (iVar1 == 0x47295) {
      if (*(char *)(iVar3 + 0x13) == '\x02') {
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xc));
        if (uVar2 == 0) {
          *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
        }
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xc));
        if (uVar2 == 0) {
          uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xe));
          if ((uVar2 == 0) || (uVar2 = FUN_80020078(0x29b), uVar2 == 0)) {
            *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
          }
          else {
            (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
            FUN_800201ac((int)*(short *)(iVar3 + 0xc),0);
            FUN_800201ac((int)*(short *)(iVar3 + 0xe),0);
            FUN_800201ac(0xbfd,0);
          }
        }
        else {
          if ((*(byte *)(param_9 + 0xaf) & 0x10) != 0) {
            *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
          }
          if ((*(byte *)(param_9 + 0xaf) & 4) != 0) {
            FUN_8011f6d0(0x18);
          }
          if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
            FUN_800201ac((int)*(short *)(iVar3 + 0xc),0);
            *(byte *)(iVar3 + 0x15) = *(byte *)(iVar3 + 0x15) & 0x7f | 0x80;
          }
        }
      }
      else {
        *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      }
    }
    else if (iVar1 == 0x2183) {
      if (*(char *)(iVar3 + 0x13) == '\x01') {
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xc));
        if (uVar2 == 0) {
          *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
        }
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xc));
        if (uVar2 == 0) {
          *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
        }
        else {
          if ((*(byte *)(param_9 + 0xaf) & 0x10) != 0) {
            *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
          }
          if ((*(byte *)(param_9 + 0xaf) & 4) != 0) {
            FUN_8011f6d0(0x18);
          }
          if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
            FUN_800201ac((int)*(short *)(iVar3 + 0xe),1);
            FUN_800201ac((int)*(short *)(iVar3 + 0xc),0);
          }
        }
      }
      else {
        *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      }
    }
    else if (iVar1 == 0x49781) {
      if (*(char *)(iVar3 + 0x13) == '\x03') {
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xc));
        if (uVar2 == 0) {
          *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
        }
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xc));
        if (uVar2 == 0) {
          uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xe));
          if ((uVar2 == 0) || (uVar2 = FUN_80020078(0x8a2), uVar2 == 0)) {
            *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
          }
          else {
            (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
            FUN_800201ac((int)*(short *)(iVar3 + 0xc),0);
            FUN_800201ac((int)*(short *)(iVar3 + 0xe),0);
          }
        }
        else {
          if ((*(byte *)(param_9 + 0xaf) & 0x10) != 0) {
            *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
          }
          if ((*(byte *)(param_9 + 0xaf) & 4) != 0) {
            FUN_8011f6d0(0x18);
          }
          if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
            FUN_800201ac((int)*(short *)(iVar3 + 0xc),0);
            *(byte *)(iVar3 + 0x15) = *(byte *)(iVar3 + 0x15) & 0x7f | 0x80;
          }
        }
      }
      else {
        *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      }
    }
    else if (iVar1 == 0x4a1c0) {
      if (*(char *)(iVar3 + 0x13) == '\x04') {
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xc));
        if (uVar2 == 0) {
          *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
        }
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xc));
        if (uVar2 == 0) {
          uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xe));
          if ((uVar2 == 0) || (uVar2 = FUN_80020078(0xc71), uVar2 == 0)) {
            *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
          }
          else {
            (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
            FUN_800201ac((int)*(short *)(iVar3 + 0xc),0);
            FUN_800201ac((int)*(short *)(iVar3 + 0xe),0);
          }
        }
        else {
          if ((*(byte *)(param_9 + 0xaf) & 0x10) != 0) {
            *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
          }
          if ((*(byte *)(param_9 + 0xaf) & 4) != 0) {
            FUN_8011f6d0(0x18);
          }
          if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
            FUN_800201ac((int)*(short *)(iVar3 + 0xc),0);
            *(byte *)(iVar3 + 0x15) = *(byte *)(iVar3 + 0x15) & 0x7f | 0x80;
          }
        }
      }
      else {
        *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      }
    }
    else if (iVar1 == 0x4a250) {
      if (*(char *)(iVar3 + 0x13) == '\x05') {
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xc));
        if (uVar2 == 0) {
          *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
        }
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xc));
        if (uVar2 == 0) {
          uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xe));
          if ((uVar2 == 0) || (uVar2 = FUN_80020078(0xcb6), uVar2 == 0)) {
            *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
          }
          else if ((*(byte *)(iVar3 + 0x15) >> 6 & 1) != 0) {
            *(byte *)(iVar3 + 0x15) = *(byte *)(iVar3 + 0x15) & 0xbf;
            FUN_800201ac((int)*(short *)(iVar3 + 0xc),0);
            uVar4 = FUN_800201ac(0xd1f,1);
            uVar4 = FUN_80008b74(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                                 0x217,0,in_r7,in_r8,in_r9,in_r10);
            uVar4 = FUN_80008b74(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,param_9,0x216,0,in_r7,in_r8,in_r9,in_r10);
            uVar4 = FUN_80008b74(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,param_9,0x229,0,in_r7,in_r8,in_r9,in_r10);
            FUN_80008b74(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_9,0x22a,0,in_r7,in_r8,in_r9,in_r10);
            (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),4,1);
            (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),10,0);
            (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0xb,1);
          }
        }
        else {
          if ((*(byte *)(param_9 + 0xaf) & 0x10) != 0) {
            *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
          }
          if ((*(byte *)(param_9 + 0xaf) & 4) != 0) {
            FUN_8011f6d0(0x18);
          }
          if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
            FUN_800201ac((int)*(short *)(iVar3 + 0xc),0);
            *(byte *)(iVar3 + 0x15) = *(byte *)(iVar3 + 0x15) & 0x7f | 0x80;
            *(byte *)(iVar3 + 0x15) = *(byte *)(iVar3 + 0x15) & 0xbf | 0x40;
          }
        }
      }
      else {
        *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      }
    }
    else if (iVar1 == 0x4a5e6) {
      if (*(char *)(iVar3 + 0x13) == '\x06') {
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xc));
        if (uVar2 == 0) {
          *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
        }
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xc));
        if (uVar2 == 0) {
          uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0xe));
          if ((uVar2 == 0) || (uVar2 = FUN_80020078(0xcb8), uVar2 == 0)) {
            *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
          }
          else {
            FUN_800201ac((int)*(short *)(iVar3 + 0xc),0);
            FUN_800201ac((int)*(short *)(iVar3 + 0xe),1);
          }
        }
        else {
          if ((*(byte *)(param_9 + 0xaf) & 0x10) != 0) {
            *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
          }
          if ((*(byte *)(param_9 + 0xaf) & 4) != 0) {
            FUN_8011f6d0(0x18);
          }
          if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
            *(byte *)(iVar3 + 0x15) = *(byte *)(iVar3 + 0x15) & 0x7f | 0x80;
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
            FUN_800201ac((int)*(short *)(iVar3 + 0xc),0);
          }
        }
      }
      else {
        *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      }
    }
    if (*(char *)(iVar3 + 0x15) < '\0') {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    }
  }
  else {
    *(char *)(iVar3 + 0x14) = *(char *)(iVar3 + 0x14) + -1;
    if (*(char *)(iVar3 + 0x14) == '\0') {
      FUN_800201ac((int)*(short *)(iVar3 + 0xe),1);
    }
  }
  return;
}

