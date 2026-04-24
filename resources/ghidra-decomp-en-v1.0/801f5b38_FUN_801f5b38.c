// Function: FUN_801f5b38
// Entry: 801f5b38
// Size: 2196 bytes

void FUN_801f5b38(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar2 + 0x14) == '\0') {
    *(byte *)(iVar2 + 0x12) = *(byte *)(iVar2 + 0x12) & 0xfe;
    iVar1 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
    if (iVar1 == 0x47295) {
      if (*(char *)(iVar2 + 0x13) == '\x02') {
        iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xc));
        if (iVar1 == 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
        }
        iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xc));
        if (iVar1 == 0) {
          iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xe));
          if ((iVar1 == 0) || (iVar1 = FUN_8001ffb4(0x29b), iVar1 == 0)) {
            *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          }
          else {
            (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
            FUN_800200e8((int)*(short *)(iVar2 + 0xc),0);
            FUN_800200e8((int)*(short *)(iVar2 + 0xe),0);
            FUN_800200e8(0xbfd,0);
          }
        }
        else {
          if ((*(byte *)(param_1 + 0xaf) & 0x10) != 0) {
            *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
          }
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            FUN_8011f3ec(0x18);
          }
          if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
            (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
            FUN_800200e8((int)*(short *)(iVar2 + 0xc),0);
            *(byte *)(iVar2 + 0x15) = *(byte *)(iVar2 + 0x15) & 0x7f | 0x80;
          }
        }
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
    else if (iVar1 == 0x2183) {
      if (*(char *)(iVar2 + 0x13) == '\x01') {
        iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xc));
        if (iVar1 == 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
        }
        iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xc));
        if (iVar1 == 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        }
        else {
          if ((*(byte *)(param_1 + 0xaf) & 0x10) != 0) {
            *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
          }
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            FUN_8011f3ec(0x18);
          }
          if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
            FUN_800200e8((int)*(short *)(iVar2 + 0xe),1);
            FUN_800200e8((int)*(short *)(iVar2 + 0xc),0);
          }
        }
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
    else if (iVar1 == 0x49781) {
      if (*(char *)(iVar2 + 0x13) == '\x03') {
        iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xc));
        if (iVar1 == 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
        }
        iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xc));
        if (iVar1 == 0) {
          iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xe));
          if ((iVar1 == 0) || (iVar1 = FUN_8001ffb4(0x8a2), iVar1 == 0)) {
            *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          }
          else {
            (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
            FUN_800200e8((int)*(short *)(iVar2 + 0xc),0);
            FUN_800200e8((int)*(short *)(iVar2 + 0xe),0);
          }
        }
        else {
          if ((*(byte *)(param_1 + 0xaf) & 0x10) != 0) {
            *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
          }
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            FUN_8011f3ec(0x18);
          }
          if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
            (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
            FUN_800200e8((int)*(short *)(iVar2 + 0xc),0);
            *(byte *)(iVar2 + 0x15) = *(byte *)(iVar2 + 0x15) & 0x7f | 0x80;
          }
        }
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
    else if (iVar1 == 0x4a1c0) {
      if (*(char *)(iVar2 + 0x13) == '\x04') {
        iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xc));
        if (iVar1 == 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
        }
        iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xc));
        if (iVar1 == 0) {
          iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xe));
          if ((iVar1 == 0) || (iVar1 = FUN_8001ffb4(0xc71), iVar1 == 0)) {
            *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          }
          else {
            (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
            FUN_800200e8((int)*(short *)(iVar2 + 0xc),0);
            FUN_800200e8((int)*(short *)(iVar2 + 0xe),0);
          }
        }
        else {
          if ((*(byte *)(param_1 + 0xaf) & 0x10) != 0) {
            *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
          }
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            FUN_8011f3ec(0x18);
          }
          if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
            (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
            FUN_800200e8((int)*(short *)(iVar2 + 0xc),0);
            *(byte *)(iVar2 + 0x15) = *(byte *)(iVar2 + 0x15) & 0x7f | 0x80;
          }
        }
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
    else if (iVar1 == 0x4a250) {
      if (*(char *)(iVar2 + 0x13) == '\x05') {
        iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xc));
        if (iVar1 == 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
        }
        iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xc));
        if (iVar1 == 0) {
          iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xe));
          if ((iVar1 == 0) || (iVar1 = FUN_8001ffb4(0xcb6), iVar1 == 0)) {
            *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          }
          else if ((*(byte *)(iVar2 + 0x15) >> 6 & 1) != 0) {
            *(byte *)(iVar2 + 0x15) = *(byte *)(iVar2 + 0x15) & 0xbf;
            FUN_800200e8((int)*(short *)(iVar2 + 0xc),0);
            FUN_800200e8(0xd1f,1);
            FUN_80008b74(0,0,0x217,0);
            FUN_80008b74(param_1,param_1,0x216,0);
            FUN_80008b74(param_1,param_1,0x229,0);
            FUN_80008b74(param_1,param_1,0x22a,0);
            (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),4,1);
            (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),10,0);
            (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0xac),0xb,1);
          }
        }
        else {
          if ((*(byte *)(param_1 + 0xaf) & 0x10) != 0) {
            *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
          }
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            FUN_8011f3ec(0x18);
          }
          if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
            (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
            FUN_800200e8((int)*(short *)(iVar2 + 0xc),0);
            *(byte *)(iVar2 + 0x15) = *(byte *)(iVar2 + 0x15) & 0x7f | 0x80;
            *(byte *)(iVar2 + 0x15) = *(byte *)(iVar2 + 0x15) & 0xbf | 0x40;
          }
        }
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
    else if (iVar1 == 0x4a5e6) {
      if (*(char *)(iVar2 + 0x13) == '\x06') {
        iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xc));
        if (iVar1 == 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
        }
        iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xc));
        if (iVar1 == 0) {
          iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0xe));
          if ((iVar1 == 0) || (iVar1 = FUN_8001ffb4(0xcb8), iVar1 == 0)) {
            *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          }
          else {
            FUN_800200e8((int)*(short *)(iVar2 + 0xc),0);
            FUN_800200e8((int)*(short *)(iVar2 + 0xe),1);
          }
        }
        else {
          if ((*(byte *)(param_1 + 0xaf) & 0x10) != 0) {
            *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
          }
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            FUN_8011f3ec(0x18);
          }
          if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
            *(byte *)(iVar2 + 0x15) = *(byte *)(iVar2 + 0x15) & 0x7f | 0x80;
            (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
            FUN_800200e8((int)*(short *)(iVar2 + 0xc),0);
          }
        }
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
    if (*(char *)(iVar2 + 0x15) < '\0') {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
  }
  else {
    *(char *)(iVar2 + 0x14) = *(char *)(iVar2 + 0x14) + -1;
    if (*(char *)(iVar2 + 0x14) == '\0') {
      FUN_800200e8((int)*(short *)(iVar2 + 0xe),1);
    }
  }
  return;
}

