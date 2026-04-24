// Function: FUN_801cf4f0
// Entry: 801cf4f0
// Size: 668 bytes

void FUN_801cf4f0(undefined2 *param_1,int param_2,int param_3)

{
  char cVar2;
  undefined uVar3;
  int iVar1;
  int iVar4;
  undefined4 local_18;
  undefined4 local_14 [3];
  
  iVar4 = *(int *)(param_1 + 0x5c);
  local_14[0] = DAT_803e5208;
  *param_1 = (short)((int)*(char *)(param_2 + 0x1c) << 8);
  *(code **)(param_1 + 0x5e) = FUN_801cde7c;
  if (param_3 != 0) {
    return;
  }
  *(float *)(iVar4 + 0x4c) = FLOAT_803e5258;
  cVar2 = *(char *)(param_2 + 0x1d);
  if (cVar2 == '\x02') {
    *(byte *)(iVar4 + 0x43c) = *(byte *)(iVar4 + 0x43c) | 1;
    iVar1 = FUN_8001ffb4(0x19f);
    if (iVar1 == 0) {
      iVar1 = FUN_8001ffb4(0x19d);
      if (iVar1 == 0) {
        *(undefined *)(iVar4 + 0x408) = 4;
      }
      else {
        *(undefined *)(iVar4 + 0x408) = 5;
      }
    }
    else {
      *(undefined *)(iVar4 + 0x408) = 6;
    }
    goto LAB_801cf6e4;
  }
  if (cVar2 < '\x02') {
    if (cVar2 == '\0') {
      *(byte *)(iVar4 + 0x43c) = *(byte *)(iVar4 + 0x43c) | 1;
      goto LAB_801cf6e4;
    }
    if (cVar2 < '\0') goto LAB_801cf6e4;
  }
  else {
    if (cVar2 == '\x04') {
      uVar3 = FUN_8001ffb4(0x48b);
      *(undefined *)(iVar4 + 0x43f) = uVar3;
      iVar1 = FUN_8001ffb4(0x102);
      if (iVar1 == 0) {
        iVar1 = FUN_8001ffb4(0xce1);
        if (iVar1 == 0) {
          *(undefined *)(iVar4 + 0x408) = 9;
        }
        else {
          *(undefined *)(iVar4 + 0x408) = 0xc;
          if ('\x02' < *(char *)(iVar4 + 0x43f)) {
            (**(code **)(*DAT_803dca68 + 0x58))(200,0x5d0);
            *(byte *)(iVar4 + 0x43c) = *(byte *)(iVar4 + 0x43c) | 0x40;
            *(undefined *)(iVar4 + 0x408) = 0x11;
          }
        }
      }
      else {
        *(undefined *)(iVar4 + 0x408) = 0x10;
      }
      goto LAB_801cf6e4;
    }
    if ('\x03' < cVar2) goto LAB_801cf6e4;
  }
  local_18 = 0x19;
  *(byte *)(iVar4 + 0x43c) = *(byte *)(iVar4 + 0x43c) | 1;
  cVar2 = (**(code **)(*DAT_803dca9c + 0x8c))
                    ((double)FLOAT_803e5254,iVar4 + 0x5c,param_1,&local_18,0xffffffff);
  if (cVar2 == '\0') {
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar4 + 0xc4);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar4 + 0xcc);
    *(undefined *)(iVar4 + 0x408) = 8;
    *(float *)(iVar4 + 0x54) = FLOAT_803e524c;
  }
LAB_801cf6e4:
  if ((*(byte *)(iVar4 + 0x43c) & 1) != 0) {
    iVar4 = iVar4 + 0x16c;
    (**(code **)(*DAT_803dcaa8 + 4))(iVar4,3,2,1);
    (**(code **)(*DAT_803dcaa8 + 0xc))(iVar4,4,&DAT_803267e8,&DAT_80326818,local_14);
    (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar4);
  }
  FUN_80037200(param_1,0x4d);
  return;
}

