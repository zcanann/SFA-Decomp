// Function: FUN_801cfac0
// Entry: 801cfac0
// Size: 668 bytes

void FUN_801cfac0(undefined2 *param_1,int param_2,int param_3)

{
  char cVar2;
  uint uVar1;
  int iVar3;
  undefined4 local_18;
  undefined4 local_14 [3];
  
  iVar3 = *(int *)(param_1 + 0x5c);
  local_14[0] = DAT_803e5ea0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x1c) << 8);
  *(code **)(param_1 + 0x5e) = FUN_801ce430;
  if (param_3 != 0) {
    return;
  }
  *(float *)(iVar3 + 0x4c) = FLOAT_803e5ef0;
  cVar2 = *(char *)(param_2 + 0x1d);
  if (cVar2 == '\x02') {
    *(byte *)(iVar3 + 0x43c) = *(byte *)(iVar3 + 0x43c) | 1;
    uVar1 = FUN_80020078(0x19f);
    if (uVar1 == 0) {
      uVar1 = FUN_80020078(0x19d);
      if (uVar1 == 0) {
        *(undefined *)(iVar3 + 0x408) = 4;
      }
      else {
        *(undefined *)(iVar3 + 0x408) = 5;
      }
    }
    else {
      *(undefined *)(iVar3 + 0x408) = 6;
    }
    goto LAB_801cfcb4;
  }
  if (cVar2 < '\x02') {
    if (cVar2 == '\0') {
      *(byte *)(iVar3 + 0x43c) = *(byte *)(iVar3 + 0x43c) | 1;
      goto LAB_801cfcb4;
    }
    if (cVar2 < '\0') goto LAB_801cfcb4;
  }
  else {
    if (cVar2 == '\x04') {
      uVar1 = FUN_80020078(0x48b);
      *(char *)(iVar3 + 0x43f) = (char)uVar1;
      uVar1 = FUN_80020078(0x102);
      if (uVar1 == 0) {
        uVar1 = FUN_80020078(0xce1);
        if (uVar1 == 0) {
          *(undefined *)(iVar3 + 0x408) = 9;
        }
        else {
          *(undefined *)(iVar3 + 0x408) = 0xc;
          if ('\x02' < *(char *)(iVar3 + 0x43f)) {
            (**(code **)(*DAT_803dd6e8 + 0x58))(200,0x5d0);
            *(byte *)(iVar3 + 0x43c) = *(byte *)(iVar3 + 0x43c) | 0x40;
            *(undefined *)(iVar3 + 0x408) = 0x11;
          }
        }
      }
      else {
        *(undefined *)(iVar3 + 0x408) = 0x10;
      }
      goto LAB_801cfcb4;
    }
    if ('\x03' < cVar2) goto LAB_801cfcb4;
  }
  local_18 = 0x19;
  *(byte *)(iVar3 + 0x43c) = *(byte *)(iVar3 + 0x43c) | 1;
  cVar2 = (**(code **)(*DAT_803dd71c + 0x8c))
                    ((double)FLOAT_803e5eec,iVar3 + 0x5c,param_1,&local_18,0xffffffff);
  if (cVar2 == '\0') {
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar3 + 0xc4);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar3 + 0xcc);
    *(undefined *)(iVar3 + 0x408) = 8;
    *(float *)(iVar3 + 0x54) = FLOAT_803e5ee4;
  }
LAB_801cfcb4:
  if ((*(byte *)(iVar3 + 0x43c) & 1) != 0) {
    iVar3 = iVar3 + 0x16c;
    (**(code **)(*DAT_803dd728 + 4))(iVar3,3,2,1);
    (**(code **)(*DAT_803dd728 + 0xc))(iVar3,4,&DAT_80327428,&DAT_80327458,local_14);
    (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar3);
  }
  FUN_800372f8((int)param_1,0x4d);
  return;
}

