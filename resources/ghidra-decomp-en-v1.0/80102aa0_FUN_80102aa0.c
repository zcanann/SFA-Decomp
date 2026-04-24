// Function: FUN_80102aa0
// Entry: 80102aa0
// Size: 1012 bytes

void FUN_80102aa0(int param_1,uint param_2,char param_3)

{
  uint uVar1;
  int iVar2;
  short **ppsVar3;
  undefined4 uVar4;
  char *pcVar5;
  uint local_28;
  undefined local_24;
  uint local_20;
  byte local_1c;
  
  if (param_1 == 2) {
    local_28 = param_2 & 0x7f;
    local_24 = (undefined)(param_2 & 0x80);
    if ((param_2 & 0x80) == 0) {
      uVar4 = 0x78;
    }
    else {
      uVar4 = 0;
    }
    FUN_80102f88(0x47,1,0,8,&local_28,uVar4,0xff);
    return;
  }
  if (param_1 < 2) {
    if ((param_1 != 0) && (-1 < param_1)) {
      local_20 = param_2 & 0x7f;
      local_1c = (byte)param_2 & 0x80;
      *(undefined *)(DAT_803dd524 + 0x139) = 1;
      if ((param_2 & 0x80) == 0) {
        uVar4 = 0x78;
      }
      else {
        uVar4 = 0;
      }
      FUN_80102f88(0x48,1,0,8,&local_20,uVar4,0xff);
      return;
    }
  }
  else {
    if (param_1 == 4) {
      FUN_80102f88(param_2 + 0x42,1,0,0,0,0x78,0xff);
      return;
    }
    if (param_1 < 4) {
      FUN_80102f88(0x42,0,1,0,0,0x78,0xff);
      return;
    }
  }
  if (param_2 == 0) {
    FUN_8007d6dc(s__camcontrol_c__failed_to_load_tr_80319b14,0);
    pcVar5 = (char *)FUN_80023cc8(0x10,0xf,0);
    if (pcVar5 != (char *)0x0) {
      FUN_8001f71c(pcVar5,0xb,0,0x10);
      pcVar5[0xd] = param_3;
      FUN_800e84d8(1);
      if ((((DAT_803dd518 == 0x42) || (DAT_803dd518 == 0x4b)) || (DAT_803dd518 == 0x48)) ||
         (DAT_803dd518 == 0x47)) {
        if (*pcVar5 == '\x01') {
          FUN_80102f88(0x4b,1,2,0x10,pcVar5,0,0xff);
        }
        else {
          FUN_80102f88(0x42,0,2,0x10,pcVar5,0,0xff);
        }
      }
      else {
        iVar2 = 0;
        ppsVar3 = (short **)&DAT_803a4228;
        for (uVar1 = (uint)DAT_803dd520; uVar1 != 0; uVar1 = uVar1 - 1) {
          if (**ppsVar3 == 0x42) {
            iVar2 = (&DAT_803a4228)[iVar2];
            goto LAB_80102df4;
          }
          ppsVar3 = ppsVar3 + 1;
          iVar2 = iVar2 + 1;
        }
        iVar2 = 0;
LAB_80102df4:
        (**(code **)(**(int **)(iVar2 + 4) + 0x10))(pcVar5,0x10);
      }
      FUN_80023800(pcVar5);
    }
  }
  else {
    if (param_2 == 0) {
      pcVar5 = (char *)0x0;
    }
    else {
      pcVar5 = (char *)FUN_80023cc8(0x10,0xf,0);
      if (pcVar5 != (char *)0x0) {
        FUN_8001f71c(pcVar5,0xb,(param_2 - 1) * 0x10,0x10);
      }
    }
    if (pcVar5 != (char *)0x0) {
      pcVar5[0xd] = param_3;
      FUN_800e84d8((int)(short)param_2);
      if (((DAT_803dd518 == 0x42) || (DAT_803dd518 == 0x4b)) ||
         ((DAT_803dd518 == 0x48 || (DAT_803dd518 == 0x47)))) {
        if (*pcVar5 == '\x01') {
          FUN_80102f88(0x4b,1,2,0x10,pcVar5,0,0xff);
        }
        else {
          FUN_80102f88(0x42,0,2,0x10,pcVar5,0,0xff);
        }
      }
      else {
        iVar2 = 0;
        ppsVar3 = (short **)&DAT_803a4228;
        for (uVar1 = (uint)DAT_803dd520; uVar1 != 0; uVar1 = uVar1 - 1) {
          if (**ppsVar3 == 0x42) {
            iVar2 = (&DAT_803a4228)[iVar2];
            goto LAB_80102ca0;
          }
          ppsVar3 = ppsVar3 + 1;
          iVar2 = iVar2 + 1;
        }
        iVar2 = 0;
LAB_80102ca0:
        (**(code **)(**(int **)(iVar2 + 4) + 0x10))(pcVar5,0x10);
      }
      FUN_80023800(pcVar5);
    }
  }
  return;
}

