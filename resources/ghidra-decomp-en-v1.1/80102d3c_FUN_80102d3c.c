// Function: FUN_80102d3c
// Entry: 80102d3c
// Size: 1012 bytes

void FUN_80102d3c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10,char param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  char *pcVar5;
  undefined8 uVar6;
  uint local_28;
  undefined local_24;
  uint local_20;
  byte local_1c;
  
  if (param_9 == 2) {
    local_28 = param_10 & 0x7f;
    local_24 = (undefined)(param_10 & 0x80);
    if ((param_10 & 0x80) == 0) {
      uVar4 = 0x78;
    }
    else {
      uVar4 = 0;
    }
    FUN_80103224(0x47,1,0,8,(uint)&local_28,uVar4,0xff);
    return;
  }
  if (param_9 < 2) {
    if ((param_9 != 0) && (-1 < param_9)) {
      local_20 = param_10 & 0x7f;
      local_1c = (byte)param_10 & 0x80;
      *(undefined *)(DAT_803de19c + 0x139) = 1;
      if ((param_10 & 0x80) == 0) {
        uVar4 = 0x78;
      }
      else {
        uVar4 = 0;
      }
      FUN_80103224(0x48,1,0,8,(uint)&local_20,uVar4,0xff);
      return;
    }
  }
  else {
    if (param_9 == 4) {
      FUN_80103224(param_10 + 0x42,1,0,0,0,0x78,0xff);
      return;
    }
    if (param_9 < 4) {
      FUN_80103224(0x42,0,1,0,0,0x78,0xff);
      return;
    }
  }
  if (param_10 == 0) {
    uVar6 = FUN_8007d858();
    pcVar5 = (char *)FUN_80023d8c(0x10,0xf);
    if (pcVar5 != (char *)0x0) {
      FUN_8001f7e0(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,pcVar5,0xb,0,0x10,
                   param_13,param_14,param_15,param_16);
      pcVar5[0xd] = param_11;
      FUN_800e875c(1);
      if ((((DAT_803de190 == 0x42) || (DAT_803de190 == 0x4b)) || (DAT_803de190 == 0x48)) ||
         (DAT_803de190 == 0x47)) {
        if (*pcVar5 == '\x01') {
          FUN_80103224(0x4b,1,2,0x10,(uint)pcVar5,0,0xff);
        }
        else {
          FUN_80103224(0x42,0,2,0x10,(uint)pcVar5,0,0xff);
        }
      }
      else {
        iVar2 = 0;
        puVar3 = &DAT_803a4e88;
        for (uVar1 = (uint)DAT_803de198; uVar1 != 0; uVar1 = uVar1 - 1) {
          if (*(short *)*puVar3 == 0x42) {
            iVar2 = (&DAT_803a4e88)[iVar2];
            goto LAB_80103090;
          }
          puVar3 = puVar3 + 1;
          iVar2 = iVar2 + 1;
        }
        iVar2 = 0;
LAB_80103090:
        (**(code **)(**(int **)(iVar2 + 4) + 0x10))(pcVar5,0x10);
      }
      FUN_800238c4((uint)pcVar5);
    }
  }
  else {
    if (param_10 == 0) {
      pcVar5 = (char *)0x0;
    }
    else {
      pcVar5 = (char *)FUN_80023d8c(0x10,0xf);
      if (pcVar5 != (char *)0x0) {
        FUN_8001f7e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,pcVar5,0xb,
                     (param_10 - 1) * 0x10,0x10,param_13,param_14,param_15,param_16);
      }
    }
    if (pcVar5 != (char *)0x0) {
      pcVar5[0xd] = param_11;
      FUN_800e875c((short)param_10);
      if (((DAT_803de190 == 0x42) || (DAT_803de190 == 0x4b)) ||
         ((DAT_803de190 == 0x48 || (DAT_803de190 == 0x47)))) {
        if (*pcVar5 == '\x01') {
          FUN_80103224(0x4b,1,2,0x10,(uint)pcVar5,0,0xff);
        }
        else {
          FUN_80103224(0x42,0,2,0x10,(uint)pcVar5,0,0xff);
        }
      }
      else {
        iVar2 = 0;
        puVar3 = &DAT_803a4e88;
        for (uVar1 = (uint)DAT_803de198; uVar1 != 0; uVar1 = uVar1 - 1) {
          if (*(short *)*puVar3 == 0x42) {
            iVar2 = (&DAT_803a4e88)[iVar2];
            goto LAB_80102f3c;
          }
          puVar3 = puVar3 + 1;
          iVar2 = iVar2 + 1;
        }
        iVar2 = 0;
LAB_80102f3c:
        (**(code **)(**(int **)(iVar2 + 4) + 0x10))(pcVar5,0x10);
      }
      FUN_800238c4((uint)pcVar5);
    }
  }
  return;
}

