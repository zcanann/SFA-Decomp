// Function: FUN_8021349c
// Entry: 8021349c
// Size: 932 bytes

undefined4 FUN_8021349c(int param_1,int param_2)

{
  char cVar1;
  ushort uVar2;
  bool bVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
    *(undefined *)(DAT_803de9d4 + 0x3f) = 0;
    *(ushort *)((int)DAT_803de9d4 + 0xfa) = *(ushort *)((int)DAT_803de9d4 + 0xfa) & 0xffdf;
    *(float *)(param_2 + 0x294) =
         *(float *)(iVar6 + (uint)*(byte *)(DAT_803de9d4 + 0x3f) * 4 + 0x38) / FLOAT_803e745c;
  }
  iVar4 = FUN_80215214(param_2);
  if (iVar4 != 0) {
    local_c = 2;
    uVar5 = FUN_800138e4((short *)*DAT_803de9d4);
    if (uVar5 == 0) {
      FUN_80013978((short *)*DAT_803de9d4,(uint)&local_c);
    }
    return 4;
  }
  uVar2 = *(ushort *)((int)DAT_803de9d4 + 0xfa);
  if ((((*(char *)(DAT_803de9d4 + 0x3f) == '\0') && (1 < *(byte *)((int)DAT_803de9d4 + 0x101))) &&
      ((uVar2 & 0x20) == 0)) &&
     ((((uVar2 & 1) == 0 && (FLOAT_803e7480 <= (float)DAT_803de9d4[2])) ||
      (((uVar2 & 1) != 0 && ((float)DAT_803de9d4[2] <= FLOAT_803e7458)))))) {
    iVar4 = (int)(uint)*(byte *)((int)DAT_803de9d4 + 0x101) >> 1;
    uVar5 = FUN_80022264(0,100);
    if ((int)uVar5 <= (int)(uint)*(byte *)(iVar6 + iVar4 + 0x56)) {
      *(undefined *)((int)DAT_803de9d4 + 0x103) = 2;
      local_10 = 5;
      uVar5 = FUN_800138e4((short *)*DAT_803de9d4);
      if (uVar5 == 0) {
        FUN_80013978((short *)*DAT_803de9d4,(uint)&local_10);
      }
      *(undefined *)((int)DAT_803de9d4 + 0xfd) = 1;
      return 5;
    }
    uVar5 = FUN_80022264(0,100);
    if ((int)uVar5 <= (int)(uint)*(byte *)(iVar6 + iVar4 + 0x52)) {
      cVar1 = *(char *)((int)DAT_803de9d4 + 0xfe);
      if (cVar1 == '\x01') {
        uVar5 = countLeadingZeros(2 - (uint)*(byte *)((int)DAT_803de9d4 + 0xff));
        uVar5 = uVar5 >> 5 & 0xff;
      }
      else if (cVar1 == '\x02') {
        uVar5 = countLeadingZeros(1 - (uint)*(byte *)((int)DAT_803de9d4 + 0xff));
        uVar5 = uVar5 >> 5 & 0xff;
      }
      else if (cVar1 == '\x04') {
        uVar5 = countLeadingZeros(8 - (uint)*(byte *)((int)DAT_803de9d4 + 0xff));
        uVar5 = uVar5 >> 5 & 0xff;
      }
      else {
        uVar5 = countLeadingZeros(4 - (uint)*(byte *)((int)DAT_803de9d4 + 0xff));
        uVar5 = uVar5 >> 5 & 0xff;
      }
      if ((uVar5 != 0) && ((*(ushort *)((int)DAT_803de9d4 + 0xfa) & 0x40) == 0)) {
        *(undefined *)((int)DAT_803de9d4 + 0xfd) = 0;
        local_14 = 0xb;
        uVar5 = FUN_800138e4((short *)*DAT_803de9d4);
        if (uVar5 == 0) {
          FUN_80013978((short *)*DAT_803de9d4,(uint)&local_14);
        }
        return 5;
      }
    }
    *(ushort *)((int)DAT_803de9d4 + 0xfa) = *(ushort *)((int)DAT_803de9d4 + 0xfa) | 0x20;
  }
  if ((*(byte *)((int)DAT_803de9d4 + 0xfe) & *(byte *)((int)DAT_803de9d4 + 0xff)) == 0) {
    return 0;
  }
  *(ushort *)((int)DAT_803de9d4 + 0xfa) = *(ushort *)((int)DAT_803de9d4 + 0xfa) & 0xffbf;
  if ((*(byte *)((int)DAT_803de9d4 + 0xfe) & *(byte *)((int)DAT_803de9d4 + 0xff)) != 0) {
    if ((*(ushort *)((int)DAT_803de9d4 + 0xfa) & 1) == 0) {
      if (FLOAT_803e744c < (float)DAT_803de9d4[0x3d] - (float)DAT_803de9d4[2]) {
        bVar3 = true;
        goto LAB_802137d0;
      }
    }
    else if (FLOAT_803e744c < (float)DAT_803de9d4[2] - (float)DAT_803de9d4[0x3d]) {
      bVar3 = true;
      goto LAB_802137d0;
    }
  }
  bVar3 = false;
LAB_802137d0:
  if (!bVar3) {
    return 0;
  }
  *(undefined *)((int)DAT_803de9d4 + 0x103) = 1;
  local_18 = 5;
  uVar5 = FUN_800138e4((short *)*DAT_803de9d4);
  if (uVar5 == 0) {
    FUN_80013978((short *)*DAT_803de9d4,(uint)&local_18);
  }
  *(undefined *)((int)DAT_803de9d4 + 0xfd) = 1;
  return 5;
}

