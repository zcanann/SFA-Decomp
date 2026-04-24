// Function: FUN_80212e24
// Entry: 80212e24
// Size: 932 bytes

undefined4 FUN_80212e24(int param_1,int param_2)

{
  char cVar1;
  ushort uVar2;
  bool bVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  iVar7 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,1);
    *(undefined *)(DAT_803ddd54 + 0x3f) = 0;
    *(ushort *)((int)DAT_803ddd54 + 0xfa) = *(ushort *)((int)DAT_803ddd54 + 0xfa) & 0xffdf;
    *(float *)(param_2 + 0x294) =
         *(float *)(iVar7 + (uint)*(byte *)(DAT_803ddd54 + 0x3f) * 4 + 0x38) / FLOAT_803e67c4;
  }
  iVar5 = FUN_80214b9c(param_2);
  if (iVar5 != 0) {
    local_c = 2;
    iVar7 = FUN_800138c4(*DAT_803ddd54);
    if (iVar7 == 0) {
      FUN_80013958(*DAT_803ddd54,&local_c);
    }
    return 4;
  }
  uVar2 = *(ushort *)((int)DAT_803ddd54 + 0xfa);
  if ((((*(char *)(DAT_803ddd54 + 0x3f) == '\0') && (1 < *(byte *)((int)DAT_803ddd54 + 0x101))) &&
      ((uVar2 & 0x20) == 0)) &&
     ((((uVar2 & 1) == 0 && (FLOAT_803e67e8 <= (float)DAT_803ddd54[2])) ||
      (((uVar2 & 1) != 0 && ((float)DAT_803ddd54[2] <= FLOAT_803e67c0)))))) {
    iVar6 = (int)(uint)*(byte *)((int)DAT_803ddd54 + 0x101) >> 1;
    iVar5 = FUN_800221a0(0,100);
    if (iVar5 <= (int)(uint)*(byte *)(iVar7 + iVar6 + 0x56)) {
      *(undefined *)((int)DAT_803ddd54 + 0x103) = 2;
      local_10 = 5;
      iVar7 = FUN_800138c4(*DAT_803ddd54);
      if (iVar7 == 0) {
        FUN_80013958(*DAT_803ddd54,&local_10);
      }
      *(undefined *)((int)DAT_803ddd54 + 0xfd) = 1;
      return 5;
    }
    iVar5 = FUN_800221a0(0,100);
    if (iVar5 <= (int)(uint)*(byte *)(iVar7 + iVar6 + 0x52)) {
      cVar1 = *(char *)((int)DAT_803ddd54 + 0xfe);
      if (cVar1 == '\x01') {
        uVar4 = countLeadingZeros(2 - (uint)*(byte *)((int)DAT_803ddd54 + 0xff));
        uVar4 = uVar4 >> 5 & 0xff;
      }
      else if (cVar1 == '\x02') {
        uVar4 = countLeadingZeros(1 - (uint)*(byte *)((int)DAT_803ddd54 + 0xff));
        uVar4 = uVar4 >> 5 & 0xff;
      }
      else if (cVar1 == '\x04') {
        uVar4 = countLeadingZeros(8 - (uint)*(byte *)((int)DAT_803ddd54 + 0xff));
        uVar4 = uVar4 >> 5 & 0xff;
      }
      else {
        uVar4 = countLeadingZeros(4 - (uint)*(byte *)((int)DAT_803ddd54 + 0xff));
        uVar4 = uVar4 >> 5 & 0xff;
      }
      if ((uVar4 != 0) && ((*(ushort *)((int)DAT_803ddd54 + 0xfa) & 0x40) == 0)) {
        *(undefined *)((int)DAT_803ddd54 + 0xfd) = 0;
        local_14 = 0xb;
        iVar7 = FUN_800138c4(*DAT_803ddd54);
        if (iVar7 == 0) {
          FUN_80013958(*DAT_803ddd54,&local_14);
        }
        return 5;
      }
    }
    *(ushort *)((int)DAT_803ddd54 + 0xfa) = *(ushort *)((int)DAT_803ddd54 + 0xfa) | 0x20;
  }
  if ((*(byte *)((int)DAT_803ddd54 + 0xfe) & *(byte *)((int)DAT_803ddd54 + 0xff)) == 0) {
    return 0;
  }
  *(ushort *)((int)DAT_803ddd54 + 0xfa) = *(ushort *)((int)DAT_803ddd54 + 0xfa) & 0xffbf;
  if ((*(byte *)((int)DAT_803ddd54 + 0xfe) & *(byte *)((int)DAT_803ddd54 + 0xff)) != 0) {
    if ((*(ushort *)((int)DAT_803ddd54 + 0xfa) & 1) == 0) {
      if (FLOAT_803e67b4 < (float)DAT_803ddd54[0x3d] - (float)DAT_803ddd54[2]) {
        bVar3 = true;
        goto LAB_80213158;
      }
    }
    else if (FLOAT_803e67b4 < (float)DAT_803ddd54[2] - (float)DAT_803ddd54[0x3d]) {
      bVar3 = true;
      goto LAB_80213158;
    }
  }
  bVar3 = false;
LAB_80213158:
  if (!bVar3) {
    return 0;
  }
  *(undefined *)((int)DAT_803ddd54 + 0x103) = 1;
  local_18 = 5;
  iVar7 = FUN_800138c4(*DAT_803ddd54);
  if (iVar7 == 0) {
    FUN_80013958(*DAT_803ddd54,&local_18);
  }
  *(undefined *)((int)DAT_803ddd54 + 0xfd) = 1;
  return 5;
}

