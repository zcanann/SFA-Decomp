// Function: FUN_80212330
// Entry: 80212330
// Size: 976 bytes

void FUN_80212330(void)

{
  ushort uVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  int iVar7;
  undefined8 uVar8;
  int local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24 [9];
  
  uVar8 = FUN_802860dc();
  iVar5 = (int)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  iVar7 = *(int *)(iVar5 + 0x4c);
  uVar1 = *(ushort *)((int)DAT_803ddd54 + 0xfa);
  if (*(char *)(iVar4 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dca8c + 0x14))(iVar5,iVar4,1);
    *(undefined *)(DAT_803ddd54 + 0x3f) = 2;
    *(float *)(iVar4 + 0x294) =
         *(float *)(iVar7 + (uint)*(byte *)(DAT_803ddd54 + 0x3f) * 4 + 0x38) / FLOAT_803e67c4;
  }
  iVar4 = FUN_80214b9c(iVar4);
  if (iVar4 == 0) {
    cVar6 = FUN_80211f38();
    if (cVar6 != '\0') {
      (**(code **)(*DAT_803dca50 + 0x24))(3,0,0);
    }
    iVar4 = FUN_8002208c((double)FLOAT_803e67c8,(double)FLOAT_803e67cc,DAT_803ddd54 + 100);
    if (iVar4 != 0) {
      FUN_8000bb18(iVar5,0x8f);
    }
    fVar2 = (float)DAT_803ddd54[1] - FLOAT_803db414;
    DAT_803ddd54[1] = fVar2;
    if (fVar2 <= FLOAT_803e67b8) {
      DAT_803ddd54[1] = FLOAT_803e67b8;
    }
    if (((FLOAT_803e67b8 < (float)DAT_803ddd54[1]) || (DAT_803ddd54[3] != (uVar1 >> 1 & 3))) ||
       ((((uVar1 & 1) != 0 || ((float)DAT_803ddd54[2] < FLOAT_803e67d0)) &&
        (((uVar1 & 1) == 0 || (FLOAT_803e67d4 < (float)DAT_803ddd54[2])))))) {
      iVar5 = 0;
    }
    else {
      if ((*(ushort *)((int)DAT_803ddd54 + 0xfa) & 8) == 0) {
        *(char *)((int)DAT_803ddd54 + 0x101) = *(char *)((int)DAT_803ddd54 + 0x101) + -1;
        local_34 = 2;
        iVar5 = FUN_800138c4(*DAT_803ddd54);
        if (iVar5 == 0) {
          FUN_80013958(*DAT_803ddd54,&local_34);
        }
      }
      else {
        *(char *)((int)DAT_803ddd54 + 0x101) = *(char *)((int)DAT_803ddd54 + 0x101) + '\x01';
        FUN_800200e8(0x572,*(undefined *)((int)DAT_803ddd54 + 0x101));
        *(undefined *)((int)DAT_803ddd54 + 0xfd) = 0;
        *(ushort *)((int)DAT_803ddd54 + 0xfa) = *(ushort *)((int)DAT_803ddd54 + 0xfa) & 0xfff7;
        cVar6 = *(char *)((int)DAT_803ddd54 + 0xfe);
        if (cVar6 == '\x01') {
          uVar3 = countLeadingZeros(2 - (uint)*(byte *)((int)DAT_803ddd54 + 0xff));
          uVar3 = uVar3 >> 5 & 0xff;
        }
        else if (cVar6 == '\x02') {
          uVar3 = countLeadingZeros(1 - (uint)*(byte *)((int)DAT_803ddd54 + 0xff));
          uVar3 = uVar3 >> 5 & 0xff;
        }
        else if (cVar6 == '\x04') {
          uVar3 = countLeadingZeros(8 - (uint)*(byte *)((int)DAT_803ddd54 + 0xff));
          uVar3 = uVar3 >> 5 & 0xff;
        }
        else {
          uVar3 = countLeadingZeros(4 - (uint)*(byte *)((int)DAT_803ddd54 + 0xff));
          uVar3 = uVar3 >> 5 & 0xff;
        }
        if ((uVar3 == 0) || ((*(ushort *)((int)DAT_803ddd54 + 0xfa) & 0x40) != 0)) {
          local_2c = 2;
          iVar5 = FUN_800138c4(*DAT_803ddd54);
          if (iVar5 == 0) {
            FUN_80013958(*DAT_803ddd54,&local_2c);
          }
        }
        else {
          local_28 = 0xb;
          iVar5 = FUN_800138c4(*DAT_803ddd54);
          if (iVar5 == 0) {
            FUN_80013958(*DAT_803ddd54,&local_28);
          }
        }
        local_30 = 4;
        iVar5 = FUN_800138c4(*DAT_803ddd54);
        if (iVar5 == 0) {
          FUN_80013958(*DAT_803ddd54,&local_30);
        }
      }
      FUN_80211d24();
      (**(code **)(*DAT_803dca50 + 0x24))(3,0,0);
      FUN_800200e8(0x572,*(undefined *)((int)DAT_803ddd54 + 0x101));
      local_38 = 0;
      iVar5 = FUN_800138b4(*DAT_803ddd54);
      if (iVar5 == 0) {
        FUN_800138e0(*DAT_803ddd54,&local_38);
      }
      iVar5 = local_38 + 1;
    }
  }
  else {
    local_24[0] = 10;
    iVar5 = FUN_800138c4(*DAT_803ddd54);
    if (iVar5 == 0) {
      FUN_80013958(*DAT_803ddd54,local_24);
    }
    iVar5 = 4;
  }
  FUN_80286128(iVar5);
  return;
}

