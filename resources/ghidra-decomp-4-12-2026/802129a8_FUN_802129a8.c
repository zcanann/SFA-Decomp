// Function: FUN_802129a8
// Entry: 802129a8
// Size: 976 bytes

void FUN_802129a8(void)

{
  char cVar1;
  ushort uVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  undefined8 uVar8;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24 [9];
  
  uVar8 = FUN_80286840();
  uVar5 = (uint)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  iVar7 = *(int *)(uVar5 + 0x4c);
  uVar2 = *(ushort *)((int)DAT_803de9d4 + 0xfa);
  if (*(char *)(iVar4 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(uVar5,iVar4,1);
    *(undefined *)(DAT_803de9d4 + 0x3f) = 2;
    *(float *)(iVar4 + 0x294) =
         *(float *)(iVar7 + (uint)*(byte *)(DAT_803de9d4 + 0x3f) * 4 + 0x38) / FLOAT_803e745c;
  }
  iVar4 = FUN_80215214(iVar4);
  if (iVar4 == 0) {
    uVar6 = FUN_802125b0();
    if ((uVar6 & 0xff) != 0) {
      (**(code **)(*DAT_803dd6d0 + 0x24))(3,0,0);
    }
    uVar6 = FUN_80022150((double)FLOAT_803e7460,(double)FLOAT_803e7464,(float *)(DAT_803de9d4 + 100)
                        );
    if (uVar6 != 0) {
      FUN_8000bb38(uVar5,0x8f);
    }
    fVar3 = (float)DAT_803de9d4[1] - FLOAT_803dc074;
    DAT_803de9d4[1] = fVar3;
    if (fVar3 <= FLOAT_803e7450) {
      DAT_803de9d4[1] = FLOAT_803e7450;
    }
    if ((((float)DAT_803de9d4[1] <= FLOAT_803e7450) && (DAT_803de9d4[3] == (uVar2 >> 1 & 3))) &&
       ((((uVar2 & 1) == 0 && (FLOAT_803e7468 <= (float)DAT_803de9d4[2])) ||
        (((uVar2 & 1) != 0 && ((float)DAT_803de9d4[2] <= FLOAT_803e746c)))))) {
      if ((*(ushort *)((int)DAT_803de9d4 + 0xfa) & 8) == 0) {
        *(char *)((int)DAT_803de9d4 + 0x101) = *(char *)((int)DAT_803de9d4 + 0x101) + -1;
        local_34 = 2;
        uVar5 = FUN_800138e4((short *)*DAT_803de9d4);
        if (uVar5 == 0) {
          FUN_80013978((short *)*DAT_803de9d4,(uint)&local_34);
        }
      }
      else {
        *(char *)((int)DAT_803de9d4 + 0x101) = *(char *)((int)DAT_803de9d4 + 0x101) + '\x01';
        FUN_800201ac(0x572,(uint)*(byte *)((int)DAT_803de9d4 + 0x101));
        *(undefined *)((int)DAT_803de9d4 + 0xfd) = 0;
        *(ushort *)((int)DAT_803de9d4 + 0xfa) = *(ushort *)((int)DAT_803de9d4 + 0xfa) & 0xfff7;
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
        if ((uVar5 == 0) || ((*(ushort *)((int)DAT_803de9d4 + 0xfa) & 0x40) != 0)) {
          local_2c = 2;
          uVar5 = FUN_800138e4((short *)*DAT_803de9d4);
          if (uVar5 == 0) {
            FUN_80013978((short *)*DAT_803de9d4,(uint)&local_2c);
          }
        }
        else {
          local_28 = 0xb;
          uVar5 = FUN_800138e4((short *)*DAT_803de9d4);
          if (uVar5 == 0) {
            FUN_80013978((short *)*DAT_803de9d4,(uint)&local_28);
          }
        }
        local_30 = 4;
        uVar5 = FUN_800138e4((short *)*DAT_803de9d4);
        if (uVar5 == 0) {
          FUN_80013978((short *)*DAT_803de9d4,(uint)&local_30);
        }
      }
      FUN_8021239c();
      (**(code **)(*DAT_803dd6d0 + 0x24))(3,0,0);
      FUN_800201ac(0x572,(uint)*(byte *)((int)DAT_803de9d4 + 0x101));
      local_38 = 0;
      uVar5 = FUN_800138d4((short *)*DAT_803de9d4);
      if (uVar5 == 0) {
        FUN_80013900((short *)*DAT_803de9d4,(uint)&local_38);
      }
    }
  }
  else {
    local_24[0] = 10;
    uVar5 = FUN_800138e4((short *)*DAT_803de9d4);
    if (uVar5 == 0) {
      FUN_80013978((short *)*DAT_803de9d4,(uint)local_24);
    }
  }
  FUN_8028688c();
  return;
}

