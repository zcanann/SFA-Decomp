// Function: FUN_80131078
// Entry: 80131078
// Size: 1168 bytes

undefined4 FUN_80131078(void)

{
  short sVar1;
  char cVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  char local_18;
  char local_17 [15];
  
  iVar6 = DAT_803de592 * 0x3c;
  if (DAT_803de591 == '\0') {
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = 0xffffffff;
    iVar4 = FUN_80020800();
    if (iVar4 == 0) {
      FUN_80014ba4(0,local_17,&local_18);
      cVar2 = local_17[0];
      if (DAT_803de579 != '\0') {
        local_17[0] = local_18;
        local_18 = -cVar2;
      }
      if (local_18 != '\0') {
        local_17[0] = '\0';
      }
      if (((local_17[0] != '\0') || (local_18 != '\0')) && (DAT_803de578 != '\0')) {
        if (((local_18 < '\0') && ((char)(&DAT_803aa0d3)[iVar6] != -1)) &&
           (((&DAT_803aa0ce)[(char)(&DAT_803aa0d3)[iVar6] * 0x1e] & 0x1000) == 0)) {
          FUN_80014b84(0);
          DAT_803de592 = (&DAT_803aa0d3)[iVar6];
          DAT_803de58e = 0xff;
        }
        else if ((('\0' < local_18) && ((char)(&DAT_803aa0d2)[iVar6] != -1)) &&
                (((&DAT_803aa0ce)[(char)(&DAT_803aa0d2)[iVar6] * 0x1e] & 0x1000) == 0)) {
          FUN_80014b84(0);
          DAT_803de592 = (&DAT_803aa0d2)[iVar6];
          DAT_803de58e = 0xff;
        }
        if ((char)(&DAT_803aa0d6)[iVar6] == -1) {
          if (((local_17[0] < '\0') && ((char)(&DAT_803aa0d4)[iVar6] != -1)) &&
             (((&DAT_803aa0ce)[(char)(&DAT_803aa0d4)[iVar6] * 0x1e] & 0x1000) == 0)) {
            FUN_80014b94(0);
            DAT_803de592 = (&DAT_803aa0d4)[iVar6];
            DAT_803de58e = 0xff;
          }
          else if ((('\0' < local_17[0]) && ((char)(&DAT_803aa0d5)[iVar6] != -1)) &&
                  (((&DAT_803aa0ce)[(char)(&DAT_803aa0d5)[iVar6] * 0x1e] & 0x1000) == 0)) {
            FUN_80014b94(0);
            DAT_803de592 = (&DAT_803aa0d5)[iVar6];
            DAT_803de58e = 0xff;
          }
        }
        else {
          iVar6 = (char)(&DAT_803aa0d6)[iVar6] * 0x3c;
          if ((local_17[0] < '\0') && ((&DAT_803aa0d4)[iVar6] != -1)) {
            FUN_80014b94(0);
            (&DAT_803aa0d6)[DAT_803de592 * 0x3c] = (&DAT_803aa0d4)[iVar6];
            DAT_803de58e = 0xff;
          }
          else if (('\0' < local_17[0]) && ((&DAT_803aa0d5)[iVar6] != -1)) {
            FUN_80014b94(0);
            (&DAT_803aa0d6)[DAT_803de592 * 0x3c] = (&DAT_803aa0d5)[iVar6];
            DAT_803de58e = 0xff;
          }
        }
        if (DAT_803de592 < '\0') {
          DAT_803de592 = DAT_803de591 + -1;
        }
        if (DAT_803de591 <= DAT_803de592) {
          DAT_803de592 = '\0';
        }
      }
      if (DAT_803de593 != '\0') {
        uVar5 = FUN_80014e9c(0);
        if ((uVar5 & 0x1100) == 0) {
          if ((uVar5 & 0x200) != 0) {
            FUN_80014b68(0,0x200);
            uVar3 = 0;
          }
        }
        else if ((((&DAT_803aa0ce)[DAT_803de592 * 0x1e] & 0x20) == 0) &&
                (uVar5 = FUN_80020078(0x44f), uVar5 == 0)) {
          FUN_80014b68(0,0x1100);
          uVar3 = 1;
        }
      }
      if (DAT_803de590 == 0) {
        sVar1 = (ushort)DAT_803dc070 * -5;
      }
      else {
        sVar1 = (ushort)DAT_803dc070 * 5;
      }
      DAT_803de58e = DAT_803de58e + sVar1;
      if (DAT_803de58e < 0x100) {
        if (DAT_803de58e < 0) {
          DAT_803de58e = -DAT_803de58e;
          DAT_803de590 = DAT_803de590 ^ 1;
        }
      }
      else {
        DAT_803de58e = 0xff - (DAT_803de58e + -0xff);
        DAT_803de590 = DAT_803de590 ^ 1;
      }
      DAT_803de593 = '\x01';
      FUN_80130618();
      FUN_801307f4();
    }
    else {
      uVar3 = 0xffffffff;
    }
  }
  return uVar3;
}

