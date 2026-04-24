// Function: FUN_80130cf0
// Entry: 80130cf0
// Size: 1168 bytes

undefined4 FUN_80130cf0(void)

{
  short sVar1;
  char cVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  char local_18;
  char local_17 [15];
  
  iVar6 = DAT_803dd912 * 0x3c;
  if (DAT_803dd911 == '\0') {
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = 0xffffffff;
    iVar4 = FUN_8002073c();
    if (iVar4 == 0) {
      FUN_80014b78(0,local_17,&local_18);
      cVar2 = local_17[0];
      if (DAT_803dd8f9 != '\0') {
        local_17[0] = local_18;
        local_18 = -cVar2;
      }
      if (local_18 != '\0') {
        local_17[0] = '\0';
      }
      if (((local_17[0] != '\0') || (local_18 != '\0')) && (DAT_803dd8f8 != '\0')) {
        if (((local_18 < '\0') && ((char)(&DAT_803a9473)[iVar6] != -1)) &&
           (((&DAT_803a946e)[(char)(&DAT_803a9473)[iVar6] * 0x1e] & 0x1000) == 0)) {
          FUN_80014b58(0);
          DAT_803dd912 = (&DAT_803a9473)[iVar6];
          DAT_803dd90e = 0xff;
        }
        else if ((('\0' < local_18) && ((char)(&DAT_803a9472)[iVar6] != -1)) &&
                (((&DAT_803a946e)[(char)(&DAT_803a9472)[iVar6] * 0x1e] & 0x1000) == 0)) {
          FUN_80014b58(0);
          DAT_803dd912 = (&DAT_803a9472)[iVar6];
          DAT_803dd90e = 0xff;
        }
        if ((char)(&DAT_803a9476)[iVar6] == -1) {
          if (((local_17[0] < '\0') && ((char)(&DAT_803a9474)[iVar6] != -1)) &&
             (((&DAT_803a946e)[(char)(&DAT_803a9474)[iVar6] * 0x1e] & 0x1000) == 0)) {
            FUN_80014b68(0);
            DAT_803dd912 = (&DAT_803a9474)[iVar6];
            DAT_803dd90e = 0xff;
          }
          else if ((('\0' < local_17[0]) && ((char)(&DAT_803a9475)[iVar6] != -1)) &&
                  (((&DAT_803a946e)[(char)(&DAT_803a9475)[iVar6] * 0x1e] & 0x1000) == 0)) {
            FUN_80014b68(0);
            DAT_803dd912 = (&DAT_803a9475)[iVar6];
            DAT_803dd90e = 0xff;
          }
        }
        else {
          iVar6 = (char)(&DAT_803a9476)[iVar6] * 0x3c;
          if ((local_17[0] < '\0') && ((&DAT_803a9474)[iVar6] != -1)) {
            FUN_80014b68(0);
            (&DAT_803a9476)[DAT_803dd912 * 0x3c] = (&DAT_803a9474)[iVar6];
            DAT_803dd90e = 0xff;
          }
          else if (('\0' < local_17[0]) && ((&DAT_803a9475)[iVar6] != -1)) {
            FUN_80014b68(0);
            (&DAT_803a9476)[DAT_803dd912 * 0x3c] = (&DAT_803a9475)[iVar6];
            DAT_803dd90e = 0xff;
          }
        }
        if (DAT_803dd912 < '\0') {
          DAT_803dd912 = DAT_803dd911 + -1;
        }
        if (DAT_803dd911 <= DAT_803dd912) {
          DAT_803dd912 = '\0';
        }
      }
      if (DAT_803dd913 != '\0') {
        uVar5 = FUN_80014e70(0);
        if ((uVar5 & 0x1100) == 0) {
          if ((uVar5 & 0x200) != 0) {
            FUN_80014b3c(0,0x200);
            uVar3 = 0;
          }
        }
        else if ((((&DAT_803a946e)[DAT_803dd912 * 0x1e] & 0x20) == 0) &&
                (iVar6 = FUN_8001ffb4(0x44f), iVar6 == 0)) {
          FUN_80014b3c(0,0x1100);
          uVar3 = 1;
        }
      }
      if (DAT_803dd910 == 0) {
        sVar1 = (ushort)DAT_803db410 * -5;
      }
      else {
        sVar1 = (ushort)DAT_803db410 * 5;
      }
      DAT_803dd90e = DAT_803dd90e + sVar1;
      if (DAT_803dd90e < 0x100) {
        if (DAT_803dd90e < 0) {
          DAT_803dd90e = -DAT_803dd90e;
          DAT_803dd910 = DAT_803dd910 ^ 1;
        }
      }
      else {
        DAT_803dd90e = 0xff - (DAT_803dd90e + -0xff);
        DAT_803dd910 = DAT_803dd910 ^ 1;
      }
      DAT_803dd913 = '\x01';
      FUN_801302c0();
      FUN_80130484();
    }
    else {
      uVar3 = 0xffffffff;
    }
  }
  return uVar3;
}

