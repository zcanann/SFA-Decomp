// Function: FUN_8012ec14
// Entry: 8012ec14
// Size: 796 bytes

void FUN_8012ec14(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined8 uVar7;
  float local_38;
  float local_34;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  
  uVar7 = FUN_802860dc();
  uVar1 = (undefined4)((ulonglong)uVar7 >> 0x20);
  uVar6 = (undefined4)uVar7;
  iVar2 = FUN_8002b9ec();
  iVar3 = FUN_8022d768();
  iVar4 = FUN_8001fedc();
  if (iVar4 == 0) {
    if (iVar3 == 0) {
      FUN_801262cc(uVar1,uVar6,param_3);
      FUN_8012d77c(uVar1,uVar6,param_3);
      if (DAT_803dd77e != '\0') {
        FUN_8012c9fc(uVar1,uVar6,param_3);
      }
      FUN_80295bc8(iVar2);
      FUN_8025d324(0,0,0x280,0x1e0);
      if ((iVar2 != 0) && (DAT_803dd780 == '\0')) {
        iVar3 = FUN_8029605c(iVar2,&local_34,&local_38);
        if (iVar3 != 0) {
          FUN_80053f2c(DAT_803dd8c4,&DAT_803dd82c,&DAT_803dd828);
          uStack44 = (uint)*(ushort *)(DAT_803dd8c4 + 10);
          local_30 = 0x43300000;
          uStack36 = (uint)*(ushort *)(DAT_803dd8c4 + 0xc);
          local_28 = 0x43300000;
          FUN_8007719c(-(double)(FLOAT_803e1e70 *
                                 (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1e88) -
                                local_34),
                       -(double)(FLOAT_803e1e70 *
                                 (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e1e88) -
                                local_38),DAT_803dd8c4,0x96,0x100);
        }
        FUN_80121440(uVar1,uVar6,param_3);
      }
      FUN_8025d324(0,0,0x280,0x1e0);
      if (iVar2 != 0) {
        FUN_80123204(uVar1,uVar6,param_3);
        iVar2 = FUN_800173c8(0x7c);
        if ((DAT_803dba70 != -1) && (DAT_803dd8d0 != 0)) {
          FUN_80019908(0xff,0xff,0xff,DAT_803dd8d0 & 0xff);
          *(char *)(iVar2 + 0x1e) = (char)DAT_803dd8d0;
          if (DAT_803dd8ca == -1) {
            FUN_80016c18(DAT_803dba70,&DAT_803a9440);
          }
          else {
            uVar5 = FUN_800191c4(DAT_803dba70,DAT_803a9444);
            FUN_8001618c(uVar5,0x7c);
          }
        }
        FUN_80125244(uVar1,uVar6,param_3);
      }
      if (DAT_803dd75b != '\0') {
        FUN_80128e70(uVar1,uVar6,param_3);
      }
      FUN_8000f0b8(uVar1);
    }
    else {
      FUN_80125ea4(uVar1,uVar6,param_3);
      FUN_801262cc(uVar1,uVar6,param_3);
      iVar2 = FUN_800173c8(0x7c);
      if ((DAT_803dba70 != -1) && (DAT_803dd8d0 != 0)) {
        FUN_80019908(0xff,0xff,0xff,DAT_803dd8d0 & 0xff);
        *(char *)(iVar2 + 0x1e) = (char)DAT_803dd8d0;
        if (DAT_803dd8ca == -1) {
          FUN_80016c18(DAT_803dba70,&DAT_803a9440);
        }
        else {
          uVar5 = FUN_800191c4(DAT_803dba70,DAT_803a9444);
          FUN_8001618c(uVar5,0x7c);
        }
      }
      FUN_8012d77c(uVar1,uVar6,param_3);
    }
    FUN_8011f7c4();
    FUN_8011f404();
    if (-1 < DAT_803dba90) {
      FUN_8012919c(uVar1,uVar6,param_3);
    }
    DAT_803dd7aa = 0;
    DAT_803dd7ac = 0;
  }
  FUN_80286128();
  return;
}

