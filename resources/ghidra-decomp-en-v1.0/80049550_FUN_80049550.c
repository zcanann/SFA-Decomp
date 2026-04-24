// Function: FUN_80049550
// Entry: 80049550
// Size: 836 bytes

/* WARNING: Removing unreachable block (ram,0x80049618) */

void FUN_80049550(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined uStack80;
  char local_4f;
  char local_4e [2];
  int local_4c;
  int local_48;
  int local_44;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  undefined4 local_2c [11];
  
  FUN_802860dc();
  if ((DAT_803dcca8 != '\0') && (DAT_803dcca9 != '\0')) {
    FUN_800137a8(&DAT_8035f730,local_2c);
    DAT_803dccac = 0;
    FUN_80246b4c(&DAT_803dccc4);
    iVar4 = FUN_8001375c(&DAT_8035f730);
    if (iVar4 == 0) {
      FUN_8001376c(&DAT_8035f730,local_2c);
      FUN_802564a4(local_2c[0]);
    }
    else {
      FUN_8025653c();
    }
    DAT_803dcca8 = '\0';
    DAT_803dcca9 = '\0';
    DAT_803dcca7 = iVar4 == 0;
  }
  DAT_803dcca5 = 1;
  DAT_803dcca6 = 1;
  if (DAT_803dcca4 == '\x01') {
    iVar4 = FUN_80244c44();
    if (iVar4 == 0) {
      DAT_803dcca4 = DAT_803dcca4 + '\x01';
      FUN_80020608(1);
    }
  }
  else if ((DAT_803dcca4 == '\0') && (iVar4 = FUN_80244c44(), iVar4 != 0)) {
    DAT_803dcca4 = DAT_803dcca4 + '\x01';
  }
  if (((DAT_803dda28 != '\0') && (DAT_803dccdc != 0)) && (600 < DAT_803dccac)) {
    FUN_80137b80(0x32,100,s_Suspected_graphics_hang_or_infin_8030c6a0);
    FUN_8025ddbc(&local_34,&local_30,&local_3c,&local_38);
    FUN_8025ddbc(&local_44,&local_40,&local_4c,&local_48);
    uVar2 = countLeadingZeros(local_40 - local_30);
    uVar2 = uVar2 >> 5;
    uVar3 = countLeadingZeros(local_44 - local_34);
    uVar3 = uVar3 >> 5;
    iVar4 = -((-(local_48 - local_38) | local_48 - local_38) >> 0x1f);
    iVar1 = -((-(local_4c - local_3c) | local_4c - local_3c) >> 0x1f);
    FUN_80256364(&uStack80,&uStack80,local_4e,&local_4f,&uStack80);
    FUN_80137b80(0x32,0x78,s_GP_status__d_d_d_d_d_d_____8030c6cc,local_4e[0],local_4f,uVar2,uVar3,
                 iVar4,iVar1);
    if ((uVar3 == 0) && (iVar4 != 0)) {
      FUN_80137b80(0x32,0x8c,s_GP_hang_due_to_XF_stall_bug__8030c6e8);
    }
    else if ((uVar2 == 0) && ((uVar3 != 0 && (iVar4 != 0)))) {
      FUN_80137b80(0x32,0x8c,s_GP_hang_due_to_unterminated_prim_8030c708);
    }
    else if ((local_4f == '\0') && (((uVar2 != 0 && (uVar3 != 0)) && (iVar4 != 0)))) {
      FUN_80137b80(0x32,0x8c,s_GP_hang_due_to_illegal_instructi_8030c730);
    }
    else if ((((local_4e[0] == '\0') || (local_4f == '\0')) ||
             ((uVar2 == 0 || ((uVar3 == 0 || (iVar4 == 0)))))) || (iVar1 == 0)) {
      FUN_80137b80(0x32,0x8c,s_GP_is_in_unknown_state__8030c784);
    }
    else {
      FUN_80137b80(0x32,0x8c,s_GP_appears_to_be_not_hung__waiti_8030c754);
    }
    FUN_80137b80(0x32,0xa0,&DAT_803db5dc,*(undefined4 *)(DAT_803dccdc + 0x198));
  }
  FUN_80286128();
  return;
}

