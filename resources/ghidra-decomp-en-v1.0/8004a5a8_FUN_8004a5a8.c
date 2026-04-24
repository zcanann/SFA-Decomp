// Function: FUN_8004a5a8
// Entry: 8004a5a8
// Size: 468 bytes

void FUN_8004a5a8(void)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined uStack72;
  char local_47;
  char local_46 [2];
  int local_44;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28 [10];
  
  FUN_802860dc();
  FUN_8025ddbc(&local_2c,local_28,&local_34,&local_30);
  FUN_8025ddbc(&local_3c,&local_38,&local_44,&local_40);
  uVar3 = countLeadingZeros(local_38 - local_28[0]);
  uVar3 = uVar3 >> 5;
  uVar4 = countLeadingZeros(local_3c - local_2c);
  uVar4 = uVar4 >> 5;
  iVar1 = -((-(local_40 - local_30) | local_40 - local_30) >> 0x1f);
  iVar2 = -((-(local_44 - local_34) | local_44 - local_34) >> 0x1f);
  FUN_80256364(&uStack72,&uStack72,local_46,&local_47,&uStack72);
  FUN_8007d6dc(s_GP_status__d_d_d_d_d_d_____8030c6cc,local_46[0],local_47,uVar3,uVar4,iVar1,iVar2);
  if ((uVar4 == 0) && (iVar1 != 0)) {
    FUN_8007d6dc(s_GP_hang_due_to_XF_stall_bug__8030c79c);
  }
  else if ((uVar3 == 0) && ((uVar4 != 0 && (iVar1 != 0)))) {
    FUN_8007d6dc(s_GP_hang_due_to_unterminated_prim_8030c7bc);
  }
  else if ((local_47 == '\0') && (((uVar3 != 0 && (uVar4 != 0)) && (iVar1 != 0)))) {
    FUN_8007d6dc(s_GP_hang_due_to_illegal_instructi_8030c7e4);
  }
  else if ((((local_46[0] == '\0') || (local_47 == '\0')) ||
           ((uVar3 == 0 || ((uVar4 == 0 || (iVar1 == 0)))))) || (iVar2 == 0)) {
    FUN_8007d6dc(s_GP_is_in_unknown_state__8030c83c);
  }
  else {
    FUN_8007d6dc(s_GP_appears_to_be_not_hung__waiti_8030c80c);
  }
  FUN_80286128();
  return;
}

