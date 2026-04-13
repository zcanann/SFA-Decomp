// Function: FUN_800496cc
// Entry: 800496cc
// Size: 836 bytes

/* WARNING: Removing unreachable block (ram,0x80049794) */

void FUN_800496cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined4 in_r6;
  uint uVar4;
  undefined4 in_r7;
  uint uVar5;
  undefined4 in_r8;
  uint uVar6;
  undefined4 in_r9;
  uint uVar7;
  undefined4 in_r10;
  int iVar8;
  undefined8 uVar9;
  byte bStack_50;
  byte local_4f;
  byte local_4e [2];
  int local_4c;
  int local_48;
  int local_44;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  undefined4 local_2c [11];
  
  uVar9 = FUN_80286840();
  if ((DAT_803dd928 != '\0') && (DAT_803dd929 != '\0')) {
    FUN_800137c8((short *)&DAT_80360390,(uint)local_2c);
    DAT_803dd92c = 0;
    FUN_802472b0((int *)&DAT_803dd944);
    uVar3 = FUN_8001377c((short *)&DAT_80360390);
    if (uVar3 == 0) {
      FUN_8001378c(-0x7fc9fc70,(uint)local_2c);
      uVar9 = FUN_80256c08(local_2c[0]);
    }
    else {
      uVar9 = FUN_80256ca0();
    }
    DAT_803dd928 = '\0';
    DAT_803dd929 = '\0';
    DAT_803dd927 = uVar3 == 0;
  }
  DAT_803dd925 = 1;
  DAT_803dd926 = 1;
  if (DAT_803dd924 == '\x01') {
    uVar3 = FUN_8024533c();
    if (uVar3 == 0) {
      DAT_803dd924 = DAT_803dd924 + '\x01';
      uVar9 = FUN_800206cc(1);
    }
  }
  else if ((DAT_803dd924 == '\0') && (uVar3 = FUN_8024533c(), uVar3 != 0)) {
    DAT_803dd924 = DAT_803dd924 + '\x01';
  }
  if (((DAT_803de6a8 != '\0') && (DAT_803dd95c != 0)) && (600 < DAT_803dd92c)) {
    FUN_80137f08(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,100,
                 s_Suspected_graphics_hang_or_infin_8030d260,in_r6,in_r7,in_r8,in_r9,in_r10);
    FUN_8025e520(&local_34,&local_30,&local_3c,&local_38);
    FUN_8025e520(&local_44,&local_40,&local_4c,&local_48);
    uVar3 = countLeadingZeros(local_40 - local_30);
    uVar3 = uVar3 >> 5;
    uVar2 = countLeadingZeros(local_44 - local_34);
    uVar2 = uVar2 >> 5;
    iVar1 = -((-(local_48 - local_38) | local_48 - local_38) >> 0x1f);
    uVar9 = FUN_80256ac8(&bStack_50,&bStack_50,local_4e,&local_4f,&bStack_50);
    uVar4 = (uint)local_4e[0];
    uVar5 = (uint)local_4f;
    uVar6 = uVar3;
    uVar7 = uVar2;
    iVar8 = iVar1;
    uVar9 = FUN_80137f08(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,0x78,
                         s_GP_status__d_d_d_d_d_d___>_8030d28c,uVar4,uVar5,uVar3,uVar2,iVar1);
    if ((uVar2 == 0) && (iVar1 != 0)) {
      uVar9 = FUN_80137f08(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,0x8c,
                           s_GP_hang_due_to_XF_stall_bug__8030d2a8,uVar4,uVar5,uVar6,uVar7,iVar8);
    }
    else if ((uVar3 == 0) && ((uVar2 != 0 && (iVar1 != 0)))) {
      uVar9 = FUN_80137f08(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,0x8c,
                           s_GP_hang_due_to_unterminated_prim_8030d2c8,uVar4,uVar5,uVar6,uVar7,iVar8
                          );
    }
    else if ((local_4f == 0) && (((uVar3 != 0 && (uVar2 != 0)) && (iVar1 != 0)))) {
      uVar9 = FUN_80137f08(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,0x8c,
                           s_GP_hang_due_to_illegal_instructi_8030d2f0,uVar4,uVar5,uVar6,uVar7,iVar8
                          );
    }
    else if ((((local_4e[0] == 0) || (local_4f == 0)) ||
             ((uVar3 == 0 || ((uVar2 == 0 || (iVar1 == 0)))))) ||
            (-1 < (-(local_4c - local_3c) | local_4c - local_3c))) {
      uVar9 = FUN_80137f08(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,0x8c,
                           s_GP_is_in_unknown_state__8030d344,uVar4,uVar5,uVar6,uVar7,iVar8);
    }
    else {
      uVar9 = FUN_80137f08(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,0x8c,
                           s_GP_appears_to_be_not_hung__waiti_8030d314,uVar4,uVar5,uVar6,uVar7,iVar8
                          );
    }
    FUN_80137f08(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,0xa0,
                 &DAT_803dc23c,*(undefined4 *)(DAT_803dd95c + 0x198),uVar5,uVar6,uVar7,iVar8);
  }
  FUN_8028688c();
  return;
}

