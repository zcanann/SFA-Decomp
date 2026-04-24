// Function: FUN_8028b394
// Entry: 8028b394
// Size: 708 bytes

int FUN_8028b394(int param_1,int param_2,uint *param_3,char *param_4,int param_5,int param_6)

{
  bool bVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  undefined uVar6;
  undefined *unaff_r28;
  uint uVar7;
  char local_48 [2];
  ushort local_46;
  int local_44;
  int local_40;
  int local_3c [4];
  
  if ((param_2 == 0) || (*param_3 == 0)) {
    iVar4 = 2;
  }
  else {
    bVar1 = false;
    *param_4 = '\0';
    uVar7 = 0;
    iVar4 = 0;
    while ((((!bVar1 && (uVar7 < *param_3)) && (iVar4 == 0)) && (*param_4 == '\0'))) {
      uVar5 = *param_3 - uVar7;
      uVar2 = 0x800;
      if (uVar5 < 0x801) {
        uVar2 = uVar5;
      }
      iVar4 = FUN_80287f2c(&local_40,&local_44);
      if (iVar4 == 0) {
        uVar6 = 0xd0;
        if (param_6 != 0) {
          uVar6 = 0xd1;
        }
        uVar5 = *(uint *)(local_44 + 0xc);
        if (uVar5 < 0x880) {
          *(uint *)(local_44 + 0xc) = uVar5 + 1;
          iVar4 = 0;
          *(undefined *)(local_44 + uVar5 + 0x10) = uVar6;
          *(int *)(local_44 + 8) = *(int *)(local_44 + 8) + 1;
        }
        else {
          iVar4 = 0x301;
        }
      }
      if (iVar4 == 0) {
        iVar4 = FUN_80287c44(local_44,param_1);
      }
      if (iVar4 == 0) {
        iVar4 = FUN_80287ca8(local_44,(short)uVar2);
      }
      if ((param_6 == 0) && (iVar4 == 0)) {
        iVar4 = FUN_80287b54(local_44,(undefined *)(param_2 + uVar7),uVar2);
      }
      if (iVar4 == 0) {
        if (param_5 == 0) {
          iVar4 = FUN_80287460(local_44);
        }
        else {
          uVar3 = 0;
          local_46 = 0;
          local_48[0] = '\0';
          if ((param_6 != 0) && (param_1 == 0)) {
            uVar3 = 1;
          }
          uVar5 = countLeadingZeros(uVar3);
          iVar4 = FUN_8028b1f0(local_44,local_3c,5,3,uVar5 >> 5);
          if (iVar4 == 0) {
            unaff_r28 = FUN_80287f00(local_3c[0]);
            FUN_80287e2c((int)unaff_r28,2);
            iVar4 = FUN_80287a2c((int)unaff_r28,(int)local_48);
          }
          if (iVar4 == 0) {
            iVar4 = FUN_80287974((int)unaff_r28,(undefined *)&local_46);
          }
          if ((param_6 != 0) && (iVar4 == 0)) {
            if ((*(int *)(unaff_r28 + 8) != local_46 + 5) &&
               (local_46 = (short)*(int *)(unaff_r28 + 8) - 5, local_48[0] == '\0')) {
              local_48[0] = '\x01';
            }
            if (local_46 <= uVar2) {
              iVar4 = FUN_8028772c((int)unaff_r28,param_2 + uVar7,(uint)local_46);
            }
          }
          uVar5 = (uint)local_46;
          if (uVar5 != uVar2) {
            if (((param_6 == 0) || (uVar2 <= uVar5)) && (local_48[0] == '\0')) {
              local_48[0] = '\x01';
            }
            bVar1 = true;
            uVar2 = uVar5;
          }
          *param_4 = local_48[0];
          FUN_80287e9c(local_3c[0]);
        }
      }
      FUN_80287e9c(local_40);
      uVar7 = uVar7 + uVar2;
    }
    *param_3 = uVar7;
  }
  return iVar4;
}

