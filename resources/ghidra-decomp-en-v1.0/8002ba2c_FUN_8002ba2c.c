// Function: FUN_8002ba2c
// Entry: 8002ba2c
// Size: 968 bytes

/* WARNING: Removing unreachable block (ram,0x8002bdcc) */
/* WARNING: Removing unreachable block (ram,0x8002bdc4) */
/* WARNING: Removing unreachable block (ram,0x8002bdd4) */

void FUN_8002ba2c(void)

{
  int iVar1;
  uint uVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined2 local_78;
  undefined local_76;
  undefined local_75;
  undefined local_74;
  undefined local_73;
  undefined local_72;
  undefined local_71;
  float local_70;
  float local_6c;
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  FUN_802860dc();
  iVar1 = FUN_80057404();
  if ((iVar1 == 2) || (iVar1 == 3)) {
    FUN_8007d6dc(s_________OBJFREEALL_802cac68);
    FUN_8002e294();
  }
  else {
    uVar2 = (**(code **)(*DAT_803dcaac + 0x74))();
    pfVar3 = (float *)(**(code **)(*DAT_803dcaac + 0x90))();
    dVar9 = (double)*pfVar3;
    dVar8 = (double)pfVar3[1];
    dVar10 = (double)pfVar3[2];
    iVar5 = 0;
    if (iVar1 != 4) {
      FUN_8007d6dc(s__LOADING_CHARACTER_maptype__d_pl_802cac80,iVar1,uVar2 & 0xff);
      FUN_800033a8(&local_78,0,0x18);
      local_64 = 0xffffffff;
      local_75 = 0;
      local_74 = 1;
      local_73 = 4;
      local_72 = 0xff;
      local_71 = 0xff;
      local_78 = *(undefined2 *)(&DAT_803db44c + (uVar2 & 0xff) * 2);
      local_76 = 0x18;
      local_70 = (float)dVar9;
      local_6c = (float)dVar8;
      local_68 = (float)dVar10;
      uVar2 = FUN_800430ac(0);
      if ((uVar2 & 0x100000) == 0) {
        iVar5 = FUN_8002d55c(&local_78,1,0xffffffff,0xffffffff,0,0);
        if (iVar5 != 0) {
          FUN_8002d30c(iVar5,1);
          FUN_8007d6dc(s_LOADED_OBJECT__s_802cac54,*(int *)(iVar5 + 0x50) + 0x91);
        }
      }
      else {
        FUN_8007d6dc(s__objSetupObject__loading_is_lock_802cac18,0xffffffff);
        iVar5 = 0;
      }
    }
    uStack92 = (int)*(char *)(pfVar3 + 3) << 8 ^ 0x80000000;
    local_60 = 0x43300000;
    dVar7 = (double)FUN_80293e80((double)((FLOAT_803de8c0 *
                                          (float)((double)CONCAT44(0x43300000,uStack92) -
                                                 DOUBLE_803de8b0)) / FLOAT_803de8c4));
    DAT_802cac00 = (float)((double)FLOAT_803de8bc * dVar7 + dVar9);
    DAT_802cac04 = (float)((double)FLOAT_803de8c8 + dVar8);
    uStack84 = (int)*(char *)(pfVar3 + 3) << 8 ^ 0x80000000;
    local_58 = 0x43300000;
    dVar8 = (double)FUN_80294204((double)((FLOAT_803de8c0 *
                                          (float)((double)CONCAT44(0x43300000,uStack84) -
                                                 DOUBLE_803de8b0)) / FLOAT_803de8c4));
    DAT_802cac08 = (float)((double)FLOAT_803de8bc * dVar8 + dVar10);
    iVar1 = FUN_80014940();
    if ((iVar1 - 2U < 5) || (iVar1 == 7)) {
      (**(code **)(*DAT_803dca50 + 4))
                ((double)DAT_802cac00,(double)DAT_802cac04,(double)DAT_802cac08,iVar5);
      (**(code **)(*DAT_803dca50 + 0x1c))(0x57,0,3,0,0,0,0);
      (**(code **)(*DAT_803dca50 + 0x28))(iVar5,0);
      (**(code **)(*DAT_803dca50 + 8))(1);
    }
    else {
      (**(code **)(*DAT_803dca50 + 4))
                ((double)DAT_802cac00,(double)DAT_802cac04,(double)DAT_802cac08,iVar5);
      (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,0,0x20,&DAT_802cabf8,0,0xff);
      (**(code **)(*DAT_803dca50 + 8))(1);
    }
    iVar1 = FUN_8000faac();
    iVar4 = (**(code **)(*DAT_803dca50 + 0xc))();
    *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar4 + 0x18);
    *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar4 + 0x1c);
    *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar4 + 0x20);
    (**(code **)(*DAT_803dca70 + 0x10))(iVar5);
    DAT_803dcb70 = 0;
    FUN_8005649c();
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  FUN_80286128();
  return;
}

