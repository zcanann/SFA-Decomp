// Function: FUN_80094554
// Entry: 80094554
// Size: 1612 bytes

/* WARNING: Removing unreachable block (ram,0x80094b80) */

void FUN_80094554(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  char cVar8;
  int *piVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined4 uVar9;
  undefined4 uVar10;
  double dVar11;
  undefined8 in_f31;
  undefined8 uVar12;
  undefined uStack152;
  undefined uStack151;
  undefined uStack150;
  undefined local_95;
  undefined local_94;
  undefined local_93 [3];
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  int local_80;
  int local_7c;
  undefined4 local_78;
  undefined4 local_74;
  float local_70;
  float local_6c;
  float local_68;
  undefined auStack100 [52];
  double local_30;
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar12 = FUN_802860d8();
  uVar2 = (undefined4)((ulonglong)uVar12 >> 0x20);
  uVar9 = (undefined4)uVar12;
  iVar3 = FUN_8000faac();
  (**(code **)(*DAT_803dca58 + 0x40))(local_93,&local_94,&local_95,&uStack150,&uStack151,&uStack152)
  ;
  if (DAT_803dd1f0 == 0) {
    iVar4 = FUN_8005cdc8();
    if (iVar4 != 0) {
      if (DAT_8039ab2c != 0) {
        iVar4 = FUN_8002b588();
        *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
        *(undefined *)(DAT_8039ab2c + 0x37) = 0xff;
        if (DAT_803dd1ec == '\0') {
          FUN_8008dae8(DAT_8039ab2c);
          *(undefined4 *)(DAT_8039ab2c + 0xc) = *(undefined4 *)(iVar3 + 0xc);
          *(undefined4 *)(DAT_8039ab2c + 0x10) = *(undefined4 *)(iVar3 + 0x10);
          *(undefined4 *)(DAT_8039ab2c + 0x14) = *(undefined4 *)(iVar3 + 0x14);
        }
        else {
          *(float *)(DAT_8039ab2c + 0xc) = FLOAT_803dd1e8;
          *(float *)(DAT_8039ab2c + 0x10) = FLOAT_803df2c0 + FLOAT_803dd1e4;
          *(float *)(DAT_8039ab2c + 0x14) = FLOAT_803dd1e0;
        }
        FUN_800412b8(local_93[0],local_94,local_95);
        FUN_8003b958(uVar2,uVar9,param_3,param_4,DAT_8039ab2c,1);
      }
      if (DAT_8039ab28 != 0) {
        cVar8 = FUN_8005ce90();
        if (cVar8 != '\0') {
          FUN_8008dae8(DAT_8039ab28);
        }
        piVar5 = (int *)FUN_8002b588(DAT_8039ab28);
        *(ushort *)(piVar5 + 6) = *(ushort *)(piVar5 + 6) & 0xfff7;
        *(undefined *)(DAT_8039ab28 + 0x37) = 0xff;
        uVar6 = *(undefined4 *)(iVar3 + 0xc);
        *(undefined4 *)(DAT_8039ab28 + 0x18) = uVar6;
        *(undefined4 *)(DAT_8039ab28 + 0xc) = uVar6;
        fVar1 = FLOAT_803df2c4 + *(float *)(iVar3 + 0x10);
        *(float *)(DAT_8039ab28 + 0x1c) = fVar1;
        *(float *)(DAT_8039ab28 + 0x10) = fVar1;
        uVar6 = *(undefined4 *)(iVar3 + 0x14);
        *(undefined4 *)(DAT_8039ab28 + 0x20) = uVar6;
        *(undefined4 *)(DAT_8039ab28 + 0x14) = uVar6;
        *(undefined2 *)(DAT_8039ab28 + 2) = 0;
        FUN_800412b8(local_93[0],local_94,local_95);
        FUN_8003b958(uVar2,uVar9,param_3,param_4,DAT_8039ab28,1);
        FUN_80060490(&local_74,&local_78,&local_7c,&local_80);
        if ((0 < local_7c) && (0 < local_80)) {
          FUN_8025d3d4(&local_84,&local_88,&local_8c,&local_90);
          FUN_8025d324(local_74,local_78,local_7c,local_80);
          *(ushort *)(*piVar5 + 2) = *(ushort *)(*piVar5 + 2) | 0x2000;
          FUN_8003bb7c(0x80);
          FUN_8025c688(0);
          FUN_8003b958(uVar2,uVar9,param_3,param_4,DAT_8039ab28,1);
          *(ushort *)(*piVar5 + 2) = *(ushort *)(*piVar5 + 2) & 0xdfff;
          FUN_8003bb7c(0);
          FUN_8025c688(1);
          FUN_8025d324(local_84,local_88,local_8c,local_90);
        }
      }
      dVar11 = (double)FUN_8008ed88();
      if ((double)FLOAT_803df2b4 < dVar11) {
        FUN_8008ede8(&local_70);
        local_70 = local_70 - FLOAT_803dcdd8;
        local_68 = local_68 - FLOAT_803dcddc;
        uVar6 = FUN_8000f54c();
        FUN_80258b24(0);
        FUN_8000fb00();
        FUN_802573f8();
        FUN_80256978(9,1);
        FUN_80256978(0xd,1);
        FUN_800799c0();
        FUN_800794e0();
        FUN_80079804();
        FUN_800789ac();
        FUN_80247494(uVar6,&local_70,&local_70);
        FUN_802472e4((double)local_70,(double)local_6c,(double)local_68,auStack100);
        FUN_8025d0a8(auStack100,0);
        FUN_8025d124(0);
        uVar6 = FUN_8008912c();
        FUN_8004c2e4(uVar6,0);
        if (dVar11 < (double)FLOAT_803df2c8) {
          iVar4 = (int)(FLOAT_803df2cc * (float)((double)FLOAT_803df2d0 * dVar11));
          local_30 = (double)(longlong)iVar4;
          FUN_800799e4(0x80,0x80,0xff,iVar4);
        }
        else {
          FUN_800799e4(0x80,0x80,0xff,0xff);
        }
        iVar4 = FUN_8002073c();
        if (iVar4 == 0) {
          uVar7 = FUN_800221a0(8000,12000);
          local_30 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          FLOAT_803db780 = (float)(local_30 - DOUBLE_803df2b8);
        }
        FUN_8025889c(0x80,2,4);
        write_volatile_4(0xcc008000,-FLOAT_803db780);
        write_volatile_4(0xcc008000,-FLOAT_803db780);
        write_volatile_4(0xcc008000,FLOAT_803df2b4);
        write_volatile_4(0xcc008000,FLOAT_803df2b4);
        write_volatile_4(0xcc008000,FLOAT_803df2b4);
        write_volatile_4(0xcc008000,FLOAT_803db780);
        write_volatile_4(0xcc008000,-FLOAT_803db780);
        write_volatile_4(0xcc008000,FLOAT_803df2b4);
        write_volatile_4(0xcc008000,FLOAT_803df2d4);
        write_volatile_4(0xcc008000,FLOAT_803df2b4);
        write_volatile_4(0xcc008000,FLOAT_803db780);
        write_volatile_4(0xcc008000,FLOAT_803db780);
        write_volatile_4(0xcc008000,FLOAT_803df2b4);
        write_volatile_4(0xcc008000,FLOAT_803df2d4);
        write_volatile_4(0xcc008000,FLOAT_803df2d4);
        write_volatile_4(0xcc008000,-FLOAT_803db780);
        write_volatile_4(0xcc008000,FLOAT_803db780);
        write_volatile_4(0xcc008000,FLOAT_803df2b4);
        write_volatile_4(0xcc008000,FLOAT_803df2b4);
        write_volatile_4(0xcc008000,FLOAT_803df2d4);
      }
      if (DAT_8039ab30 != 0) {
        iVar4 = FUN_8002b588();
        *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
        *(undefined *)(DAT_8039ab30 + 0x37) = 0xff;
        if (DAT_803dd1ec == '\0') {
          FUN_8008dae8(DAT_8039ab30);
          *(undefined4 *)(DAT_8039ab30 + 0xc) = *(undefined4 *)(iVar3 + 0xc);
          *(undefined4 *)(DAT_8039ab30 + 0x10) = *(undefined4 *)(iVar3 + 0x10);
          *(undefined4 *)(DAT_8039ab30 + 0x14) = *(undefined4 *)(iVar3 + 0x14);
        }
        else {
          *(float *)(DAT_8039ab30 + 0xc) = FLOAT_803dd1e8;
          *(float *)(DAT_8039ab30 + 0x10) = FLOAT_803dd1e4 - FLOAT_803df2d8;
          *(float *)(DAT_8039ab30 + 0x14) = FLOAT_803dd1e0;
        }
        FUN_8003b958(uVar2,uVar9,param_3,param_4,DAT_8039ab30,1);
      }
    }
  }
  else {
    FUN_8008dae8();
    iVar4 = FUN_8002b588(DAT_803dd1f0);
    *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
    *(undefined *)(DAT_803dd1f0 + 0x37) = 0xff;
    uVar6 = *(undefined4 *)(iVar3 + 0xc);
    *(undefined4 *)(DAT_803dd1f0 + 0x18) = uVar6;
    *(undefined4 *)(DAT_803dd1f0 + 0xc) = uVar6;
    uVar6 = *(undefined4 *)(iVar3 + 0x10);
    *(undefined4 *)(DAT_803dd1f0 + 0x1c) = uVar6;
    *(undefined4 *)(DAT_803dd1f0 + 0x10) = uVar6;
    uVar6 = *(undefined4 *)(iVar3 + 0x14);
    *(undefined4 *)(DAT_803dd1f0 + 0x20) = uVar6;
    *(undefined4 *)(DAT_803dd1f0 + 0x14) = uVar6;
    FUN_800412b8(local_93[0],local_94,local_95);
    FUN_8003b958(uVar2,uVar9,param_3,param_4,DAT_803dd1f0,1);
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  FUN_80286124();
  return;
}

