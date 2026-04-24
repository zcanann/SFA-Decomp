// Function: FUN_8002bb04
// Entry: 8002bb04
// Size: 968 bytes

/* WARNING: Removing unreachable block (ram,0x8002beac) */
/* WARNING: Removing unreachable block (ram,0x8002bea4) */
/* WARNING: Removing unreachable block (ram,0x8002be9c) */
/* WARNING: Removing unreachable block (ram,0x8002bb24) */
/* WARNING: Removing unreachable block (ram,0x8002bb1c) */
/* WARNING: Removing unreachable block (ram,0x8002bb14) */

void FUN_8002bb04(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  uint uVar2;
  float *pfVar3;
  undefined2 *puVar4;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  undefined8 uVar6;
  undefined8 extraout_f1;
  double dVar7;
  double in_f29;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
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
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  FUN_80286840();
  iVar1 = FUN_80057580();
  if ((iVar1 == 2) || (iVar1 == 3)) {
    uVar6 = FUN_8007d858();
    FUN_8002e38c(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else {
    uVar2 = (**(code **)(*DAT_803dd72c + 0x74))();
    pfVar3 = (float *)(**(code **)(*DAT_803dd72c + 0x90))();
    dVar9 = (double)*pfVar3;
    dVar8 = (double)pfVar3[1];
    dVar10 = (double)pfVar3[2];
    iVar5 = 0;
    if (iVar1 != 4) {
      uVar6 = FUN_8007d858();
      FUN_800033a8((int)&local_78,0,0x18);
      local_64 = 0xffffffff;
      local_75 = 0;
      local_74 = 1;
      local_73 = 4;
      local_72 = 0xff;
      local_71 = 0xff;
      local_78 = *(undefined2 *)(&DAT_803dc0ac + (uVar2 & 0xff) * 2);
      local_76 = 0x18;
      local_70 = (float)dVar9;
      local_6c = (float)dVar8;
      local_68 = (float)dVar10;
      uVar2 = FUN_800431a4();
      if ((uVar2 & 0x100000) == 0) {
        iVar5 = FUN_8002d654(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&local_78
                             ,1,0xff,0xffffffff,(uint *)0x0,0,in_r9,in_r10);
        if (iVar5 != 0) {
          FUN_8002d404(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,1);
          FUN_8007d858();
        }
      }
      else {
        FUN_8007d858();
        iVar5 = 0;
      }
    }
    uStack_5c = (int)*(char *)(pfVar3 + 3) << 8 ^ 0x80000000;
    local_60 = 0x43300000;
    dVar7 = (double)FUN_802945e0();
    DAT_802cb7c0 = (float)((double)FLOAT_803df53c * dVar7 + dVar9);
    DAT_802cb7c4 = (float)((double)FLOAT_803df548 + dVar8);
    uStack_54 = (int)*(char *)(pfVar3 + 3) << 8 ^ 0x80000000;
    local_58 = 0x43300000;
    dVar8 = (double)FUN_80294964();
    DAT_802cb7c8 = (float)((double)FLOAT_803df53c * dVar8 + dVar10);
    iVar1 = FUN_8001496c();
    if ((iVar1 - 2U < 5) || (iVar1 == 7)) {
      (**(code **)(*DAT_803dd6d0 + 4))
                ((double)DAT_802cb7c0,(double)DAT_802cb7c4,(double)DAT_802cb7c8,iVar5);
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x57,0,3,0,0,0,0);
      (**(code **)(*DAT_803dd6d0 + 0x28))(iVar5,0);
      (**(code **)(*DAT_803dd6d0 + 8))(1);
    }
    else {
      (**(code **)(*DAT_803dd6d0 + 4))
                ((double)DAT_802cb7c0,(double)DAT_802cb7c4,(double)DAT_802cb7c8,iVar5);
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,0,0x20,&DAT_802cb7b8,0,0xff);
      (**(code **)(*DAT_803dd6d0 + 8))(1);
    }
    puVar4 = FUN_8000facc();
    iVar1 = (**(code **)(*DAT_803dd6d0 + 0xc))();
    *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(iVar1 + 0x18);
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(iVar1 + 0x1c);
    *(undefined4 *)(puVar4 + 10) = *(undefined4 *)(iVar1 + 0x20);
    (**(code **)(*DAT_803dd6f0 + 0x10))(iVar5);
    DAT_803dd7f0 = 0;
    FUN_80056618();
  }
  FUN_8028688c();
  return;
}

