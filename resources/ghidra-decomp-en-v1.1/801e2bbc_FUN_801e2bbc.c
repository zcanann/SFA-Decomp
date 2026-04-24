// Function: FUN_801e2bbc
// Entry: 801e2bbc
// Size: 1212 bytes

/* WARNING: Removing unreachable block (ram,0x801e3058) */
/* WARNING: Removing unreachable block (ram,0x801e2bcc) */

void FUN_801e2bbc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  float *pfVar6;
  double in_f31;
  double dVar7;
  double in_ps31_1;
  int local_68;
  undefined auStack_64 [6];
  undefined2 local_5e;
  float local_5c;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  float fStack_44;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar1 = FUN_8028683c();
  pfVar6 = *(float **)(uVar1 + 0xb8);
  iVar2 = (**(code **)(**(int **)(*(int *)(uVar1 + 0x30) + 0x68) + 0x24))();
  iVar3 = (**(code **)(**(int **)(*(int *)(uVar1 + 0x30) + 0x68) + 0x28))();
  if (((*(char *)(pfVar6 + 3) != '\0') && (iVar3 < 6)) && (*(short *)(uVar1 + 0x46) != 0x69c)) {
    FUN_8000da78(uVar1,0x2c6);
  }
  iVar4 = FUN_801e18cc(*(int *)(uVar1 + 0x30));
  if ((iVar4 < 2) && (*(char *)(pfVar6 + 3) < '\x01')) {
    *pfVar6 = *pfVar6 - FLOAT_803dc074;
    if (*pfVar6 <= FLOAT_803e64ac) {
      uVar5 = FUN_80022264(10,0x19);
      dVar7 = (double)FLOAT_803e64a8;
      for (; uVar5 != 0; uVar5 = uVar5 - 1) {
        local_58 = *(float *)(uVar1 + 0x18);
        local_54 = *(float *)(uVar1 + 0x1c);
        local_50[0] = *(float *)(uVar1 + 0x20);
        local_5c = (float)dVar7;
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x9f,auStack_64,0x200001,0xffffffff,0);
      }
      fStack_44 = (float)FUN_80022264(0x5a,0xf0);
      fStack_44 = -fStack_44;
      local_48 = 0x43300000;
      *pfVar6 = (float)((double)CONCAT44(0x43300000,fStack_44) - DOUBLE_803e64c0);
    }
    if ((2 < iVar2) && (*(char *)(uVar1 + 0xad) == '\x01')) {
      local_5c = FLOAT_803e64b0;
      local_5e = 0xc0a;
      FUN_80038524(uVar1,0,&local_58,&local_54,local_50,0);
      local_58 = local_58 - *(float *)(uVar1 + 0x18);
      local_54 = local_54 - *(float *)(uVar1 + 0x1c);
      local_50[0] = local_50[0] - *(float *)(uVar1 + 0x20);
      for (iVar4 = 0; iVar4 < (int)(uint)DAT_803dc070; iVar4 = iVar4 + 1) {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x7aa,auStack_64,2,0xffffffff,0);
      }
    }
  }
  if (*(int *)(uVar1 + 0x30) != 0) {
    if ((*(short *)(uVar1 + 0x46) != 0x69c) && (*(int *)(*(int *)(uVar1 + 0x30) + 0xf4) < 4)) {
      fStack_44 = -pfVar6[2];
      local_48 = 0x43300000;
      pfVar6[1] = (float)((double)CONCAT44(0x43300000,fStack_44) - DOUBLE_803e64c0) / FLOAT_803e64b4
      ;
      if (pfVar6[1] < FLOAT_803e64ac) {
        pfVar6[1] = -pfVar6[1];
      }
      if (pfVar6[1] < FLOAT_803e64b8) {
        pfVar6[1] = FLOAT_803e64b8;
      }
    }
    *(uint *)(uVar1 + 0xf4) = *(int *)(uVar1 + 0xf4) - (uint)DAT_803dc070;
    if (*(int *)(uVar1 + 0xf4) < 0) {
      *(undefined4 *)(uVar1 + 0xf4) = 0;
    }
    if (((((((iVar3 == 1) &&
            (iVar3 = FUN_80036974(uVar1,&local_68,(int *)0x0,(uint *)0x0), iVar3 != 0)) &&
           (*(int *)(uVar1 + 0xf4) == 0)) &&
          ((local_68 != 0 && (iVar3 = FUN_8002bac4(), local_68 != iVar3)))) &&
         ((*(short *)(local_68 + 0x46) != 0x69c &&
          ((*(short *)(local_68 + 0x46) != 0x9a &&
           (*(undefined4 *)(uVar1 + 0xf4) = 0x14, *(int *)(uVar1 + 0x30) != 0)))))) &&
        ((iVar2 == 2 || (iVar2 == 5)))) && (*(short *)(uVar1 + 0x46) == 0x69c)) {
      FUN_8002ad08(uVar1,0xf,200,0,0,1);
      FUN_8000bb38(uVar1,0x2c7);
      *(char *)(pfVar6 + 3) = *(char *)(pfVar6 + 3) + -1;
      if (*(char *)(pfVar6 + 3) < '\x01') {
        *(undefined *)(pfVar6 + 3) = 0;
        (**(code **)(**(int **)(*(int *)(uVar1 + 0x30) + 0x68) + 0x20))();
        FUN_80035ff8(uVar1);
        *(ushort *)(uVar1 + 6) = *(ushort *)(uVar1 + 6) | 0x4000;
        FUN_8009adfc((double)FLOAT_803e64bc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     uVar1,1,1,1,0,1,1,0);
        FUN_8000bb38(uVar1,0x2c8);
      }
    }
    if (*(int *)(uVar1 + 0xf4) == 0) {
      *(undefined *)(*(int *)(uVar1 + 0x54) + 0x6e) = 6;
      *(undefined *)(*(int *)(uVar1 + 0x54) + 0x6f) = 1;
      *(undefined4 *)(*(int *)(uVar1 + 0x54) + 0x48) = 0x10;
      *(undefined4 *)(*(int *)(uVar1 + 0x54) + 0x4c) = 0x10;
    }
    else {
      *(undefined *)(*(int *)(uVar1 + 0x54) + 0x6c) = 0;
    }
    fStack_44 = -pfVar6[2];
    local_48 = 0x43300000;
    uStack_3c = (int)*(short *)(uVar1 + 4) ^ 0x80000000;
    local_40 = 0x43300000;
    iVar2 = (int)-((float)((double)CONCAT44(0x43300000,fStack_44) - DOUBLE_803e64c0) *
                   FLOAT_803dc074 -
                  (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e64c0));
    local_38 = (longlong)iVar2;
    *(short *)(uVar1 + 4) = (short)iVar2;
  }
  FUN_80286888();
  return;
}

