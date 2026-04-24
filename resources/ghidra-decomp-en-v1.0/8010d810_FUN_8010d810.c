// Function: FUN_8010d810
// Entry: 8010d810
// Size: 700 bytes

void FUN_8010d810(undefined4 param_1,int param_2,int param_3)

{
  double dVar1;
  int iVar2;
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  float local_5c;
  float local_58;
  undefined4 local_54;
  undefined auStack80 [4];
  undefined auStack76 [4];
  undefined auStack72 [32];
  double local_28;
  undefined4 local_20;
  uint uStack28;
  
  if (DAT_803dd578 == (undefined4 *)0x0) {
    DAT_803dd578 = (undefined4 *)FUN_80023cc8(0x38,0xf,0);
  }
  if (param_2 == 2) {
    *(undefined2 *)((int)DAT_803dd578 + 0x32) = *(undefined2 *)(DAT_803dd578 + 0xc);
    DAT_803dd578[7] = DAT_803dd578[3];
    DAT_803dd578[9] = DAT_803dd578[4];
    DAT_803dd578[5] = *DAT_803dd578;
    dVar1 = DOUBLE_803e1990;
    *(short *)(DAT_803dd578 + 0xd) =
         (short)(int)(FLOAT_803e19b8 *
                     (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_3 + 3) ^ 0x80000000) -
                            DOUBLE_803e1990));
    DAT_803dd578[8] =
         (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_3 + 5) ^ 0x80000000) - dVar1);
    local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(param_3 + 4) ^ 0x80000000);
    DAT_803dd578[10] = (float)(local_28 - dVar1);
    DAT_803dd578[6] =
         (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_3 + 2) ^ 0x80000000) - dVar1);
    *(short *)(DAT_803dd578 + 0xb) = (short)*(char *)(param_3 + 1);
    *(short *)((int)DAT_803dd578 + 0x2e) = (short)*(char *)(param_3 + 1);
  }
  else {
    FUN_800033a8(DAT_803dd578,0,0x38);
    iVar2 = (**(code **)(*DAT_803dca50 + 0x18))();
    (**(code **)(**(int **)(iVar2 + 4) + 0x20))(&local_58,&local_5c,&local_60,&local_64,&local_68);
    uStack28 = (uint)*(ushort *)(DAT_803dd578 + 0xc);
    local_20 = 0x43300000;
    (**(code **)(*DAT_803dca50 + 0x38))
              ((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e1998),param_1,
               auStack72,auStack76,auStack80,&local_54,0);
    *(short *)((int)DAT_803dd578 + 0x32) = (short)(int)local_68;
    DAT_803dd578[7] = local_60;
    DAT_803dd578[9] = local_64;
    DAT_803dd578[5] = local_54;
    *(undefined2 *)(DAT_803dd578 + 0xd) = 0x1e;
    DAT_803dd578[8] = FLOAT_803e19bc;
    DAT_803dd578[10] = FLOAT_803e19c0;
    DAT_803dd578[6] = FLOAT_803e19c4 * (local_5c + local_58);
    *(undefined2 *)(DAT_803dd578 + 0xb) = 0x3c;
    *(undefined2 *)((int)DAT_803dd578 + 0x2e) = 0x3c;
    DAT_803dd578[1] = local_54;
    DAT_803dd578[2] = FLOAT_803e19c8;
  }
  return;
}

