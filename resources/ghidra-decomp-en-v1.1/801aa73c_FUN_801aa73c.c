// Function: FUN_801aa73c
// Entry: 801aa73c
// Size: 884 bytes

void FUN_801aa73c(int param_1)

{
  byte bVar4;
  int iVar1;
  short *psVar2;
  uint uVar3;
  undefined *puVar5;
  int local_28 [2];
  undefined8 local_20;
  
  puVar5 = *(undefined **)(param_1 + 0xb8);
  bVar4 = FUN_801aa584();
  switch(*puVar5) {
  case 0:
    FUN_80037048(0x3f,local_28);
    if (local_28[0] == 4) {
      *puVar5 = 1;
    }
    break;
  case 1:
    uVar3 = FUN_80020078(0x3ec);
    if (uVar3 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      *puVar5 = 2;
    }
    break;
  case 2:
    (**(code **)(*DAT_803dd6e8 + 0x58))(6000,0x603);
    *(float *)(puVar5 + 4) = FLOAT_803e52bc;
    *puVar5 = 3;
    puVar5[0xc] = bVar4;
    break;
  case 3:
    if (bVar4 == 0) {
      FUN_8000bb38(0,0x7e);
      (**(code **)(*DAT_803dd6e8 + 0x60))();
      FUN_800201ac(0xa3,1);
      FUN_800201ac(0x620,0);
      *puVar5 = 5;
    }
    else {
      iVar1 = FUN_8002bac4();
      *(float *)(puVar5 + 8) = *(float *)(puVar5 + 8) + FLOAT_803dc074 / FLOAT_803e52b0;
      if (FLOAT_803e52c0 < *(float *)(puVar5 + 8)) {
        *(float *)(puVar5 + 8) = FLOAT_803e52c0;
      }
      if (*(float *)(param_1 + 0x10) + *(float *)(puVar5 + 8) < *(float *)(iVar1 + 0x10)) {
        *(float *)(puVar5 + 4) = FLOAT_803e52c4 * FLOAT_803dc074 + *(float *)(puVar5 + 4);
        if (FLOAT_803e52bc < *(float *)(puVar5 + 4)) {
          *(float *)(puVar5 + 4) = FLOAT_803e52bc;
        }
      }
      else {
        local_20 = (double)CONCAT44(0x43300000,(uint)bVar4);
        *(float *)(puVar5 + 4) =
             -(FLOAT_803dc074 * (float)(local_20 - DOUBLE_803e52e0) - *(float *)(puVar5 + 4));
      }
      FUN_8004c38c((double)(*(float *)(param_1 + 0x10) + *(float *)(puVar5 + 8)),
                   (double)(*(float *)(param_1 + 0x10) - FLOAT_803e52c8),(double)FLOAT_803e52cc,
                   (double)FLOAT_803e52d0,(double)FLOAT_803e52d4,0);
      if (*(float *)(puVar5 + 4) < FLOAT_803e52d8) {
        (**(code **)(*DAT_803dd6e8 + 0x60))();
        *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar1 + 0xc);
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar1 + 0x10);
        *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar1 + 0x14);
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
        (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
        *puVar5 = 4;
      }
      else {
        iVar1 = (int)*(float *)(puVar5 + 4);
        local_20 = (double)(longlong)iVar1;
        (**(code **)(*DAT_803dd6e8 + 0x5c))(iVar1);
      }
      if (bVar4 != puVar5[0xc]) {
        FUN_8000bb38(0,0x409);
        puVar5[0xc] = bVar4;
      }
    }
    break;
  case 4:
    (**(code **)(*DAT_803dd72c + 0x28))();
    break;
  case 5:
    psVar2 = (short *)FUN_8002bac4();
    (**(code **)(*DAT_803dd72c + 0x1c))(psVar2 + 6,(int)*psVar2,1,0);
    *puVar5 = 6;
    break;
  case 6:
    uVar3 = FUN_80020078(0x1c0);
    if (uVar3 == 0) {
      FUN_8004c380();
      *puVar5 = 7;
    }
  }
  return;
}

