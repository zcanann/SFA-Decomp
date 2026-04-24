// Function: FUN_801aa188
// Entry: 801aa188
// Size: 884 bytes

void FUN_801aa188(int param_1)

{
  byte bVar3;
  short *psVar1;
  int iVar2;
  undefined *puVar4;
  int local_28 [2];
  double local_20;
  
  puVar4 = *(undefined **)(param_1 + 0xb8);
  bVar3 = FUN_801a9fd0(param_1,puVar4);
  switch(*puVar4) {
  case 0:
    FUN_80036f50(0x3f,local_28);
    if (local_28[0] == 4) {
      *puVar4 = 1;
    }
    break;
  case 1:
    iVar2 = FUN_8001ffb4(0x3ec);
    if (iVar2 != 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      *puVar4 = 2;
    }
    break;
  case 2:
    (**(code **)(*DAT_803dca68 + 0x58))(6000,0x603);
    *(float *)(puVar4 + 4) = FLOAT_803e4624;
    *puVar4 = 3;
    puVar4[0xc] = bVar3;
    break;
  case 3:
    if (bVar3 == 0) {
      FUN_8000bb18(0,0x7e);
      (**(code **)(*DAT_803dca68 + 0x60))();
      FUN_800200e8(0xa3,1);
      FUN_800200e8(0x620,0);
      *puVar4 = 5;
    }
    else {
      iVar2 = FUN_8002b9ec();
      *(float *)(puVar4 + 8) = *(float *)(puVar4 + 8) + FLOAT_803db414 / FLOAT_803e4618;
      if (FLOAT_803e4628 < *(float *)(puVar4 + 8)) {
        *(float *)(puVar4 + 8) = FLOAT_803e4628;
      }
      if (*(float *)(param_1 + 0x10) + *(float *)(puVar4 + 8) < *(float *)(iVar2 + 0x10)) {
        *(float *)(puVar4 + 4) = FLOAT_803e462c * FLOAT_803db414 + *(float *)(puVar4 + 4);
        if (FLOAT_803e4624 < *(float *)(puVar4 + 4)) {
          *(float *)(puVar4 + 4) = FLOAT_803e4624;
        }
      }
      else {
        local_20 = (double)CONCAT44(0x43300000,(uint)bVar3);
        *(float *)(puVar4 + 4) =
             -(FLOAT_803db414 * (float)(local_20 - DOUBLE_803e4648) - *(float *)(puVar4 + 4));
      }
      FUN_8004c210((double)(*(float *)(param_1 + 0x10) + *(float *)(puVar4 + 8)),
                   (double)(*(float *)(param_1 + 0x10) - FLOAT_803e4630),(double)FLOAT_803e4634,
                   (double)FLOAT_803e4638,(double)FLOAT_803e463c,0);
      if (*(float *)(puVar4 + 4) < FLOAT_803e4640) {
        (**(code **)(*DAT_803dca68 + 0x60))();
        *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
        *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
        (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
        *puVar4 = 4;
      }
      else {
        iVar2 = (int)*(float *)(puVar4 + 4);
        local_20 = (double)(longlong)iVar2;
        (**(code **)(*DAT_803dca68 + 0x5c))(iVar2);
      }
      if (bVar3 != puVar4[0xc]) {
        FUN_8000bb18(0,0x409);
        puVar4[0xc] = bVar3;
      }
    }
    break;
  case 4:
    (**(code **)(*DAT_803dcaac + 0x28))();
    break;
  case 5:
    psVar1 = (short *)FUN_8002b9ec();
    (**(code **)(*DAT_803dcaac + 0x1c))(psVar1 + 6,(int)*psVar1,1,0);
    *puVar4 = 6;
    break;
  case 6:
    iVar2 = FUN_8001ffb4(0x1c0);
    if (iVar2 == 0) {
      FUN_8004c204();
      *puVar4 = 7;
    }
  }
  return;
}

