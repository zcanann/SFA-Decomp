// Function: FUN_80183c9c
// Entry: 80183c9c
// Size: 1252 bytes

void FUN_80183c9c(int param_1)

{
  ushort uVar1;
  float fVar2;
  short sVar3;
  undefined4 uVar4;
  int iVar5;
  undefined2 uVar6;
  uint *puVar7;
  int iVar8;
  double dVar9;
  float local_48;
  undefined local_44 [3];
  char cStack65;
  undefined4 local_40;
  undefined auStack60 [4];
  undefined auStack56 [12];
  float local_2c;
  undefined auStack40 [4];
  float local_24;
  double local_20;
  double local_18;
  
  iVar8 = *(int *)(param_1 + 0x4c);
  local_40 = 0xffffffff;
  local_48 = FLOAT_803e39ac;
  (**(code **)(*DAT_803dca58 + 0x18))(&local_48);
  puVar7 = *(uint **)(param_1 + 0xb8);
  uVar4 = FUN_8002b9ec();
  if (*(int *)(param_1 + 0x30) != 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  iVar5 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(iVar8 + 0x14));
  fVar2 = FLOAT_803e39b8;
  if (iVar5 == 0) {
    FUN_80035f00(param_1);
  }
  else if ((float)puVar7[1] <= FLOAT_803e39b8) {
    local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36));
    iVar5 = (int)(FLOAT_803e39dc * FLOAT_803db414 + (float)(local_20 - DOUBLE_803e39b0));
    local_18 = (double)(longlong)iVar5;
    if (0xff < iVar5) {
      iVar5 = 0xff;
    }
    *(char *)(param_1 + 0x36) = (char)iVar5;
    if (*(short *)(puVar7 + 2) != 0) {
      FUN_80035f00(param_1);
      sVar3 = *(short *)(puVar7 + 2);
      uVar1 = (ushort)DAT_803db410;
      *(ushort *)(puVar7 + 2) = sVar3 - uVar1;
      if ((short)(sVar3 - uVar1) < 1) {
        if ((int)*puVar7 < 1) {
          puVar7[1] = (uint)FLOAT_803e39ac;
        }
        else {
          puVar7[1] = (uint)FLOAT_803e39ac;
          local_18 = (double)CONCAT44(0x43300000,*puVar7 ^ 0x80000000);
          (**(code **)(*DAT_803dcaac + 100))
                    ((double)(float)(local_18 - DOUBLE_803e39c8),*(undefined4 *)(iVar8 + 0x14));
        }
        *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar8 + 8);
        *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar8 + 0xc);
        *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar8 + 0x10);
        *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(iVar8 + 8);
        *(undefined4 *)(param_1 + 0x84) = *(undefined4 *)(iVar8 + 0xc);
        *(undefined4 *)(param_1 + 0x88) = *(undefined4 *)(iVar8 + 0x10);
        fVar2 = FLOAT_803e39b8;
        *(float *)(param_1 + 0x24) = FLOAT_803e39b8;
        *(float *)(param_1 + 0x28) = fVar2;
        *(float *)(param_1 + 0x2c) = fVar2;
      }
      if (*(short *)(puVar7 + 2) < 0x33) {
        return;
      }
    }
    *(undefined2 *)(param_1 + 2) = *(undefined2 *)(puVar7 + 6);
    local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(puVar7 + 6) ^ 0x80000000);
    iVar8 = (int)((float)(local_18 - DOUBLE_803e39c8) * FLOAT_803e39e0);
    local_20 = (double)(longlong)iVar8;
    *(short *)(puVar7 + 6) = (short)iVar8;
    if ((*(short *)(param_1 + 2) < 10) && (-10 < *(short *)(param_1 + 2))) {
      *(undefined2 *)(param_1 + 2) = 0;
    }
    iVar8 = FUN_80036770(param_1,auStack60,&local_40,local_44,&local_2c,auStack40,&local_24);
    if (iVar8 == 0x10) {
      FUN_8002b050(param_1,300);
      iVar8 = 0;
    }
    if ((iVar8 != 0) && (*(int *)(param_1 + 0x30) == 0)) {
      *(char *)((int)puVar7 + 0x13) = *(char *)((int)puVar7 + 0x13) + cStack65;
      FUN_8002ac30(param_1,0xf,200,0,0,1);
      local_2c = local_2c + FLOAT_803dcdd8;
      local_24 = local_24 + FLOAT_803dcddc;
      FUN_8009a1dc((double)FLOAT_803e39e4,param_1,auStack56,1,0);
      if (*(byte *)((int)puVar7 + 0x13) < *(byte *)(puVar7 + 10)) {
        iVar8 = FUN_8000b5d0(0,*(undefined2 *)(puVar7 + 5));
        if (iVar8 == 0) {
          FUN_8000bb18(param_1,*(undefined2 *)(puVar7 + 5));
        }
        if (*(short *)(param_1 + 0x46) == 0x3de) {
          uVar6 = FUN_800221a0(600,800);
          *(undefined2 *)(puVar7 + 6) = uVar6;
        }
      }
      else {
        FUN_8000b7bc(param_1,0x7f);
        (**(code **)(*DAT_803ddac8 + 4))(param_1,1,0,2,0xffffffff,0);
        iVar8 = FUN_8000b5d0(0,*(undefined2 *)((int)puVar7 + 0x16));
        if (iVar8 == 0) {
          FUN_8000bb18(param_1,*(undefined2 *)((int)puVar7 + 0x16));
        }
        *(undefined2 *)(puVar7 + 2) = 0x32;
        *(undefined *)((int)puVar7 + 0x13) = 0;
        FUN_801833e4(param_1,uVar4,puVar7);
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
    }
    iVar8 = FUN_8002b9ec();
    FUN_800216d0(iVar8 + 0x18,param_1 + 0x18);
    sVar3 = *(short *)((int)puVar7 + 10) - (ushort)DAT_803db410;
    *(short *)((int)puVar7 + 10) = sVar3;
    if (sVar3 < 1) {
      sVar3 = FUN_800221a0(0,100);
      *(short *)((int)puVar7 + 10) = sVar3 + 300;
    }
    if (*(int *)(param_1 + 0x30) != 0) {
      FUN_80183250(param_1,puVar7);
    }
  }
  else {
    *(undefined *)(param_1 + 0x36) = 0;
    if ((*puVar7 != 0xffffffff) &&
       (puVar7[1] = (uint)-(FLOAT_803db414 * local_48 - (float)puVar7[1]), (float)puVar7[1] <= fVar2
       )) {
      iVar8 = FUN_8002b9ec();
      dVar9 = (double)FUN_80021704(param_1 + 0x18,iVar8 + 0x18);
      if ((double)FLOAT_803e39d0 < dVar9) {
        puVar7[1] = (uint)FLOAT_803e39b8;
        *(undefined2 *)(puVar7 + 2) = 0;
        FUN_80035f20(param_1);
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
      }
      else {
        puVar7[1] = (uint)FLOAT_803e39ac;
      }
    }
  }
  return;
}

