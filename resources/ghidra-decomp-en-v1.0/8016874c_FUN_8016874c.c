// Function: FUN_8016874c
// Entry: 8016874c
// Size: 1076 bytes

void FUN_8016874c(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  float fVar2;
  undefined2 *puVar3;
  undefined4 uVar4;
  int iVar5;
  undefined uVar6;
  int iVar7;
  int *piVar8;
  double dVar9;
  undefined8 uVar10;
  undefined auStack72 [2];
  undefined auStack70 [2];
  short local_44 [2];
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  longlong local_20;
  
  uVar10 = FUN_802860dc();
  puVar3 = (undefined2 *)((ulonglong)uVar10 >> 0x20);
  iVar7 = (int)uVar10;
  piVar8 = *(int **)(iVar7 + 0x40c);
  local_34 = DAT_802c2210;
  local_30 = DAT_802c2214;
  local_2c = DAT_802c2218;
  local_28 = DAT_802c221c;
  uVar4 = FUN_8002b9ec();
  iVar5 = *(int *)(param_3 + 0x2d0);
  if (iVar5 != 0) {
    local_40 = *(float *)(iVar5 + 0x18) - *(float *)(puVar3 + 0xc);
    local_3c = *(float *)(iVar5 + 0x1c) - *(float *)(puVar3 + 0xe);
    local_38 = *(float *)(iVar5 + 0x20) - *(float *)(puVar3 + 0x10);
    dVar9 = (double)FUN_802931a0((double)(local_38 * local_38 +
                                         local_40 * local_40 + local_3c * local_3c));
    *(float *)(param_3 + 0x2c0) = (float)dVar9;
  }
  (**(code **)(*DAT_803dcab8 + 0x54))
            (puVar3,param_3,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,0,4);
  (**(code **)(*DAT_803dcab8 + 0x14))(puVar3,uVar4,4,local_44,auStack70,auStack72);
  if ((local_44[0] == 1) || (local_44[0] == 2)) {
    iVar5 = (**(code **)(*DAT_803dcab8 + 0x50))
                      (puVar3,param_3,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,1,
                       &DAT_803ac668);
    if (iVar5 != 0) {
      if ((iVar5 != 0x10) && (iVar5 != 0x11)) {
        FUN_8009a1dc((double)FLOAT_803e30bc,puVar3,&DAT_803ac668,3,0);
        (**(code **)(*DAT_803dca8c + 0x14))(puVar3,param_3,4);
        *(char *)(param_3 + 0x354) = *(char *)(param_3 + 0x354) + -1;
        FUN_8002ac30(puVar3,0xf,200,0,0,1);
        FUN_8000bb18(puVar3,0x22);
      }
      if (*(char *)(param_3 + 0x354) < '\x01') {
        *(undefined2 *)(param_3 + 0x270) = 2;
      }
    }
  }
  else {
    iVar5 = (**(code **)(*DAT_803dcab8 + 0x50))
                      (puVar3,param_3,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,1,
                       &DAT_803ac668);
    if (iVar5 != 0) {
      if (iVar5 == 0x11) {
        if (*(short *)(param_3 + 0x270) != 1) {
          (**(code **)(*DAT_803dca8c + 0x14))(puVar3,param_3,6);
          *(undefined *)(param_3 + 0x27b) = 1;
          *(undefined *)(param_3 + 0x27a) = 1;
          *(undefined2 *)(param_3 + 0x270) = 1;
          FUN_8009a1dc((double)FLOAT_803e30bc,puVar3,&DAT_803ac668,1,0);
          FUN_8000bb18(puVar3,0x22);
          FUN_8000bb18(puVar3,0x3ac);
        }
      }
      else if ((iVar5 != 0x10) && ((float)piVar8[0x10] < FLOAT_803e30c0)) {
        FUN_8016821c(puVar3,piVar8);
        DAT_803ac670 = FLOAT_803e3078;
        DAT_803ac66c = 0;
        DAT_803ac66a = 0;
        DAT_803ac668 = 0;
        (**(code **)(*DAT_803dda90 + 4))(0,1,&DAT_803ac668,0x401,0xffffffff,&local_34);
        FUN_802961fc(uVar4,2);
        (**(code **)(*DAT_803dca8c + 0x14))(puVar3,param_3,5);
        FUN_8009a1dc((double)FLOAT_803e30bc,puVar3,&DAT_803ac668,4,0);
        FUN_8000bb18(puVar3,0x255);
      }
    }
    if (*(char *)(param_3 + 0x354) < '\x01') {
      *(undefined2 *)(param_3 + 0x270) = 2;
    }
  }
  fVar2 = FLOAT_803e3060;
  if (*piVar8 != 0) {
    if (FLOAT_803e3060 < (float)piVar8[0x10]) {
      uVar1 = (uint)(float)piVar8[0x10];
      local_20 = (longlong)(int)uVar1;
      uVar6 = FUN_800221a0(0,uVar1 & 0xff);
      *(undefined *)(*piVar8 + 0x36) = uVar6;
      *(undefined2 *)(*piVar8 + 4) = puVar3[2];
      *(undefined2 *)(*piVar8 + 2) = puVar3[1];
      *(undefined2 *)*piVar8 = *puVar3;
      piVar8[0x10] = (int)-(FLOAT_803e30c4 * FLOAT_803db414 - (float)piVar8[0x10]);
    }
    else {
      *(undefined *)(*piVar8 + 0x36) = 0;
      piVar8[0x10] = (int)fVar2;
    }
  }
  FUN_80286128();
  return;
}

