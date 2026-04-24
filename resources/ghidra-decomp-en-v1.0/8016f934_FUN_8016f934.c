// Function: FUN_8016f934
// Entry: 8016f934
// Size: 1196 bytes

void FUN_8016f934(short *param_1)

{
  float fVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  float local_28 [2];
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  piVar6 = *(int **)(param_1 + 0x5c);
  iVar5 = *(int *)(param_1 + 0x7c);
  iVar4 = *(int *)(param_1 + 0x26);
  if ((*(byte *)(piVar6 + 0x1c) & 8) == 0) {
    piVar6[0xf] = (int)((float)piVar6[0xf] - FLOAT_803db414);
    if ((float)piVar6[0xf] < FLOAT_803e3330) {
      piVar6[0xf] = (int)FLOAT_803e3330;
    }
    if (param_1[0x23] == 0x83e) {
      if (*piVar6 != 0) {
        FUN_8001db6c((double)FLOAT_803e3330,*piVar6,0);
      }
      param_1[3] = param_1[3] | 0x4000;
    }
    else {
      if (FLOAT_803e3330 == (float)piVar6[0xd]) {
        dVar7 = (double)FUN_80022908(param_1 + 0x12);
        piVar6[0xc] = (int)(float)((double)FLOAT_803e335c / dVar7);
      }
      piVar6[0xd] = (int)((float)piVar6[0xd] + FLOAT_803db414);
      if ((float)piVar6[0xc] < (float)piVar6[0xd]) {
        if (*(char *)(iVar4 + 0x19) == '\0') {
          uVar3 = 1;
        }
        else {
          uVar3 = 3;
        }
        FUN_80035df4(param_1,0xe,uVar3,0);
      }
      if ((*(byte *)(piVar6 + 0x1c) & 1) == 0) {
        piVar6[9] = *(int *)(param_1 + 6);
        piVar6[10] = *(int *)(param_1 + 8);
        piVar6[0xb] = *(int *)(param_1 + 10);
        *(byte *)(piVar6 + 0x1c) = *(byte *)(piVar6 + 0x1c) | 1;
      }
      if (*(char *)(*(int *)(param_1 + 0x2a) + 0xad) != '\0') {
        if (*(char *)(*(int *)(param_1 + 0x2a) + 0xac) == '\x0e') {
          FUN_8000bb18(param_1,0xba);
          (**(code **)(*DAT_803dca98 + 0x10))
                    ((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                     (double)*(float *)(param_1 + 10),(double)FLOAT_803e3360,param_1);
          (**(code **)(*DAT_803dca98 + 0x14))
                    ((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                     (double)*(float *)(param_1 + 10),(double)FLOAT_803e3330,(int)*param_1,2);
        }
        else {
          FUN_8000bb18(param_1,0xb3);
        }
        if (*(char *)((int)piVar6 + 0x71) == '\0') {
          FUN_80099660((double)FLOAT_803e3354,param_1,3);
        }
        else if (*(char *)((int)piVar6 + 0x71) == '\x01') {
          FUN_80099660((double)FLOAT_803e3354,param_1,0);
        }
        else {
          FUN_80099660((double)FLOAT_803e3354,param_1,6);
        }
        piVar6[0xe] = (int)FLOAT_803e3358;
        *(undefined *)(param_1 + 0x1b) = 0;
        if (*piVar6 != 0) {
          FUN_8001f384();
          *piVar6 = 0;
        }
        FUN_80036fa4(param_1,2);
        FUN_80035f00(param_1);
      }
      fVar1 = FLOAT_803e3330;
      if ((float)piVar6[0xe] == FLOAT_803e3330) {
        *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
        *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
        *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
        if (iVar5 != 0) {
          if ((*(ushort *)(iVar5 + 0xb0) & 0x40) == 0) {
            FUN_8016f260(param_1,piVar6,iVar5);
          }
          else {
            *(undefined4 *)(param_1 + 0x7c) = 0;
          }
        }
        piVar6[9] = (int)(*(float *)(param_1 + 0x12) * FLOAT_803db414 + (float)piVar6[9]);
        piVar6[10] = (int)(*(float *)(param_1 + 0x14) * FLOAT_803db414 + (float)piVar6[10]);
        piVar6[0xb] = (int)(*(float *)(param_1 + 0x16) * FLOAT_803db414 + (float)piVar6[0xb]);
        *(ushort *)((int)piVar6 + 0x46) =
             *(short *)((int)piVar6 + 0x46) + (ushort)DAT_803db410 * 0x5dc;
        if ((*(byte *)(piVar6 + 0x1c) & 4) != 0) {
          piVar6[10] = (int)-(FLOAT_803e3364 * FLOAT_803db414 - (float)piVar6[10]);
          iVar4 = FUN_800658a4((double)(float)piVar6[9],(double)(float)piVar6[10],
                               (double)(float)piVar6[0xb],param_1,local_28,0);
          if (iVar4 == 0) {
            local_28[0] = local_28[0] - FLOAT_803e3368;
            if ((local_28[0] < FLOAT_803e3330) && (FLOAT_803e336c < local_28[0])) {
              piVar6[10] = (int)((float)piVar6[10] - local_28[0]);
            }
          }
        }
        *(int *)(param_1 + 6) = piVar6[9];
        *(int *)(param_1 + 8) = piVar6[10];
        *(int *)(param_1 + 10) = piVar6[0xb];
        if (iVar5 != 0) {
          uStack28 = (uint)*(ushort *)((int)piVar6 + 0x46);
          local_20 = 0x43300000;
          dVar7 = (double)FUN_80293e80((double)((FLOAT_803e3338 *
                                                (float)((double)CONCAT44(0x43300000,uStack28) -
                                                       DOUBLE_803e3370)) / FLOAT_803e333c));
          *(float *)(param_1 + 6) =
               (float)((double)FLOAT_803e3334 * dVar7 + (double)*(float *)(param_1 + 6));
          uStack20 = (uint)*(ushort *)((int)piVar6 + 0x46);
          local_18 = 0x43300000;
          dVar7 = (double)FUN_80294204((double)((FLOAT_803e3338 *
                                                (float)((double)CONCAT44(0x43300000,uStack20) -
                                                       DOUBLE_803e3370)) / FLOAT_803e333c));
          *(float *)(param_1 + 10) =
               (float)((double)FLOAT_803e3334 * dVar7 + (double)*(float *)(param_1 + 10));
        }
        uVar2 = (uint)DAT_803db410;
        iVar4 = *(int *)(param_1 + 0x7a);
        *(uint *)(param_1 + 0x7a) = iVar4 - uVar2;
        if ((int)(iVar4 - uVar2) < 0) {
          FUN_8002cbc4(param_1);
        }
      }
      else {
        *(float *)(param_1 + 0x12) = FLOAT_803e3330;
        *(float *)(param_1 + 0x14) = fVar1;
        *(float *)(param_1 + 0x16) = fVar1;
        FUN_80035dac(param_1);
        piVar6[0xe] = (int)((float)piVar6[0xe] - FLOAT_803db414);
        if ((float)piVar6[0xe] <= FLOAT_803e3330) {
          FUN_8002cbc4(param_1);
        }
      }
    }
  }
  return;
}

