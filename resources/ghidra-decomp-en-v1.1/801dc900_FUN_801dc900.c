// Function: FUN_801dc900
// Entry: 801dc900
// Size: 1116 bytes

void FUN_801dc900(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  float fVar2;
  float fVar3;
  ushort *puVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  int iVar8;
  int *piVar9;
  double dVar10;
  double extraout_f1;
  double dVar11;
  uint uStack_68;
  int iStack_64;
  undefined4 uStack_60;
  undefined auStack_5c [12];
  float local_50;
  float local_4c;
  float local_48 [8];
  longlong local_28;
  
  puVar4 = (ushort *)FUN_80286840();
  piVar9 = *(int **)(puVar4 + 0x5c);
  dVar11 = (double)FLOAT_803dc074;
  FUN_8002fb40((double)(float)piVar9[0xd],dVar11);
  if (*(char *)(piVar9 + 0x13) != '\0') {
    if (FLOAT_803e6228 < (float)piVar9[0xf]) {
      piVar9[0xf] = (int)((float)piVar9[0xf] - FLOAT_803dc074);
    }
    dVar10 = (double)(float)piVar9[0xd];
    if ((double)FLOAT_803e622c < dVar10) {
      piVar9[0xd] = (int)(float)(dVar10 - (double)FLOAT_803e6230);
    }
    if (((*(byte *)(piVar9 + 0x13) & 0x80) != 0) && (*(int *)(puVar4 + 0x7c) != 0)) {
      iVar8 = 0;
      piVar6 = piVar9;
      piVar7 = piVar9;
      do {
        if (*piVar7 == 0) {
          dVar10 = (double)FUN_801dc590(dVar10,dVar11,param_3,param_4,param_5,param_6,param_7,
                                        param_8);
        }
        else {
          iVar5 = (**(code **)(**(int **)(*piVar7 + 0x68) + 0x28))();
          if (iVar5 < 4) {
            dVar10 = (double)(**(code **)(**(int **)(*piVar7 + 0x68) + 0x24))(*piVar7,piVar6 + 3);
          }
          else {
            *piVar7 = 0;
            dVar10 = extraout_f1;
          }
        }
        piVar7 = piVar7 + 1;
        piVar6 = piVar6 + 3;
        iVar8 = iVar8 + 1;
      } while (iVar8 < 3);
    }
    if ((*(byte *)(piVar9 + 0x13) & 0x20) != 0) {
      if ((*(byte *)(piVar9 + 0x13) & 0xc0) == 0) {
        iVar8 = FUN_80037c38(puVar4,8,0xff,0xff,0x78,0x129,(float *)(piVar9 + 0x11));
      }
      else {
        iVar8 = FUN_80036868((int)puVar4,&uStack_60,&iStack_64,&uStack_68,&local_50,&local_4c,
                             local_48);
      }
      if (FLOAT_803e6228 <= (float)piVar9[0x10]) {
        piVar9[0x10] = (int)((float)piVar9[0x10] - FLOAT_803dc074);
      }
      if ((iVar8 != 0) && (iVar8 != 0x11)) {
        if ((float)piVar9[0x10] <= FLOAT_803e6228) {
          if ((*(byte *)(piVar9 + 0x13) & 0xc0) == 0) {
            FUN_8000bb38((uint)puVar4,0x129);
            FUN_8000bb38((uint)puVar4,0x12a);
          }
          else {
            local_50 = local_50 + FLOAT_803dda58;
            local_48[0] = local_48[0] + FLOAT_803dda5c;
            FUN_8009a468(puVar4,auStack_5c,1,(int *)0x0);
            FUN_8002ad08(puVar4,0xf,200,0,0,1);
            FUN_801dc6ac((uint)puVar4,(int)piVar9);
          }
          local_50 = FLOAT_803e6228;
          local_4c = FLOAT_803e6238 * (float)piVar9[0xe];
          local_48[0] = FLOAT_803e6228;
          FUN_80096f20(puVar4,*(byte *)(piVar9 + 0x13) & 0xf,0x14,(int)auStack_5c,0);
          piVar9[0xd] = (int)FLOAT_803e6220;
          piVar9[0x10] = (int)FLOAT_803e6240;
          if ((*(byte *)(piVar9 + 0x13) & 0x80) != 0) {
            iVar8 = 0;
            piVar6 = piVar9;
            do {
              if ((*piVar6 != 0) &&
                 (iVar5 = (**(code **)(**(int **)(*piVar6 + 0x68) + 0x28))(), 1 < iVar5)) {
                FUN_80036548(*piVar6,(int)puVar4,'\x0e',1,0);
              }
              piVar6 = piVar6 + 1;
              iVar8 = iVar8 + 1;
            } while (iVar8 < 3);
          }
        }
      }
    }
    iVar8 = FUN_8002bac4();
    fVar2 = *(float *)(puVar4 + 6) - *(float *)(iVar8 + 0xc);
    fVar3 = *(float *)(puVar4 + 10) - *(float *)(iVar8 + 0x14);
    dVar11 = FUN_80293900((double)(fVar2 * fVar2 + fVar3 * fVar3));
    uVar1 = (uint)dVar11;
    local_28 = (longlong)(int)uVar1;
    if ((uVar1 & 0xffff) < (uint)*(ushort *)(piVar9 + 0x12)) {
      if (((*(byte *)(piVar9 + 0x13) & 0x10) != 0) &&
         ((uint)*(ushort *)(piVar9 + 0x12) <= (uint)*(ushort *)((int)piVar9 + 0x4a))) {
        if ((float)piVar9[0xf] <= FLOAT_803e6228) {
          local_50 = FLOAT_803e6228;
          local_4c = FLOAT_803e6244 * FLOAT_803e6238 * (float)piVar9[0xe];
          local_48[0] = FLOAT_803e6228;
          FUN_80096f20(puVar4,*(byte *)(piVar9 + 0x13) & 0xf,10,(int)auStack_5c,1);
          piVar9[0xf] = (int)FLOAT_803e6248;
        }
      }
      piVar9[0xc] = (int)((float)piVar9[0xc] - FLOAT_803dc074);
      if ((float)piVar9[0xc] <= FLOAT_803e6228) {
        local_50 = FLOAT_803e6228;
        local_4c = FLOAT_803e6238 * (float)piVar9[0xe];
        local_48[0] = FLOAT_803e6228;
        FUN_80021b8c(puVar4,&local_50);
        FUN_80096f20(puVar4,*(byte *)(piVar9 + 0x13) & 0xf,1,(int)auStack_5c,0);
        piVar9[0xc] = (int)((float)piVar9[0xc] + FLOAT_803e624c);
      }
    }
    *(short *)((int)piVar9 + 0x4a) = (short)uVar1;
  }
  FUN_8028688c();
  return;
}

